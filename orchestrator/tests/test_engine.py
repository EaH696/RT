"""Tests for the orchestration loop: commander planning + executor dispatch.

The agent is faked (a scripted callable) so the loop is exercised without a
live model. Scope enforcement, de-duplication, and the confirmation gate are
the behaviours under test.
"""
import pytest

from rt.store import Store, frontier, awaiting_confirmation, is_open
from rt.scope import Scope
from rt.engine import Engine, parse_tasks


def _scope():
    from rt import _ed25519
    s = Scope(engagement_id="TEST-1", allowed_cidrs=["10.0.0.0/24"],
              excluded_cidrs=["10.0.0.9/32"])
    s.sign("tester", _ed25519.generate_seed())
    return s


def _store(tmp_path):
    s = Store(tmp_path / ".rt")
    s.init(engagement_id="TEST-1", objective="get domain admin", scope_ref="scope.json")
    s.add_finding("host up", creator="recon", kind="host", target="10.0.0.5")
    return s


class ScriptedAgent:
    """Returns queued envelopes in order; records prompts it was given."""
    def __init__(self, *results):
        self._results = list(results)
        self.prompts = []

    def __call__(self, prompt, **kwargs):
        self.prompts.append(prompt)
        out = self._results.pop(0) if self._results else '{"tasks": []}'
        return {"result": out}


# -- parse_tasks -------------------------------------------------------------- #

def test_parse_plain_json():
    specs = parse_tasks('{"tasks": [{"from": ["f001"], "description": "scan", "tier": "enum", "target": "10.0.0.5"}]}')
    assert specs == [{"from": ["f001"], "description": "scan", "tier": "enum",
                      "target": "10.0.0.5", "title": None}]


def test_parse_fenced_and_prose():
    txt = 'Here is my plan:\n```json\n{"tasks": [{"from": "f001", "description": "x"}]}\n```\nDone.'
    specs = parse_tasks(txt)
    assert len(specs) == 1
    assert specs[0]["from"] == ["f001"]        # string coerced to list
    assert specs[0]["tier"] == "recon"          # default


def test_parse_garbage_is_empty():
    assert parse_tasks("sorry, I cannot help") == []
    assert parse_tasks("") == []
    assert parse_tasks('{"tasks": "not a list"}') == []


# -- plan() ------------------------------------------------------------------- #

def test_plan_creates_in_scope_task(tmp_path):
    s = _store(tmp_path)
    agent = ScriptedAgent('{"tasks": [{"from": ["f001"], "description": "enum svc", "tier": "enum", "target": "10.0.0.5"}]}')
    res = Engine(s, _scope(), model="m", agent=agent).plan()
    assert len(res.created) == 1
    assert s.get_task(res.created[0])["risk_tier"] == "enum"


def test_plan_refuses_out_of_scope(tmp_path):
    s = _store(tmp_path)
    # 10.0.0.9 is excluded; 8.8.8.8 is outside allowed entirely
    agent = ScriptedAgent('{"tasks": ['
                          '{"from": ["f001"], "description": "a", "tier": "enum", "target": "10.0.0.9"},'
                          '{"from": ["f001"], "description": "b", "tier": "enum", "target": "8.8.8.8"}]}')
    res = Engine(s, _scope(), model="m", agent=agent).plan()
    assert res.created == []
    assert set(res.skipped_scope) == {"10.0.0.9", "8.8.8.8"}


def test_plan_dedupes_open_tasks(tmp_path):
    s = _store(tmp_path)
    spec = '{"tasks": [{"from": ["f001"], "description": "enum svc", "tier": "enum", "target": "10.0.0.5"}]}'
    eng = Engine(s, _scope(), model="m", agent=ScriptedAgent(spec, spec))
    assert len(eng.plan().created) == 1
    # same proposal again while the first is still open -> no duplicate
    assert len(eng.plan().created) == 0


def test_plan_gated_task_queues_not_dispatched(tmp_path):
    s = _store(tmp_path)
    s.add_finding("vuln svc", creator="recon", kind="vuln", target="10.0.0.5")
    agent = ScriptedAgent('{"tasks": [{"from": ["f002"], "description": "pop CVE", "tier": "exploit", "target": "10.0.0.5"}]}')
    eng = Engine(s, _scope(), model="m", agent=agent)
    res = eng.plan()
    tid = res.created[0]
    # gated: not on the frontier, sitting in the approval queue
    assert tid not in {t["id"] for t in frontier(s)}
    assert tid in {t["id"] for t in awaiting_confirmation(s)}
    # step() must not dispatch it
    eng.step(res)
    assert res.dispatched == []


def test_confirmed_gated_task_dispatches(tmp_path):
    s = _store(tmp_path)
    s.add_finding("vuln svc", creator="recon", kind="vuln", target="10.0.0.5")
    agent = ScriptedAgent('{"tasks": [{"from": ["f002"], "description": "pop CVE", "tier": "exploit", "target": "10.0.0.5"}]}')
    eng = Engine(s, _scope(), model="m", agent=agent)
    tid = eng.plan().created[0]
    s.confirm_task(tid, operator="tester")
    res = eng.step()
    assert tid in res.dispatched


# -- run() -------------------------------------------------------------------- #

class RaisingAgent:
    """Plans one task, then every executor dispatch raises."""
    def __init__(self):
        self.calls = 0
    def __call__(self, prompt, **kwargs):
        self.calls += 1
        if self.calls == 1:  # commander pass
            return {"result": '{"tasks": [{"from": ["f001"], "description": "enum", "tier": "enum", "target": "10.0.0.5"}]}'}
        raise RuntimeError("agent binary not found")  # executor pass


def test_executor_failure_does_not_abort_run(tmp_path):
    s = _store(tmp_path)
    eng = Engine(s, _scope(), model="m", agent=RaisingAgent())
    history = eng.run(max_rounds=5)          # must not raise
    assert sum(len(r.created) for r in history) == 1
    assert sum(len(r.failed) for r in history) == 1
    assert sum(len(r.dispatched) for r in history) == 0
    assert eng.last_errors and "not found" in eng.last_errors[0]
    # the task is left claimed-but-open for a later run to retry
    t = s.list_tasks()[0]
    assert t["to"] is None


def test_run_terminates_when_no_new_work(tmp_path):
    s = _store(tmp_path)
    # round 1 proposes one enum task; subsequent rounds propose nothing
    agent = ScriptedAgent('{"tasks": [{"from": ["f001"], "description": "enum", "tier": "enum", "target": "10.0.0.5"}]}')
    history = Engine(s, _scope(), model="m", agent=agent).run(max_rounds=10)
    assert len(history) < 10                      # stopped early, did not spin
    assert sum(len(r.created) for r in history) == 1
    assert sum(len(r.dispatched) for r in history) >= 1
