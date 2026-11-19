"""Smoke tests for the engagement graph and the exploit confirmation gate."""
import pytest

from rt.store import Store, RTError, frontier, awaiting_confirmation
from rt.scope import Scope


def _init(tmp_path):
    s = Store(tmp_path / ".rt")
    s.init(engagement_id="TEST-1", objective="get domain admin", scope_ref="scope.json")
    return s


def test_init_and_finding(tmp_path):
    s = _init(tmp_path)
    assert s.exists()
    f = s.add_finding("ssh open", creator="recon", kind="service",
                      target="10.0.0.5", data={"port": "22"})
    assert f["id"] == "f001"
    assert s.get_finding("f001")["kind"] == "service"


def test_recon_task_is_not_gated(tmp_path):
    s = _init(tmp_path)
    f = s.add_finding("host up", creator="recon", kind="host", target="10.0.0.5")
    t = s.add_task([f["id"]], "enumerate services", creator="cmd",
                   risk_tier="enum", target="10.0.0.5")
    assert t["requires_confirmation"] is False
    assert t["id"] in {x["id"] for x in frontier(s)}


def test_exploit_task_is_gated(tmp_path):
    s = _init(tmp_path)
    f = s.add_finding("vuln svc", creator="recon", kind="vuln", target="10.0.0.5")
    t = s.add_task([f["id"]], "exploit CVE-2021-41773", creator="cmd",
                   risk_tier="exploit", target="10.0.0.5")
    assert t["requires_confirmation"] is True
    # not ready and not claimable until confirmed
    assert t["id"] not in {x["id"] for x in frontier(s)}
    assert t["id"] in {x["id"] for x in awaiting_confirmation(s)}
    with pytest.raises(RTError):
        s.claim_task(t["id"], worker="exploit-agent")
    # operator confirms -> now claimable
    s.confirm_task(t["id"], operator="esmadi")
    claimed = s.claim_task(t["id"], worker="exploit-agent")
    assert claimed["status"] == "claimed"
    assert s.get_task(t["id"])["confirmed_by"] == "esmadi"


def test_exploit_task_requires_target(tmp_path):
    s = _init(tmp_path)
    f = s.add_finding("x", creator="r", kind="vuln", target="10.0.0.5")
    with pytest.raises(RTError):
        s.add_task([f["id"]], "exploit", creator="cmd", risk_tier="exploit")


def test_scope_in_out(tmp_path):
    sc = Scope(engagement_id="T", allowed_cidrs=["10.0.0.0/24"],
               excluded_cidrs=["10.0.0.9/32"], allowed_domains=["app.acme.test"])
    sc.sign("esmadi")
    assert sc.verify()
    assert sc.permits("10.0.0.5")
    assert sc.permits("https://app.acme.test/login")
    assert not sc.permits("10.0.0.9")        # excluded wins
    assert not sc.permits("10.9.9.9")         # not allowed
    assert not sc.permits("evil.example.com")
