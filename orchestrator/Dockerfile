# RT orchestrator — the engagement graph, agents, `rt` CLI and operator console.
# stdlib-only core, so the image stays small and runs on an air-gapped host.
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
# Default model runner; point RT_AGENT_BIN at a locally served model so no
# target data leaves the appliance.
ENV RT_AGENT_BIN=claude
EXPOSE 8800
ENTRYPOINT ["rt"]
CMD ["--help"]
