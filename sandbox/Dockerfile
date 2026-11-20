# RT sandbox — tool-execution runner with egress pinned to the policy-gate.
#
# NOTE: the Community image uses LocalRuntime (no microVM isolation) unless
# RT_CONTAINER_SHIM points at a gVisor/Firecracker launcher. The hardened,
# egress-pinned runtime ships with the supported Enterprise appliance.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rt-sandbox ./...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rt-sandbox /usr/local/bin/rt-sandbox
EXPOSE 8710 8720
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rt-sandbox"]
CMD ["-addr", ":8710", "-egress-addr", ":8720", "-gate", "http://policy-gate:8700"]
