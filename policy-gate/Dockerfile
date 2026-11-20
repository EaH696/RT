# RT policy-gate — authoritative scope enforcement + egress decision service.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rt-policy-gate ./...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rt-policy-gate /usr/local/bin/rt-policy-gate
EXPOSE 8700
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rt-policy-gate"]
CMD ["-scope", "/scope/scope.json", "-addr", ":8700"]
