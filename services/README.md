# services/ — polyglot microservice slice (Go + gRPC + Python)

A working proof of the [design decisions](../docs/en/ARCHITECTURE.md#design-decisions-rationale)
(modular monolith that's service-ready; offload a hot path without a rewrite): the first
extracted service (a **Go collector**) talks to the **Python detection
engine** over **gRPC**. The Python monolith is unchanged — `engine_grpc/server.py`
just exposes the existing engine over the wire.

```
  JSONL logs ─► [collector-go]  ──gRPC: Analyze(events)──►  [engine_grpc (Python)]
                                ◄──── ranked detections ────   (104 scenarios, NetworkX)
```

## Layout

| Path | What |
|------|------|
| `proto/fsrpc/v1/detector.proto` | the gRPC contract (`Detector.Analyze`) |
| `engine_grpc/server.py` | Python gRPC server wrapping `augur` engine |
| `engine_grpc/fsrpc/v1/*_pb2*.py` | generated Python stubs (committed) |
| `collector-go/main.go` | Go collector: reads JSONL → gRPC → prints detections |
| `collector-go/gen/fsrpcv1/*.pb.go` | generated Go stubs (committed) |
| `run-grpc-demo.sh` | starts the engine + runs the collector |

## Run it

Prerequisites: `uv` (Python), Go ≥ 1.26 (per `collector-go/go.mod`).

```bash
make grpc-demo            # one command: starts the engine, runs the Go collector
# or manually, in two terminals:
uv run --extra grpc python services/engine_grpc/server.py 50051
cd services/collector-go && go run . ../../sample_data/corpus/enterprise_day.jsonl 0.9
```

Expected: the collector reads ~1,968 events and the engine returns 11 detections at 100%.

## Tests

`tests/test_grpc_engine.py` exercises the servicer in-process. It **skips** unless the
optional extra is installed, so the default suite stays infra-free:

```bash
uv sync --extra grpc && uv run pytest tests/test_grpc_engine.py -v
```

## Regenerating stubs (only if you edit the .proto)

```bash
# Python (protoc bundled in grpcio-tools)
uv run --extra grpc python -m grpc_tools.protoc -I services/proto \
  --python_out=services/engine_grpc --grpc_python_out=services/engine_grpc \
  services/proto/fsrpc/v1/detector.proto

# Go (needs protoc-gen-go + protoc-gen-go-grpc on PATH:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest)
PATH="$(go env GOPATH)/bin:$PATH" uv run --extra grpc python -m grpc_tools.protoc -I services/proto \
  --go_out=services/collector-go/gen --go_opt=module=augur/collector/gen \
  --go-grpc_out=services/collector-go/gen --go-grpc_opt=module=augur/collector/gen \
  services/proto/fsrpc/v1/detector.proto
```
