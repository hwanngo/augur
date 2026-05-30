[English](../en/CONTRIBUTING.md) | **Tiếng Việt**

# Augur — Hướng dẫn đóng góp

Tài liệu này bao gồm toàn bộ quy trình phát triển: thiết lập môi trường, các yêu cầu về kiểm thử, các bất biến không được vi phạm, cách thêm kịch bản, cách thêm nguồn log mới hoặc bộ chuẩn hóa OS, các tính năng mở rộng tùy chọn (Neo4j, gRPC, AI generation), quy ước commit, và các mục tiêu Make. Khi một chủ đề không được đề cập ở đây, tài liệu chuyên sâu liên quan sẽ được liên kết.

Tài liệu liên quan: [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) | [ARCHITECTURE.md](ARCHITECTURE.md) | [ENGINE.md](ENGINE.md) | [DATA_MODEL.md](DATA_MODEL.md)

---

## Yêu cầu tiên quyết

- **Python 3.14 trở lên** — `pyproject.toml` của dự án yêu cầu `requires-python = ">=3.14"`.
- **uv** — công cụ quản lý môi trường và phụ thuộc duy nhất cho dự án này.

Cài đặt uv nếu chưa có:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Tuyệt đối không dùng `pip`, `pip install`, hay `python -m venv`** cho dự án này. Mọi thao tác với môi trường, bao gồm cài đặt phụ thuộc, chạy kiểm thử, và chạy các module CLI, đều thực hiện qua `uv`.

Tùy chọn, cho các quy trình làm việc dựa trên Docker:

- **Docker với Compose v2** — cần cho `make up` (toàn bộ stack đóng gói container) hoặc `make neo4j-local`.
- **pnpm** — cần cho `make ui-build` hoặc `make ui-dev` (frontend React).

---

## Cài đặt

```bash
git clone <repo>
cd augur
make install   # tương đương: uv sync
```

`uv sync` đọc `pyproject.toml`, tạo `.venv`, và cài đặt:

- **Phụ thuộc runtime** — `pydantic`, `PyYAML`, `networkx`, `fastapi`, `uvicorn`, `argon2-cffi`, `python-multipart`
- **Nhóm dev** — `pytest`, `httpx2`

Các extra `neo4j`, `grpc`, và `ai` **không** được cài mặc định. Xem phần "Các extra tùy chọn" bên dưới.

---

## Chạy kiểm thử

```bash
make test                                      # = uv run pytest -q
uv run pytest -q                               # tương tự — 1164 passed, 3 skipped
uv run pytest -v                               # đầu ra chi tiết
uv run pytest -v tests/test_acceptance.py      # một tệp cụ thể
uv run pytest -k "test_scoring"               # theo từ khóa
```

Kết quả cơ bản mong đợi: **1164 passed, 3 skipped**. 3 bài bị bỏ qua là các bài kiểm thử tích hợp Neo4j (luôn bị bỏ qua trừ khi `AUGUR_NEO4J_TEST=1` — xem bên dưới).

### Yêu cầu TDD

Augur tuân theo phương pháp Phát triển Hướng kiểm thử (Test-Driven Development). Trước khi triển khai bất kỳ tính năng mới nào:

1. Viết một bài kiểm thử thất bại mô tả chính xác hành vi mong đợi.
2. Chạy `uv run pytest -q` và xác nhận rằng bài kiểm thử thất bại vì đúng lý do.
3. Viết lượng code production tối thiểu để bài kiểm thử vượt qua.
4. Tái cấu trúc nếu hữu ích; giữ bài kiểm thử luôn xanh.

Các bài kiểm thử chấp nhận trong `tests/test_acceptance.py` và bài kiểm thử cổng v2 trong `tests/test_scenario_library_v2.py` là nguồn sự thật cho tính đúng đắn của engine. Không được điều chỉnh các assertions của chúng để khớp với một triển khai bị lỗi.

---

## Cấu trúc dự án

```
augur/
├── pyproject.toml              # metadata, deps, cấu hình pytest
├── Makefile                    # make help | install | dev | test | engine | demo |
│                               #       demo-min | hunt | up | down | logs | neo4j-local |
│                               #       grpc-demo | ui-dev | ui-build | clean
├── Dockerfile                  # image ứng dụng (Python 3.14, uv, extra neo4j)
├── docker-compose.yml          # toàn bộ stack: app + Neo4j 5.26 + named volumes
├── scripts/
│   └── regen_sample_data.py    # tái tạo toàn bộ fixture sample_data từ các kịch bản
├── src/augur/                  # toàn bộ mã nguồn production
│   ├── enums.py                # Severity, Zone, Criticality, LinkScope, SEVERITY_RANK
│   ├── pipeline.py             # build_backend(), default_topology(), default_scenarios()
│   ├── demo.py                 # python -m augur.demo  (phục vụ dashboard / headless)
│   ├── hunt.py                 # python -m augur.hunt  (source → engine → sinks)
│   ├── generate.py             # python -m augur.generate  (tạo ứng viên bằng LLM, [ai])
│   ├── useradmin.py            # python -m augur.useradmin (bootstrap admin)
│   ├── maintenance.py          # python -m augur.maintenance (lưu trữ / prune)
│   ├── topology/
│   │   ├── network.py          # load_topology(), Topology.enrich(host) -> (Zone, Criticality)
│   │   └── standard_topology.yaml
│   ├── scenarios/
│   │   ├── schema.py           # Scenario, Step, TemporalLink, SpatialConstraints (extra=forbid)
│   │   └── loader.py           # load_scenarios(dir) — đệ quy, kiểm tra trùng id
│   ├── ingest/
│   │   └── jsonl.py            # read_jsonl(path) — ném IngestError kèm số dòng
│   ├── normalize/
│   │   ├── registry.py         # dict REGISTRY; normalize_event(); dispatch theo source_type
│   │   ├── model.py            # dataclass NormalizedEvent
│   │   ├── windows_sysmon.py   # source_type "windows_sysmon" (event_id 1/7/"edr")
│   │   ├── linux_auditd.py     # source_type "linux_auditd" (EXECVE/SYSCALL/EDR)
│   │   ├── macos_esf.py        # source_type "macos_esf" (ES_EVENT_NOTIFY_EXEC/MMAP)
│   │   └── ecs.py              # shim tương thích ngược cho đường dẫn Windows legacy (không có source_type)
│   ├── graph/
│   │   ├── models.py           # dataclass HostNode, ProcessNode, FileNode, Edge
│   │   ├── interface.py        # ABC GraphBackend
│   │   ├── networkx_backend.py # backend mặc định không cần hạ tầng
│   │   ├── neo4j_backend.py    # adapter Cypher tùy chọn
│   │   └── builder.py         # build_graph(events, topology, backend)
│   ├── engine/
│   │   ├── criteria.py         # match_value(), node_matches(), behavior_edge_matches()
│   │   ├── matcher.py          # match_scenario() — DFS prefix dài nhất hợp lệ
│   │   ├── scoring.py          # dataclass Detection, build_detection(), rank()
│   │   └── runner.py           # run_engine(backend, scenarios, min_proximity)
│   ├── connectors/             # giao thức Source/Sink + run_hunt()
│   ├── auth/                   # cookie phiên, argon2id, RBAC, CSRF, rate-limit
│   ├── alerting/               # cảnh báo có trạng thái, bands, SOC inbox, giám sát tự động
│   ├── generative/             # tạo ứng viên LLM tùy chọn [ai] + gauntlet guardrail
│   ├── simulator/              # bộ tạo log đa-OS xác định (feed PoC)
│   ├── metrics/                # phủ MITRE, tỷ lệ FP, khả năng phát hiện. CLI augur.metrics
│   └── api/app.py              # FastAPI: tất cả route, RBAC, CSRF, phục vụ static
├── frontend/                   # React 19 + Vite + TS + Tailwind (SPA console SOC)
├── scenarios/                  # 40 tệp *.yaml trong 14 thư mục con tactic ATT&CK
│   ├── reconnaissance/
│   ├── resource_development/
│   ├── initial_access/
│   ├── execution/
│   ├── persistence/
│   ├── privilege_escalation/
│   ├── defense_evasion/
│   ├── credential_access/
│   ├── discovery/
│   ├── lateral_movement/
│   ├── collection/
│   ├── command_and_control/
│   ├── exfiltration/
│   └── impact/
├── sample_data/                # fixture *_tp.jsonl theo từng kịch bản + acceptance/ + corpus/
└── tests/                      # bộ kiểm thử pytest (phẳng, không có thư mục con)
```

---

## Các bất biến — Không được vi phạm

Các bất biến này bảo vệ tính đúng đắn và khả năng chuyển đổi của engine. Một PR vi phạm bất kỳ bất biến nào sẽ không được merge.

### 1. Tính xác định của engine
`match_scenario` phải tạo ra đầu ra giống hệt nhau cho các đầu vào giống hệt nhau. Bộ so khớp sắp xếp các tập ứng viên theo `(timestamp, element_id)` trước khi DFS. Không được có đọc đồng hồ hệ thống, không có sự ngẫu nhiên, và không có thứ tự lặp không xác định ở bất kỳ đâu trong đường dẫn tính điểm.

### 2. Bộ kiểm thử mặc định không cần hạ tầng
`uv run pytest` (hoặc `make test`) phải vượt qua với **không có dịch vụ ngoài nào** — không có Neo4j đang chạy, không có truy cập mạng, không có Docker, không có timer thực. `NetworkXBackend` luôn là mặc định. Ba bài kiểm thử Neo4j trong `tests/test_neo4j_backend.py` được trang trí với `@pytest.mark.skipif(AUGUR_NEO4J_TEST != "1", ...)` và phải giữ nguyên như vậy.

### 3. Topology là nguồn chân lý
`Topology.enrich(hostname)` là nguồn chân lý duy nhất cho zone và criticality. Các trường `zone` do sự kiện cung cấp bị bỏ qua trong quá trình đánh giá ràng buộc. Một host không xác định nhận `(Zone.Unknown, Criticality.UNKNOWN)` và tự động thất bại tất cả các ràng buộc không gian. Không được bỏ qua điều này.

### 4. Tính chặt chẽ của schema kịch bản
Tất cả các model pydantic đều dùng `ConfigDict(extra="forbid")`. Thêm các trường mới một cách tường minh — không bao giờ nới lỏng thành `extra="allow"`. Bộ xác thực kịch bản cũng thực thi: `step_ids` phải liên tục từ 1..N; bước 1 không được có `temporal_link`; tất cả các bước tiếp theo phải có `temporal_link` với `previous_step == step_id - 1`.

### 5. Công thức proximity
`proximity = round(matched_len / scenario.step_count, 4)`. Prefix phải hoàn toàn liên tục — một bước thất bại ở bất kỳ cổng nào (không gian, thời gian, hoặc link-scope) sẽ phá vỡ chuỗi; các bước sau không thể đóng góp. Không được thay đổi công thức mà không cập nhật [ENGINE.md](ENGINE.md) và các bài kiểm thử chấp nhận.

### 6. Thứ tự xếp hạng
`rank()` sắp xếp theo `(-proximity, -severity_rank, -latest_ts_epoch)`. Không được thay đổi thứ tự này.

### 7. Không có LLM trong đường dẫn mặc định
Extra `[ai]` (`anthropic` SDK) không bao giờ được import ngoài `src/augur/generative/`. `uv sync` mặc định không được kéo SDK vào. Lớp generative được kiểm soát bởi admin và hoạt động trên các đột biến ứng viên vượt qua gauntlet guardrail xác định trước khi được con người phê duyệt.

### 8. `_public()` loại bỏ các trường Detection riêng tư
`api/app.py::_public()` xóa bất kỳ trường `Detection` nào có tên bắt đầu bằng `_` (cụ thể là `_latest_ts`, `_latest_ts_epoch`, `_severity_rank`) trước khi gửi phản hồi API. Không được đổi tên các trường này mà không cập nhật `_public()`.

---

## Cách thêm kịch bản mới

Tài liệu tham khảo schema đầy đủ có trong [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md). Các bước dưới đây là danh sách kiểm tra bắt buộc.

### 1. Chọn ID và thư mục tactic

ID kịch bản có tiền tố theo OS: `SCEN-WIN-NNN`, `SCEN-LNX-NNN`, `SCEN-MAC-NNN`, hoặc `SCEN-CLD-NNN`. Chọn số thứ tự tiếp theo cho OS family. Đặt tệp YAML trong thư mục tactic ATT&CK tương ứng:

```
scenarios/<tactic>/<descriptive_name>.yaml
```

Ví dụ: `scenarios/credential_access/lsass_comsvcs.yaml`.

### 2. Viết YAML

```yaml
scenario_metadata:
  scenario_id: SCEN-WIN-042
  name: "My New Scenario"
  description: "..."
  severity: HIGH
  os_family: windows           # windows | linux | macos
  applicable_zones:
    - User_Endpoint
  mitre_mappings:
    - tactic: credential_access
      technique: T1003.001
  validation_queries:
    - type: kql
      query: |
        SecurityEvent | where EventID == 4688 ...

steps:
  - step_id: 1
    description: "Step 1 description"
    matching_criteria:
      Node_Type: Process
      process_name: suspicious.exe   # thân thiện với synth: chuỗi chính xác hoặc pattern đơn giản
  - step_id: 2
    description: "Step 2"
    temporal_link:
      previous_step: 1
      link_scope: same_host
      max_time_delta_seconds: 120
    matching_criteria:
      Node_Type: Process
      process_name: another.exe
```

Các quy tắc chính:
- `Node_Type` là bắt buộc trong `matching_criteria` của mỗi bước.
- Bước 2..N phải có `temporal_link` với `previous_step == step_id - 1`.
- Bước 1 **không được** có `temporal_link`.
- Bao gồm `≥1` `mitre_mapping` và `≥1` `validation_query`.
- Giữ criteria thân thiện với synth (chuỗi chính xác hoặc pattern đơn giản) — bài kiểm thử cổng v2 tổng hợp một trace và kỳ vọng kịch bản kích hoạt ở 1.0.

### 3. Vượt qua bài kiểm thử cổng v2

Đây là cổng kiểm soát chất lượng quan trọng nhất. Nó tổng hợp một trace từ kịch bản, đưa vào engine, và xác nhận proximity == 1.0:

```bash
uv run pytest tests/test_scenario_library_v2.py -v
```

Bài kiểm thử `test_every_v2_scenario_synthesizes_and_fires_at_1` sẽ thất bại nếu criteria của kịch bản quá rộng (false positive trên traffic lành tính) hoặc quá hẹp để khớp với trace tổng hợp. Lặp lại cho đến khi bài kiểm thử này xanh.

Cùng tệp cũng chạy `test_every_v2_scenario_well_formed` (định dạng ID, `os_family`, `step_count >= 3`, `>= 1` ánh xạ MITRE) và `test_v2_covers_all_14_tactics` (phủ tactic trên toàn thư viện).

### 4. Tái tạo dữ liệu mẫu

Sau khi bài kiểm thử cổng v2 vượt qua, tái tạo fixture TP theo từng kịch bản để bài kiểm thử cổng fixture cũng vượt qua:

```bash
uv run python -m scripts.regen_sample_data
```

Script này gọi `render_injection` cho mỗi kịch bản, ghi một `sample_data/<tactic>/<SCEN-ID>_tp.jsonl` cho mỗi kịch bản, và cũng tái tạo các fixture `acceptance/` và `corpus/`. Các tệp kết quả phải được commit cùng với YAML kịch bản.

### 5. Xác nhận cổng fixture

```bash
uv run pytest tests/test_scenario_tp_fixtures.py -v
```

`test_tp_fixture_matches_its_scenario_fully` tham số hóa trên mỗi tệp `*_tp.jsonl` và xác nhận proximity == 1.0. Điều này phải vượt qua với kịch bản mới của bạn.

### 6. Chạy toàn bộ bộ kiểm thử

```bash
make test   # 1164 passed, 3 skipped — không có hồi quy
```

---

## Cách thêm nguồn log mới / Bộ chuẩn hóa OS

Toàn bộ quá trình phân tích sự kiện được điều phối qua `src/augur/normalize/registry.py` sử dụng trường `source_type` trong các sự kiện log thô.

### 1. Viết module chuẩn hóa

Tạo `src/augur/normalize/<source_type>.py`. Module phải expose một hàm `normalize(raw: dict) -> NormalizedEvent | None`. Trả về `None` cho các loại sự kiện mà bộ chuẩn hóa không xử lý.

Dùng `windows_sysmon.py` hoặc `linux_auditd.py` làm tài liệu tham khảo. Hàm ánh xạ các trường thô sang `NormalizedEvent` (được định nghĩa trong `normalize/model.py`). Trường `kind` phải là một trong `"process_create"`, `"image_load"`, hoặc `"behavior"`.

### 2. Đăng ký bộ chuẩn hóa

Trong `src/augur/normalize/registry.py`, thêm khóa `source_type` mới vào `REGISTRY`:

```python
from augur.normalize import windows_sysmon, linux_auditd, macos_esf, my_source

REGISTRY: dict[str, ...] = {
    "windows_sysmon": windows_sysmon.normalize,
    "linux_auditd": linux_auditd.normalize,
    "macos_esf": macos_esf.normalize,
    "my_source": my_source.normalize,     # thêm ở đây
}
```

Các sự kiện không có `source_type` sẽ chuyển sang đường dẫn legacy `windows_sysmon` (không cần thay đổi cho điều đó).

### 3. Mở rộng NormalizedEvent nếu cần

Nếu nguồn mới giới thiệu các trường chưa có trong `NormalizedEvent`, thêm chúng vào `src/augur/normalize/model.py`. Tuân theo các quy ước đặt tên hiện có (snake_case, các trường tùy chọn mặc định là `None`).

### 4. Cập nhật xây dựng đồ thị nếu cần

Nếu kind mới tạo ra loại node hoặc edge mới, thêm nhánh tương ứng trong `src/augur/graph/builder.py`. Nếu nó tái sử dụng các loại hiện có (ví dụ: một sự kiện process khác), thêm nhánh trong logic `build_graph` hiện có.

### 5. Cập nhật criteria engine nếu cần

Nếu nguồn mới giới thiệu các thuộc tính có thể so khớp chưa có trong `PROCESS_KEY_MAP` hoặc `FILE_KEY_MAP`, thêm chúng vào `src/augur/engine/criteria.py`.

### 6. Viết kiểm thử

Thêm các bài kiểm thử chuẩn hóa trong `tests/test_normalize_<source_type>.py` theo các mẫu trong `test_normalize_linux.py` hoặc `test_normalize_macos.py`. Thêm các bài kiểm thử builder trong `tests/test_builder.py` nếu có loại node/edge mới. Tất cả các bài kiểm thử phải không cần hạ tầng.

---

## Cách thêm một tín hiệu telemetry mù với engine

Một số tín hiệu (các kind `dns_query` / `network_connect` được thêm cho overlay threat-intel IOC) **chỉ** cấp cho overlay chỉ-đọc `/api/ioc_match` — engine không bao giờ thấy chúng. Công thức giữ chúng hoàn toàn bổ sung để đầu ra engine vẫn giống hệt từng byte:

1. **Thêm (các) field vào `NormalizedEvent`** (`normalize/model.py`) — tùy chọn, mặc định `None`/rỗng. Giữ chúng **ngoài** `PROCESS_KEY_MAP` / `FILE_KEY_MAP` của `criteria.py` để engine vẫn mù với chúng (ví dụ `hashes`, `domain`, `dest_ip`, `dest_port`).
2. **Ánh xạ sự kiện nguồn → một `kind` mới** trong bộ chuẩn hóa theo từng OS (ví dụ `dns_query`, `network_connect`).
3. **Thêm nhánh nghịch đảo** vào bộ emitter simulator theo từng OS (`simulator/emitters.py`) để simulator có thể tạo ra tín hiệu.
4. **Tái tạo sample_data** bằng `uv run python -m scripts.regen_sample_data`.
5. **Thêm một bài kiểm thử guard graph-equality** chứng minh `build_graph` loại bỏ kind mới (không node/edge nào) để đầu ra engine giống hệt từng byte — xem `tests/test_graph_blind_multi_os_netintel.py`.

Bất biến cốt lõi vẫn giữ: **code engine / matcher / scoring / graph KHÔNG BAO GIỜ được thay đổi** để thêm một tín hiệu mù với engine. Nếu một tín hiệu cần điều khiển phát hiện, nó không còn mù với engine nữa — thay vào đó hãy thêm nó như một node/edge graph và một khóa criteria theo phần ở trên.

---

## Cách thêm Behavior Marker mới

Các sự kiện behavior từ EDR tạo ra các edge tự vòng `EXHIBITED` trên các instance `ProcessNode`. Thuộc tính edge `behavior` mang một thẻ chuỗi (ví dụ: `"lsass_access"`, `"shadow_copy_delete"`).

Để thêm một behavior marker mới:

1. Thêm các sự kiện mẫu mang chuỗi behavior mới vào tệp `sample_data/*.jsonl` liên quan.
2. Tham chiếu marker trong một bước kịch bản bằng cách dùng `Behavior_Markers: ["my_new_behavior"]` trong `matching_criteria`.
3. Không cần thay đổi code trừ khi bạn cần một **khóa criterion mới** ngoài `Behavior_Markers`, `TargetProcess`, và `GrantedAccess` hiện có. Nếu cần khóa mới:
   - Thêm nó vào `BEHAVIOR_KEYS` trong `src/augur/engine/criteria.py`.
   - Thêm logic so khớp vào `behavior_edge_matches()`.
   - Cập nhật [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md).

---

## Các extra tùy chọn

Ba extra mở rộng Augur với các khả năng tùy chọn. Chúng không bao giờ được import ngoài các module được chỉ định và không được xuất hiện trong lần chạy kiểm thử mặc định.

### `[neo4j]` — backend đồ thị thay thế

```bash
uv sync --extra neo4j
```

Cài đặt driver Python `neo4j`. Backend được kích hoạt bằng cách đặt `AUGUR_BACKEND=neo4j`. Xem [ARCHITECTURE.md](ARCHITECTURE.md) để biết về abstraction `GraphBackend`.

Các bài kiểm thử tích hợp (3 trong `tests/test_neo4j_backend.py`) bị bỏ qua theo mặc định. Chạy chúng với một instance Neo4j đang hoạt động:

```bash
AUGUR_NEO4J_TEST=1 uv run pytest tests/test_neo4j_backend.py -v
```

Các bài kiểm thử này không bao giờ được thêm vào lần chạy `make test` mặc định.

### `[grpc]` — lát cắt microservice gRPC đa ngôn ngữ

```bash
uv sync --extra grpc
```

Cài đặt `grpcio` và `grpcio-tools`. Được dùng bởi demo Go collector → Python detection engine gRPC (`services/`, xem ARCHITECTURE.md). Chạy với `make grpc-demo`.

### `[ai]` — lớp ứng viên kịch bản generative

```bash
uv sync --extra ai
```

Cài đặt `anthropic`. Bật `python -m augur.generate` và các route API `/api/generate` + `/api/candidates` (chỉ admin). Biến môi trường `ANTHROPIC_API_KEY` là bắt buộc khi runtime. Không có gì tự động vào thư viện kịch bản: đầu ra LLM chạy qua toàn bộ gauntlet guardrail xác định (xác thực schema → dedup → kiểm tra FP → kiểm tra khả năng phát hiện) trước khi con người phê duyệt qua UI hoặc API.

Extra `[ai]` không bao giờ được import ở bất kỳ đâu ngoài `src/augur/generative/`.

---

## Connectors (Sources và Sinks)

Lớp connector có thể cắm vào trong `src/augur/connectors/` tách rời việc nhập log khỏi engine và cho phép các phát hiện được phân phối đến nhiều đích mà không cần chạm vào engine.

| Khái niệm | Interface | Vị trí |
|-----------|-----------|--------|
| `Source` | `read() -> Iterable[dict]` | `connectors/base.py` |
| `Sink` / `SinkBase` | `emit(Detection)`, `emit_all(list[Detection])` | `connectors/base.py` |
| Registry | `SOURCES`, `SINKS`, `get_source()`, `get_sink()` | `connectors/__init__.py` |
| Orchestrator | `run_hunt(source, sinks, *, min_proximity, …)` | `connectors/runner.py` |

`run_hunt` pipeline: `source.read()` → `normalize_events` → `build_graph` → `run_engine` → phân phối phát hiện đến mọi sink. Mỗi sink được cô lập — một sink bị crash được ghi log và không chặn các sink khác.

Chạy một hunt từ CLI:

```bash
make hunt
# tương đương với:
uv run python -m augur.hunt \
  --source jsonl --source-arg path=sample_data/corpus/enterprise_day.jsonl \
  --sink stdout --sink jsonl --sink-arg jsonl:path=out/detections.jsonl \
  --min-proximity 0.9
```

Source tích hợp sẵn: `jsonl`, `directory`, `stdin`. Sink tích hợp sẵn: `stdout`, `jsonl`, `webhook`, `slack`. Dùng `AUGUR_WEBHOOK_URL` / `AUGUR_SLACK_WEBHOOK_URL` cho URL webhook.

**Thêm Source:** triển khai `read(self) -> Iterable[dict]`, đăng ký trong `SOURCES`, viết bài kiểm thử không cần hạ tầng trong `tests/test_connectors.py`.

**Thêm Sink:** kế thừa `SinkBase`, triển khai `emit(self, detection: Detection) -> None`, đăng ký trong `SINKS`, viết bài kiểm thử không cần hạ tầng (dùng `tmp_path` cho sink file, `ThreadingHTTPServer` trong process cho sink mạng).

---

## Quy trình làm việc Docker

### Toàn bộ stack đóng gói container

```bash
make up      # docker compose up -d --build (cũng chạy ui-build trước)
make down    # docker compose down (named volumes vẫn giữ lại — dùng -v để xóa)
make logs    # docker compose logs -f app
```

File compose khởi động:
- **app** — FastAPI + React SPA tại `http://localhost:8000`, được cấu hình với `AUGUR_BACKEND=neo4j` và `NEO4J_URI=bolt://neo4j:7687`.
- **neo4j** — Neo4j 5.26 tại cổng 7474 (trình duyệt) + 7687 (Bolt), named volumes `neo4j_data`/`neo4j_logs`.

Named volumes tồn tại qua các chu kỳ `down`/`up`. Chỉ dùng `docker compose down -v` để xóa dữ liệu đồ thị đã lưu trữ.

### Neo4j trong Docker, engine chạy cục bộ

```bash
uv sync --extra neo4j
make neo4j-local
# tương đương với:
# docker compose up -d neo4j
# AUGUR_BACKEND=neo4j NEO4J_URI=bolt://localhost:7687 uv run --extra neo4j python -m augur.demo
```

Mặc định Neo4j: `bolt://localhost:7687`, user `neo4j`, password `augur`. Ghi đè bằng `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`.

---

## Tài liệu tham khảo mục tiêu Make

Chạy `make` (hoặc `make help`) để xem danh sách tự tài liệu hóa, phân nhóm. Ghi đè tham số trên dòng
lệnh, ví dụ `make demo PORT=9000`. Mỗi mục tiêu có chú thích `## …` mà `make help` hiển thị.

| Mục tiêu | Chức năng |
|----------|----------|
| `make help` | Liệt kê tất cả mục tiêu, phân nhóm (mục tiêu mặc định) |
| `make install` | `uv sync` — tạo/cập nhật venv |
| `make dev` | Chạy API (`:8000`) + Vite dev server (`:5173`) cùng lúc — UI tải lại nóng |
| `make test` | `uv run pytest -q` — toàn bộ bộ kiểm thử (1164 passed, 3 skipped) |
| `make engine` | Chạy demo headless trên mẫu 2-attack tích hợp sẵn (`--no-serve`) |
| `make demo` | Dashboard trên corpus `enterprise_day.jsonl` đầy đủ — `http://127.0.0.1:8000`; khởi tạo đăng nhập `admin`/`dev-password-123` trên DB mới |
| `make demo-min` | Dashboard trên mẫu 2-attack tối giản |
| `make hunt` | Corpus → engine → stdout + `out/detections.jsonl` (min-proximity 0.9) |
| `make up` | Build UI rồi `docker compose up -d --build` (app + Neo4j) |
| `make down` | `docker compose down` |
| `make logs` | `docker compose logs -f app` |
| `make neo4j-local` | Chỉ khởi động Neo4j trong Docker; chạy engine cục bộ kết nối vào đó |
| `make grpc-demo` | Demo Go collector → gRPC → Python engine |
| `make ui-dev` | Vite dev server (proxy `/api` đến localhost:8000) |
| `make ui-build` | `pnpm build` (tự cài deps khi lockfile thay đổi) — tạo ra `frontend/dist` |
| `make clean` | Xóa `__pycache__`, `.pytest_cache`, egg-info |

---

## Quy ước commit

Dự án này dùng [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope tùy chọn>): <mô tả ngắn, ≤72 ký tự>

[nội dung tùy chọn — giải thích tại sao, không chỉ cái gì]
```

| Type | Khi nào sử dụng |
|------|----------------|
| `feat` | Tính năng mới hoặc kịch bản mới |
| `fix` | Sửa lỗi |
| `test` | Thêm hoặc sửa kiểm thử |
| `refactor` | Tái cấu trúc mà không thay đổi hành vi |
| `docs` | Chỉ thay đổi tài liệu |
| `chore` | Build, CI, công cụ |

Ví dụ:

```
feat(scenarios): add SCEN-LNX-014 cron-based persistence scenario
fix(normalize): handle missing is_injected field in EID 7 events
test(acceptance): add no_detection_temporal_gap case for SCEN-WIN-001
docs: update ENGINE.md proximity formula section
chore: bump pydantic to 2.13.4
```

Commit thường xuyên. Các commit nhỏ, tập trung dễ review và bisect hơn.

---

## Ghi chú về chất lượng code

- **Các model Pydantic** — tất cả đều dùng `ConfigDict(extra="forbid")`. Không được nới lỏng thành `extra="allow"`.
- **Các node đồ thị** — các đối tượng `@dataclass` thuần túy trong `graph/models.py`. Giữ chúng là dataclass; `api/app.py` dùng `dataclasses.asdict()` để tuần tự hóa.
- **Giá trị chuỗi Enum** — `Zone`, `Severity`, `Criticality`, `LinkScope` đều là `str, Enum`. Các thuộc tính `.value` của chúng là các chuỗi chuẩn dùng trong YAML, phản hồi API, và các kiểm tra ràng buộc không gian.
- **Timestamps** — luôn là các đối tượng `datetime` (có nhận thức múi giờ, từ `datetime.fromisoformat()`). Không bao giờ so sánh hoặc sắp xếp chuỗi ISO thô.
- **Không dùng `print()` trong code thư viện** — chỉ `demo.py` và các điểm entry CLI mới in ra stdout. Code thư viện dùng logging.
- **Đặt tên tệp kiểm thử** — phẳng trong `tests/`, có tiền tố `test_`. Không có thư mục con.
- **Kiểm thử không cần hạ tầng** — không có lời gọi mạng thực, không có subprocess, không có `time.sleep`. Dùng `tmp_path`, `monkeypatch`, và server trong process.
