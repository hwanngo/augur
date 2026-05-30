**English** | [Tiếng Việt](../vi/README.md)

# Augur

**Nền tảng săn lùng mối đe dọa chủ động và kiểm định rủi ro xác định luận, không dùng AI.**

Augur trả lời một câu hỏi duy nhất, theo cách xác định luận và không cần LLM nào: *"Kịch bản tấn công này có đang diễn ra bên trong tổ chức của tôi không — và nếu có, đó chính xác là kịch bản nào, và đã tiến tới đâu rồi?"*

Augur nhận vào nhật ký endpoint thô (JSON Lines), chuẩn hóa chúng qua các bộ chuẩn hóa đa hệ điều hành về một lược đồ sự kiện chính tắc, chiếu chúng lên đồ thị tri thức thời gian được làm giàu bằng tô-pô mạng, rồi chấm điểm xem mỗi kịch bản tấn công định sẵn hiện diện đến đâu. Đầu ra là danh sách các lần phát hiện được xếp hạng — mỗi lần kèm theo điểm gần kề `matched/total`, chuỗi bằng chứng từng bước, và các truy vấn săn lùng KQL/Sigma sẵn sàng sao chép — được trình bày qua backend REST FastAPI và bảng điều khiển SOC React.

Không có lời gọi LLM nào trong đường chấm điểm. Không có hộp đen xác suất. Đầu vào giống hệt nhau luôn tạo ra kết quả giống hệt nhau, hoàn toàn có thể giải thích.

---

## Tại sao Augur tồn tại

Các nhóm SOC đối mặt với hai vấn đề tích lũy. Thứ nhất là **mệt mỏi cảnh báo**: các công cụ thông thường được tối ưu để tạo ra càng nhiều tín hiệu càng tốt, nhấn chìm các nhà phân tích trong nhiễu loạn và hướng sự chú ý hầu như hoàn toàn vào các sự kiện của hôm qua. Thứ hai là thiếu một **lăng kính kiểm định chuỗi tấn công**: ngay cả khi những sự kiện đáng ngờ xuất hiện, vẫn không có cơ chế tự động hỏi liệu chúng có tạo thành các bước đầu của một kịch bản tấn công *cụ thể, được đặt tên* đang diễn ra hay không.

Augur bác bỏ mô hình tối đa hóa cảnh báo. Thay vì hỏi "sự kiện này có vẻ đáng ngờ không?", nó hỏi "mô hình chuỗi tấn công X có đang tiến triển bên trong mạng này không, và kẻ tấn công đã đi đến đâu rồi?" Mỗi lần phát hiện đều gắn với một kịch bản có tên, do con người viết; mỗi điểm gần kề là thước đo trực tiếp của số bước chuỗi tấn công có thứ tự đã được quan sát; mỗi kết quả đều cho thấy chính xác những bước nào đã khớp, trên host nào, vào lúc nào, và bằng chứng nào vẫn còn thiếu.

Augur hỗ trợ hai hoạt động bổ sung:

- **Săn lùng chủ động** — với dữ liệu nhật ký trực tiếp hoặc gần đây, phát hiện kịch bản tấn công nào đang diễn ra, xếp hạng theo mức độ tiến triển và mức độ nghiêm trọng.
- **Đánh giá tư thế bảo mật** — ngay cả khi không có sự cố đang xảy ra, các điểm gần kề trên tất cả kịch bản cho một số đọc phơi nhiễm định lượng. Một kịch bản ở mức gần kề 40% là ưu tiên săn lùng trước khi bất kỳ cảnh báo nào kích hoạt.

---

## Điểm khác biệt: Chấm điểm gần kề tiền tố hợp lệ dài nhất

Khái niệm cốt lõi của engine rất đơn giản và được tính toán chính xác về mặt cơ học.

Mỗi kịch bản là một danh sách có thứ tự gồm N bước. Engine tìm *tiền tố liên tiếp* dài nhất của các bước đều khớp với đồ thị đồng thời, được kiểm soát bởi ba ràng buộc tại mỗi ranh giới bước:

- **Không gian** — host có trong vùng áp dụng không (ví dụ `User_Endpoint`, `Active_Directory`)? Các host không xác định tự động thất bại ở tất cả các cổng không gian.
- **Thời gian** — bước này có xảy ra trong cửa sổ thời gian quy định sau bước trước không?
- **Phạm vi liên kết** — bước này có trên cùng host (`same_host`), host khác (`cross_host`), hay cả hai (`any`)?

```
proximity = round(matched_prefix_length / total_steps, 4)
```

Nếu bước 3 thất bại ở bất kỳ cổng nào, bước 4 và 5 không đóng góp — chuỗi tấn công phải tiến triển theo thứ tự. Xếp hạng: `(-proximity, -severity_rank, -latest_timestamp)`.

Không có lần đọc đồng hồ thực, không có số ngẫu nhiên, và không có LLM nào trong đường chấm điểm. Kết quả là xác định luận: chạy cùng nhật ký qua cùng kịch bản và bạn luôn nhận được cùng câu trả lời, có thể kiểm tra từng bước.

---

## Bản đồ nền tảng

Augur được tổ chức thành các hệ thống con tập trung, có thể kiểm tra độc lập:

| Hệ thống con | Đường dẫn | Trách nhiệm |
|--------------|-----------|-------------|
| **Ingest** | `ingest/` | `read_jsonl(path)` — trình đọc JSONL theo từng dòng; ném `IngestError` kèm số dòng khi phân tích thất bại |
| **Normalize** | `normalize/` | Registry bộ chuẩn hóa đa OS được khóa theo `source_type`: `windows_sysmon` (event ID 1/7/"edr"), `linux_auditd` (EXECVE/SYSCALL/EDR), `macos_esf` (ES_EVENT_NOTIFY_EXEC/MMAP). `source_type` vắng mặt thì dùng đường Windows kế thừa. Tất cả các đường ánh xạ tới một `NormalizedEvent` chính tắc (các loại: `process_create`, `image_load`, `behavior`). `ecs.py` là shim tương thích ngược. |
| **Graph** | `graph/` | ABC `GraphBackend` với hai triển khai: `NetworkXBackend` (mặc định, không cần hạ tầng) và `Neo4jBackend` (tùy chọn). Các nút có kiểu: `HostNode`, `ProcessNode`, `FileNode`. Các loại cạnh: `SPAWNED`, `LOADED`, `EXHIBITED`, `RUNS_ON`. `build_graph(events, topology, backend)`. |
| **Topology** | `topology/` | `load_topology()` + `Topology.enrich(host) -> (Zone, Criticality)`. Nguồn xác thực cho vùng và mức độ tới hạn — các trường vùng do sự kiện cung cấp bị bỏ qua. Host không xác định → `(Zone.Unknown, Criticality.UNKNOWN)` → thất bại ở tất cả cổng không gian. |
| **Scenarios** | `scenarios/` | Lược đồ Pydantic (`extra=forbid`): `Scenario`, `Step`, `TemporalLink`, `SpatialConstraints`. Trường `os_family` tùy chọn (mặc định `windows`). `load_scenarios(dir)` tải đệ quy + xác nhận tất cả YAML với tính năng bảo vệ ID trùng lặp. |
| **Engine** | `engine/` | `criteria.py` (toán tử khớp), `matcher.py` (DFS tiền tố hợp lệ dài nhất, xác định luận), `scoring.py` (`Detection`, `build_detection` — làm giàu cộng thêm mỗi bước còn thiếu với tiêu chí + cửa sổ thời gian của nó để săn lùng bước kế tiếp, `rank`), `diagnose.py` (gần-trật có thể giải thích: *tại sao* một lần phát hiện một phần bị dừng — cổng mà bước kế tiếp đã thất bại cùng với delta cụ thể; chỉ đọc, tái sử dụng các hàm trợ giúp cổng của matcher, không bao giờ chạm vào chấm điểm), `runner.py` (`run_engine(backend, scenarios, min_proximity)`). |
| **Connectors** | `connectors/` | Giao thức `Source`/`Sink` + `run_hunt`. Nguồn: Jsonl, Directory, Stdin, Http. Bộ nhận: Stdout, JsonlFile, Webhook, Slack, Jira, CortexXsoar. |
| **Auth** | `auth/` | Cookie phiên phía máy chủ (`fs_session`, HttpOnly/SameSite=Strict, Secure trong môi trường sản xuất), băm mật khẩu argon2id, lưu trữ SQLite (users/sessions/auth_events), RBAC viewer < analyst < admin, double-submit CSRF, giới hạn tốc độ/khóa trong tiến trình, đóng lỗi `AUGUR_SECRET_KEY` trong sản xuất, khởi động admin qua env/CLI không có mật khẩu mặc định. |
| **Generative** | `generative/` | Tùy chọn `[ai]` thêm vào. Một LLM (`claude-opus-4-8`) đề xuất các kịch bản đột biến ứng viên; một bộ kiểm tra xác định luận (schema → dedup → FP-guard kiểm tra kích hoạt trên dữ liệu lành tính → kiểm tra khả năng phát hiện) cộng với cổng phê duyệt con người trước khi bất kỳ thứ gì vào thư viện. CLI: `augur.generate`. |
| **Alerting** | `alerting/` | Vòng đời cảnh báo trạng thái: dedup theo `(scenario_id + hosts)`, các band WATCH/HIGH/CONFIRMED (0.6/0.8/1.0), thông báo một lần mỗi lần vượt band qua Sinks, màn hình nền tự động (được kiểm soát bởi env `AUGUR_MONITOR_ENABLED`). Quy trình phân loại SOC đầy đủ: người được giao + trạng thái (open → ack → in_progress → resolved → closed), `/assign` `/status` `/comment`, bộ lọc thời gian, thẻ tóm tắt, chip SLA, thao tác hàng loạt. API + UI hộp thư SOC. |
| **Response** | `response/` | Response Playbooks: một runbook chuẩn dẫn xuất theo chiến thuật contain/eradicate/recover/validate cho mỗi lần phát hiện (`playbook.py`), cộng với điều phối một-cú-nhấp qua các Sink connector. **Xem trước** không cần hạ tầng theo mặc định; điều phối Slack/Jira thực chỉ qua cấu hình sink cảnh báo được lưu trữ. |
| **Simulator** | `simulator/` | Bộ tạo nhật ký đa OS xác định luận: hồ sơ và bộ phát per-OS (nghịch đảo của các bộ chuẩn hóa), đường cơ sở lành tính có hạt giống, tiêm tấn công qua `synth`, CLI `--batch`/`--stream`, nạp thư mục cho màn hình. `realism.py` cung cấp các dòng lệnh chính xác theo kỹ thuật và đường dẫn nhị phân thực. |
| **Metrics** | `metrics/` | Bộ kiểm định: độ phủ MITRE, tỷ lệ dương tính giả, khả năng phát hiện theo kịch bản, và `robustness.py` (đột biến các dấu vết tổng hợp để chứng minh các cổng thời gian/không gian/liên kết của engine TỪ CHỐI đúng cách — ranh giới âm tính giả, không chỉ là việc phát hiện kích hoạt). `coverage.py` `coverage_gap_matrix` — lưới chiến thuật×OS về nơi thư viện KHÔNG có độ phủ cho các họ OS được triển khai (độ phủ cloud-stub gộp vào windows/linux). CLI: `augur.metrics` — `--fail-on-robustness [--all-steps]` là một cổng CI. Khả năng phát hiện 40/40, độ bền vững 100%. |
| **API** | `api/` | Backend REST FastAPI. Tất cả các tuyến dữ liệu được kiểm soát RBAC. Lớp nhà-phân-tích-SOC chỉ đọc: `momentum.py` (đà gần kề — chuỗi tăng/đứng/giảm trung thực từ việc chạy engine trên cùng corpus tại các giới hạn thời gian tăng dần; không có lịch sử bịa đặt, không lưu trữ), `host_risk.py` (Bảng Rủi ro Host — các host được xếp hạng theo Σ(proximity × criticality × severity)), `navigator.py` (xuất lớp JSON ATT&CK Navigator v4.5), `drill.py` (Diễn tập Đội Tím — chạy kịch bản được trình giả lập tiêm vào một cách xác định luận, hạt giống cố định + thời gian gốc). **Vòng lặp ứng phó sự cố (IR):** `incidents.py` (gom cụm các lần phát hiện tương quan thành sự cố), `incident_response.py` (runbook contain/eradicate/recover/validate hợp nhất theo từng sự cố), `incident_report.py` (báo cáo hậu sự cố với xuất markdown). **Detection Health:** `detection_health.py` (độ sống theo kịch bản — đang kích hoạt / một phần / im lặng / chưa bao giờ trên corpus). **Lớp phủ threat-intel:** `ioc.py` + `ioc_extract.py` (khớp một watchlist CTI — process/image/command/technique + hash/domain/ip/CIDR/IPv6 — hoặc các IOC khớp được trích xuất từ báo cáo dán vào (hash/domain/ip/IPv6), trên telemetry tổng hợp Windows/Linux/macOS). Tất cả đều xây trên engine chỉ đọc; đường chấm điểm không thay đổi. |
| **Frontend** | `frontend/` | React 19 + Vite + TypeScript + Tailwind + zustand + react-router v7 + i18next (en/vi). Bảng điều khiển SOC tối — có thể cài đặt PWA, đáp ứng hoàn toàn (ngăn kéo hamburger). |
| **Pipeline** | `pipeline.py` | Lớp nối dây `build_backend()` / `_select_backend()`. |

Các CLI cấp cao nhất: `augur.demo` (chạy engine / phục vụ dashboard), `augur.hunt`, `augur.generate`, `augur.useradmin`, `augur.maintenance` (cắt xén lưu giữ lưu trữ).

---

## Thư viện kịch bản

Thư viện chứa **40 kịch bản** với ID có tiền tố OS:

| Tiền tố | Hệ điều hành | Số lượng |
|---------|-------------|---------|
| `SCEN-WIN-*` | Windows (Sysmon) | 19 |
| `SCEN-LNX-*` | Linux (auditd) | 13 |
| `SCEN-MAC-*` | macOS (ESF) | 8 |
| `SCEN-CLD-*` | Cloud-stub (được gắn thẻ với OS của host) | đã tính ở trên |

Tất cả **14 chiến thuật ATT&CK** đều được bao phủ trong 14 thư mục con danh mục (`reconnaissance`, `resource_development`, `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`).

Mỗi kịch bản được neo vào một kỹ thuật MITRE thực, mang ít nhất một `mitre_mapping` và một truy vấn săn lùng KQL/Sigma, và được viết để thân thiện với synth — nghĩa là trình giả lập PoC có thể thực hiện nó từ đầu đến cuối.

Các neo chính tắc:

| ID | Kịch bản |
|----|----------|
| `SCEN-WIN-001` | LSASS comsvcs MiniDump (đánh cắp thông tin xác thực) |
| `SCEN-LNX-001` | Backdoor cron (tồn tại dai dẳng) |
| `SCEN-MAC-001` | Stager osascript (thực thi) |
| `SCEN-CLD-001` | Đánh cắp khóa AWS (cloud-stub, truy cập thông tin xác thực) |

Thêm kịch bản mới chỉ yêu cầu một tệp YAML trong thư mục danh mục thích hợp — không cần thay đổi mã. Trình tải khám phá tất cả các tệp `*.yaml` đệ quy. Xem [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) để biết tài liệu tham khảo lược đồ đầy đủ.

---

## Dữ liệu mẫu

Tất cả dữ liệu mẫu đều có thể tái tạo qua `python -m scripts.regen_sample_data`.

**Dữ liệu cơ sở dương tính thực theo kịch bản** (`sample_data/<tactic>/<id>_tp.jsonl`): một tệp mỗi kịch bản (tổng cộng 40), các dấu vết dương tính native-OS kích hoạt ở mức gần kề 1.0 với các giá trị thực tế.

**Dữ liệu cơ sở chấp nhận** (`sample_data/acceptance/`, tên tự giải thích):

| Tệp | Mục đích |
|-----|----------|
| `full_detection.jsonl` | Dấu vết tấn công hoàn chỉnh → gần kề 100% |
| `partial_detection.jsonl` | 3 trong 5 bước đầu → gần kề 60% |
| `no_detection_benign.jsonl` | Hoạt động văn phòng bình thường → không phát hiện (bảo vệ FP) |
| `no_detection_temporal_gap.jsonl` | Bước cuối ngoài cửa sổ thời gian → chuỗi dừng ở 80% |
| `no_detection_wrong_zone.jsonl` | Cùng cuộc tấn công trên host sai vùng → bị triệt tiêu hoàn toàn |
| `demo_multi_os.jsonl` | Hỗn hợp đa OS thực tế: một cuộc tấn công đầy đủ + ransomware một phần + nhiễu lành tính |

**Corpus doanh nghiệp** (`sample_data/corpus/enterprise_day.jsonl`): khoảng 9.616 sự kiện trên 6 host (đa OS), với 5 cuộc tấn công được cài vào được khai báo trong `corpus/manifest.json`. Được sử dụng bởi `make demo` để cung cấp cho bảng điều khiển SOC một nguồn dữ liệu trông thực tế.

---

## REST API

Tất cả các tuyến dữ liệu đều được kiểm soát RBAC. Tài liệu tham khảo đầy đủ có trong [API.md](API.md).

| Danh mục | Endpoint |
|----------|----------|
| Sức khỏe | `GET /api/health` |
| Dữ liệu | `GET /api/detections`, `/api/scenarios`, `/api/topology`, `/api/metrics` |
| Lớp phân tích | `GET /api/momentum`, `/api/host_risk`, `/api/coverage_gaps`, `/api/navigator_layer`, `/api/detection_health` |
| Sự cố | `GET /api/incidents`, `/api/incident_response`, `/api/incident_report/{id}` (`?format=markdown`) |
| Threat intel | `POST /api/ioc_match`, `/api/ioc_extract` |
| Diễn tập | `POST /api/drill` |
| Response | `GET /api/playbook`, `POST /api/dispatch` |
| Xác thực | `POST /api/auth/login`, `logout`, `me`, `change-password`, `sessions` |
| Người dùng | `GET/POST/PATCH/DELETE /api/users…` |
| Generative | `POST /api/generate`, `GET/POST/DELETE /api/candidates…` |
| Alerting | `GET /api/alerts`, `/api/alerts/summary`, `/api/alerts/{id}`, `POST /api/alerts/{id}/ack`, phân loại `/assign` `/status` `/comment`, `GET/PUT /api/alerts/config`, `POST /api/alerts/scan` |

Bảo vệ CSRF được áp dụng cho tất cả các endpoint có thay đổi dữ liệu. React SPA được phục vụ từ `frontend/dist` với định tuyến dự phòng SPA.

---

## Frontend (Bảng điều khiển SOC React)

Frontend là bảng điều khiển SOC tối được xây dựng với React 19, Vite, TypeScript, Tailwind CSS, zustand để quản lý trạng thái, react-router v7, và i18next với bản địa hóa tiếng Anh và tiếng Việt. Bảng điều khiển **có thể cài đặt PWA** và **đáp ứng hoàn toàn** (ngăn kéo hamburger trên màn hình nhỏ).

Các trang: Dashboard, Scenarios, Topology, Host Risk, Coverage Gaps, Detection Health, Incidents, Intel, Drill, Generated, Alerts, Users, Sessions, Account, Audit.

- **Dashboard** — thẻ phát hiện được xếp hạng với thanh gần kề, phân tích từng bước, và các truy vấn KQL/Sigma
- **Scenarios** — duyệt thư viện kịch bản đầy đủ
- **Topology** — trực quan hóa bản đồ vùng mạng
- **Host Risk** — Bảng Rủi ro Host: các host được xếp hạng theo Σ(proximity × criticality × severity)
- **Coverage Gaps** — Ma trận Lỗ hổng Độ phủ: lưới chiến thuật×OS về nơi thư viện không có độ phủ cho các họ OS được triển khai (không có cột Cloud — cloud-stub gộp vào Windows/Linux)
- **Detection Health** — bảng độ sống theo kịch bản: kịch bản nào đang kích hoạt, một phần, im lặng, hay chưa bao giờ trên corpus
- **Incidents** — vòng lặp IR của SOC: các lần phát hiện tương quan được gom cụm thành sự cố, mỗi sự cố kèm runbook ứng phó hợp nhất và báo cáo hậu sự cố (xuất markdown)
- **Intel** — lớp phủ threat-intel: một watchlist CTI (process/image/command/technique + hash/domain/ip/CIDR/IPv6) hoặc các IOC khớp được trích xuất từ báo cáo dán vào (hash/domain/ip/IPv6) → khớp trên telemetry tổng hợp Windows/Linux/macOS (trung thực theo cấu trúc — chỉ dùng địa chỉ thuộc dải tài liệu)
- **Drill** — Diễn tập Đội Tím: chọn một kịch bản + host → trình giả lập xác định luận tiêm nó vào một nguồn lành tính → engine chỉ đọc chạy → lần phát hiện hiện ra (huấn luyện / chứng minh độ phủ)
- **Generated** — xem xét và phê duyệt/từ chối các kịch bản ứng viên do LLM tạo ra
- **Alerts** — hộp thư SOC với thông báo badge + toast và quy trình phân loại đầy đủ: người được giao + trạng thái (open → ack → in_progress → resolved → closed), bình luận, bộ lọc thời gian, thẻ tóm tắt, chip SLA, thao tác hàng loạt
- **Users / Sessions** — quản lý dành cho admin
- **Account / Audit** — cài đặt cá nhân và nhật ký sự kiện xác thực

**DetectionCard** dùng chung giờ cũng hiển thị hướng dẫn bước kế tiếp, chẩn đoán gần-trật "tại sao nó bị dừng", một sparkline đà gần kề, một bảng response-playbook, và một thao tác "Export ATT&CK Layer".

Bản dựng frontend tách biệt với gói Python. `make demo` phục vụ `frontend/dist` đã được dựng sẵn. Để phát triển UI, chạy `pnpm dev` trong `frontend/`.

---

## Khởi động nhanh

### Yêu cầu tiên quyết

- **Python 3.14+** và **[uv](https://docs.astral.sh/uv/)** — trình quản lý môi trường của dự án.

```bash
# Cài đặt uv (macOS / Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Không bao giờ dùng `pip` trần hoặc `python -m venv`** — dự án được quản lý độc quyền với `uv`.

### Cài đặt

```bash
git clone <repo-url> augur
cd augur
make install     # uv sync — tạo venv, cài đặt dự án + dev deps
make ui-build    # pnpm i && pnpm build — biên dịch console React vào frontend/dist
```

> `frontend/dist` nằm trong .gitignore, nên cần chạy `make ui-build` **một lần** (và sau mỗi thay đổi
> giao diện) trước khi console được phục vụ. Không có nó, API vẫn chạy nhưng chỉ phục vụ trang dự phòng
> tối giản. Yêu cầu: **[pnpm](https://pnpm.io/)** (Node ≥ 20).

### Chạy

**Một tiến trình — API + console trên cùng một cổng** (cách demo thường dùng):

```bash
make ui-build    # một lần — biên dịch console (bỏ qua nếu đã build)
make demo
# → http://127.0.0.1:8000  (đăng nhập admin / dev-password-123)
```

`make demo` khởi tạo đăng nhập `admin` / `dev-password-123` trên DB mới; ghi đè bằng
`make demo AUGUR_ADMIN_PASSWORD=…` (mật khẩu ≥ 12 ký tự, không chứa tên người dùng).

**Frontend tải lại nóng** (phát triển giao diện) — `make dev` chạy API (`:8000`) và Vite dev server
(`:5173`) cùng lúc; không cần `make ui-build`:

```bash
make dev
# → http://localhost:5173   (tải lại nóng; Ctrl-C dừng cả hai)
```

**Không giao diện / các điểm vào khác** (không UI, không đăng nhập):

```bash
make test        # ~1164 passed, 3 bỏ qua (Neo4j + AI tùy chọn)
make engine      # chạy engine không giao diện → in phát hiện được xếp hạng, thoát
```

Các lệnh tương đương trực tiếp (không dùng make):

```bash
uv run pytest -q
uv run python -m augur.demo --no-serve
uv run python -m augur.demo --logs sample_data/acceptance/demo_multi_os.jsonl --min-proximity 0.20
uv run python -m augur.demo --logs sample_data/corpus/enterprise_day.jsonl
```

### Stack Docker đầy đủ (tùy chọn)

```bash
make up     # docker compose up -d --build — ứng dụng FastAPI + Neo4j 5.26
make down   # docker compose down (named volumes vẫn tồn tại)
make logs   # theo dõi nhật ký container ứng dụng
```

Stack compose chạy hai dịch vụ trên mạng bridge `augur` chuyên dụng:

- **app** (http://localhost:8000) — FastAPI + bảng điều khiển React, Python 3.14, `AUGUR_BACKEND=neo4j`, chờ Neo4j khỏe mạnh.
- **neo4j** (http://localhost:7474 browser, bolt 7687) — Neo4j 5.26, named volumes `neo4j_data`/`neo4j_logs`, thông tin xác thực `neo4j`/`augur`.

`make test`, `make engine`, và `make demo` **không bao giờ yêu cầu Docker hoặc Neo4j** — chúng dùng backend NetworkX trong bộ nhớ.

---

## Ví dụ minh họa: Một lần phát hiện từ đầu đến cuối

Chạy `make engine` với `sample_data/acceptance/demo_multi_os.jsonl` cho ra:

```
========================================================================
Augur — 2 scenario(s) matched (min_proximity=0.3)
========================================================================
[CRITICAL ] Credential Theft via LSASS comsvcs MiniDump
           SCEN-WIN-001 — 5/5 steps — 100% — hosts: HR_User_PC
[CRITICAL ] Ransomware Staging via Shadow Copy Deletion and Mass File Rename
           SCEN-WIN-009 — 3/4 steps — 75% — hosts: File_Server_01
           missing: Ransom_Note_Drop
========================================================================
```

Điều gì đã xảy ra:

1. **SCEN-WIN-001** — tất cả 5 bước (thực thi dropper → tải DLL → truy cập LSASS → dàn dựng thông tin xác thực → exfil) khớp trên `HR_User_PC` (vùng: `User_Endpoint`) trong các cửa sổ thời gian của chúng. Gần kề = 100%. Kịch bản kích hoạt đầy đủ đã được xác nhận.

2. **SCEN-WIN-009** — 3 trong 4 bước khớp trên `File_Server_01` (vùng: `Internal_Server`); bước `Ransom_Note_Drop` không được quan sát. Gần kề = 75%. Kẻ tấn công đã bắt đầu chuỗi ransomware nhưng chưa thả ghi chú đòi tiền chuộc — cảnh báo sớm trong khi vẫn còn thời gian để phản ứng.

3. `Finance_User_PC` cho thấy hoạt động bình thường (Chrome, Notepad, DLL đã ký). **Không phát hiện** cho host đó — engine không kích hoạt trên nhiễu loạn.

Dashboard tại `http://127.0.0.1:8000` hiển thị mỗi lần phát hiện dưới dạng thẻ với thanh tiến trình gần kề, phân tích từng bước (xanh lá = đã khớp, xám = thiếu, mỗi bước hiển thị host + timestamp + bằng chứng đã khớp), và các truy vấn săn lùng KQL/Sigma có thể sao chép. Thanh trượt min-proximity có thể được hạ thấp để phát hiện các tín hiệu yếu hơn ở giai đoạn sớm hơn.

---

## Kiến trúc Pipeline

Một chiều, mỗi giai đoạn đứng sau một giao diện rõ ràng:

```
Nhật ký JSONL
    │
    ▼  ingest/jsonl.py          read_jsonl() → list[dict]
    │
    ▼  normalize/<os>.py        normalize_events() → list[NormalizedEvent]
    │                           (đa OS: windows_sysmon / linux_auditd / macos_esf)
    │
    ▼  graph/builder.py         build_graph() → GraphBackend
    │                           ◀── topology.enrich(host) → (Zone, Criticality)
    │
    ▼  engine/matcher.py        match_scenario() → (matched_len, chain)
    │                           [cổng không gian + thời gian + phạm vi liên kết]
    │
    ▼  engine/scoring.py        build_detection() → Detection → rank()
    │
    ▼  api/app.py               FastAPI /api/detections + React SPA
```

Lớp đồ thị được trừu tượng hóa đằng sau `GraphBackend` (ABC trong `graph/interface.py`):

| Backend | Module | Khi nào sử dụng |
|---------|--------|----------------|
| **NetworkXBackend** | `graph/networkx_backend.py` | Mặc định — không cần dep ngoài, tất cả unit tests |
| **Neo4jBackend** | `graph/neo4j_backend.py` | Tùy chọn qua `AUGUR_BACKEND=neo4j` |

Khớp kịch bản, chấm điểm, và đầu ra API giống hệt nhau bất kể backend. Chỉ có lớp lưu trữ đồ thị thay đổi.

---

## Bố cục dự án

| Đường dẫn | Trách nhiệm |
|-----------|-------------|
| `pyproject.toml` | Siêu dữ liệu gói, deps, extras tùy chọn (`neo4j`, `ai`), cấu hình pytest |
| `Makefile` | `install`, `test`, `engine`, `demo`, `up`, `down`, `logs`, `clean`, `neo4j-local` |
| `Dockerfile` | Image ứng dụng (Python 3.14, uv, extra `neo4j`) |
| `docker-compose.yml` | Stack đầy đủ app + Neo4j 5.26 với named volumes bền vững |
| `src/augur/enums.py` | `Severity`, `Criticality`, `Zone`, `LinkScope`, `SEVERITY_RANK` |
| `src/augur/topology/` | `load_topology()`, `Topology.enrich()`, `standard_topology.yaml` |
| `src/augur/scenarios/schema.py` | Mô hình đối tượng kịch bản Pydantic (`extra=forbid` xuyên suốt) |
| `src/augur/scenarios/loader.py` | `load_scenarios()` — trình tải YAML đệ quy với bảo vệ ID trùng lặp |
| `scenarios/<tactic>/*.yaml` | 40 định nghĩa kịch bản trong 14 thư mục con chiến thuật ATT&CK |
| `src/augur/ingest/jsonl.py` | `read_jsonl()`, `IngestError` |
| `src/augur/normalize/` | Registry bộ chuẩn hóa đa OS: `windows_sysmon`, `linux_auditd`, `macos_esf`, shim `ecs.py` |
| `src/augur/graph/` | ABC `GraphBackend`, `NetworkXBackend`, `Neo4jBackend`, `builder.py`, mô hình nút/cạnh |
| `src/augur/engine/` | `criteria.py`, `matcher.py`, `scoring.py`, `diagnose.py`, `runner.py` |
| `src/augur/connectors/` | Giao thức `Source`/`Sink`, `sources.py`, `sinks.py`, `runner.py` |
| `src/augur/auth/` | argon2id, sessions, RBAC, CSRF, rate-limit, `router.py`, `users_router.py`, `store.py` |
| `src/augur/generative/` | Tạo ứng viên LLM, bộ kiểm tra guardrail, `router.py`, `eval.py`, `synth.py` |
| `src/augur/alerting/` | Vòng đời cảnh báo trạng thái + quy trình phân loại, bands, `monitor.py`, `notify.py`, `router.py`, `store.py` |
| `src/augur/response/` | Response Playbooks: `playbook.py` (runbook dẫn xuất theo chiến thuật), điều phối qua Sink connector (mặc định xem trước) |
| `src/augur/simulator/` | Bộ tạo nhật ký đa OS, `profiles.py`, `emitters.py`, `realism.py`, `inject.py` |
| `src/augur/metrics/` | Độ phủ MITRE, tỷ lệ FP, khả năng phát hiện, `robustness.py` (đột biến từ-chối-cổng), `coverage.py` (`coverage_gap_matrix`), `report.py` |
| `src/augur/api/app.py` | Ứng dụng FastAPI, nối dây tuyến, dự phòng SPA; tuyến phân tích `momentum.py`, `host_risk.py`, `navigator.py`, `drill.py`, `detection_health.py`, `incidents.py`, `incident_response.py`, `incident_report.py`, `ioc.py`, `ioc_extract.py` |
| `src/augur/pipeline.py` | `build_backend()`, `_select_backend()` |
| `src/augur/demo.py` | CLI `main()`: `--logs`, `--min-proximity`, `--no-serve`, `--port` |
| `frontend/` | React 19 + Vite + TS + Tailwind + zustand + react-router v7 + i18next |
| `sample_data/` | Dữ liệu TP theo kịch bản (40), dữ liệu chấp nhận (6), corpus (9.616 sự kiện) |
| `tests/` | ~1164 passed, 3 skipped (kiểm thử tích hợp Neo4j + AI tùy chọn) |
| `docs/en/` | Bộ tài liệu này |

---

## Quy tắc chấm điểm

```
proximity = round(matched_prefix_length / total_steps, 4)
```

- Chỉ có **tiền tố liên tiếp** được tính. Bước 3 thất bại sẽ triệt tiêu hoàn toàn bước 4 và 5.
- Ngưỡng báo cáo mặc định: **0.30** (có thể cấu hình: `--min-proximity 0.10` trên CLI, `?min_proximity=0.10` trên API).
- Xếp hạng: **proximity giảm dần** → **severity giảm dần** (CRITICAL > HIGH > MEDIUM > LOW) → **sự kiện khớp mới nhất trước**.

Xem [ENGINE.md](ENGINE.md) để biết mô tả thuật toán đầy đủ, ví dụ minh họa, và đảm bảo tính xác định luận.

---

## Kiểm thử

```bash
make test                                          # ~1164 passed, 3 skipped
uv run pytest -q                                   # tương tự
uv run pytest -v tests/test_acceptance.py          # chỉ kiểm thử chấp nhận
uv run pytest tests/test_scenario_library.py       # xác nhận tất cả 40 tệp YAML kịch bản
uv run pytest tests/test_enterprise_corpus.py      # corpus 9.616 sự kiện, 5 cuộc tấn công được cài
AUGUR_NEO4J_TEST=1 uv run pytest tests/test_neo4j_backend.py  # tích hợp Neo4j (yêu cầu Neo4j đang chạy)
```

Các khẳng định chấp nhận chính:

| Kiểm thử | Khẳng định |
|----------|-----------|
| `test_true_positive` | `full_detection.jsonl` → SCEN-WIN-001 proximity == 1.0 trên HR_User_PC |
| `test_partial_proximity` | `partial_detection.jsonl` → SCEN-WIN-001 proximity == 0.6 (3/5 bước) |
| `test_benign_no_detection` | `no_detection_benign.jsonl` → không phát hiện ≥ 0.30 |
| `test_temporal_gate` | `no_detection_temporal_gap.jsonl` → chuỗi dừng, bước 5 bị triệt tiêu |
| `test_spatial_gate` | `no_detection_wrong_zone.jsonl` → phát hiện bị triệt tiêu hoàn toàn |
| `test_multi_os_demo` | `demo_multi_os.jsonl` → SCEN-WIN-001 ở 1.0, SCEN-WIN-009 ở 0.75 |

Các kiểm thử TP theo kịch bản (`tests/test_scenario_tp_fixtures.py`) khẳng định rằng mỗi một trong số 40 dữ liệu cơ sở `<id>_tp.jsonl` kích hoạt kịch bản của nó ở mức gần kề chính xác là 1.0.

---

## Những lưu ý thành thật

Những điều này được nêu rõ ràng ở đây thay vì ẩn trong các chú thích:

- **Khả năng phát hiện = 100% một phần là do cấu trúc.** Các kịch bản được viết để thân thiện với synth để công cụ PoC có thể thực hiện chúng. Đây không phải là tuyên bố về 100% recall trong thế giới thực đối với nhật ký đối thủ mà bạn không tạo ra.
- **Tỷ lệ FP = 0.0 được đo trên corpus do trình giả lập tạo ra.** Corpus lành tính sạch theo cấu trúc. Kiểm định thực địa trên dữ liệu EDR sản xuất chưa được thực hiện.
- **Các kịch bản cloud-stub xấp xỉ hoạt động cloud qua telemetry endpoint.** Các bộ chuẩn hóa CloudTrail, M365, hoặc mạng thực sự là một dự án tương lai. Các kịch bản `SCEN-CLD-*` kích hoạt dựa trên các sự kiện cấp host tương quan với hành vi nhắm mục tiêu cloud, không phải nhật ký API cloud native.
- **Trình giả lập và dữ liệu mẫu là các đại diện PoC** cho nhật ký máy thực, không thay thế việc tích hợp Augur với SIEM hoặc EDR sản xuất.

---

## Lớp Generative (tùy chọn)

Augur bao gồm một hệ thống con tạo kịch bản hỗ trợ AI tùy chọn (`augur.generate`, yêu cầu `uv sync --extra ai`). Nó sử dụng một LLM (`claude-opus-4-8`) để đề xuất các kịch bản đột biến ứng viên dưới dạng YAML hợp lệ lược đồ. Trước khi bất kỳ ứng viên nào đến được thư viện, nó phải vượt qua bộ kiểm tra guardrail xác định luận:

1. Xác nhận lược đồ (Pydantic, `extra=forbid`)
2. Kiểm tra dedup so với ID và tên kịch bản hiện có
3. Bảo vệ kích hoạt trên dữ liệu lành tính (ứng viên không được kích hoạt trên corpus lành tính)
4. Kiểm tra khả năng phát hiện (ứng viên phải kích hoạt trên dấu vết TP được tạo ra)
5. Phê duyệt con người qua quy trình `/api/candidates` và trang Generated trong bảng điều khiển React

Không có gì tự động vào thư viện. Engine xác định luận sử dụng kịch bản không thay đổi — các kịch bản được tạo ra đi qua cùng trình tải, bộ khớp, và bộ chấm điểm như những kịch bản được viết tay.

---

## Biến môi trường

| Biến | Mặc định | Mô tả |
|------|---------|-------|
| `AUGUR_BACKEND` | `networkx` | `neo4j` để dùng backend Neo4j |
| `AUGUR_NEO4J_TEST` | không đặt | Đặt thành `1` để bật kiểm thử tích hợp Neo4j |
| `AUGUR_SECRET_KEY` | **bắt buộc trong sản xuất** | Khóa ký phiên; đóng lỗi (không có mặc định) |
| `AUGUR_ADMIN_USER` | không đặt | Tên người dùng admin bootstrap (env/CLI, không có mật khẩu mặc định) |
| `AUGUR_ADMIN_PASSWORD` | không đặt | Mật khẩu admin bootstrap |
| `AUGUR_COOKIE_SECURE` | `false` | Đặt `true` đằng sau proxy TLS trong sản xuất |
| `AUGUR_MONITOR_ENABLED` | không đặt | Đặt thành `1` để khởi động màn hình cảnh báo nền tự động |
| `AUGUR_AI_MODEL` | `claude-opus-4-8` | Mô hình LLM cho hệ thống con generative (tùy chọn) |

---

## Tài liệu

| Tài liệu | Mô tả |
|----------|-------|
| [EXPLAINER.md](EXPLAINER.md) | Tour ELI5 bằng ngôn ngữ đơn giản: khung "máy dò khói cho các cuộc tấn công mạng", proximity được giải thích đơn giản, minh họa bằng ví dụ cụ thể |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Thiết kế pipeline đầy đủ, trừu tượng GraphBackend, luồng dữ liệu, các quyết định thiết kế, đường nối generative Phase 2 |
| [ENGINE.md](ENGINE.md) | Phân tích sâu thuật toán khớp, công thức chấm điểm, toán tử tiêu chí, đảm bảo tính xác định luận, ví dụ minh họa |
| [DATA_MODEL.md](DATA_MODEL.md) | Lược đồ sự kiện nhật ký, các trường NormalizedEvent, chi tiết bộ chuẩn hóa đa OS, mô hình nút/cạnh đồ thị, tô-pô |
| [API.md](API.md) | Tài liệu tham khảo endpoint REST, hình dạng yêu cầu/phản hồi, ví dụ curl, ghi chú RBAC |
| [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) | Tài liệu tham khảo lược đồ YAML đầy đủ, toán tử khớp, ngữ nghĩa `temporal_link`, danh sách kiểm tra từng bước để thêm kịch bản |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Quy trình phát triển, kỳ vọng TDD, thêm nguồn nhật ký, thêm marker hành vi, quy ước commit |
| [THREAT_MODEL.md](../en/THREAT_MODEL.md) | Mô hình mối đe dọa bảo mật cho dịch vụ Augur: xác thực, CSRF, quản lý phiên, ranh giới tin cậy |

## Chạy tập dữ liệu thật trên web console

Augur có sẵn một đường kiểm chứng dữ liệu thật, xác định (deterministic): một bản ghi Sysmon thật từ OTRF
Security-Datasets (`empire_mimikatz_logonpasswords`) được phát hiện bởi `SCEN-REAL-WIN-T1003-001` (Real LSASS
Credential Dump, T1003.001) ở độ gần 1.0 mức CRITICAL trên `WORKSTATION5.theshire.local`.

```bash
# 1. Tải + gắn thẻ tập dữ liệu OTRF thật (idempotent; vào datasets/real/ đã bị gitignore).
#    --tag chèn "source_type": "windows_sysmon_real" vào từng bản ghi để registry định tuyến đúng
#    qua bộ chuẩn hóa Sysmon thật.
uv run python scripts/fetch_real_datasets.py --tag empire_mimikatz_logonpasswords

# 2. Phục vụ console trên tập dữ liệu thật (tự tải+gắn thẻ nếu bỏ qua bước 1).
uv run python -m augur.demo --real            # tập mặc định: empire_mimikatz_logonpasswords
#   → khởi tạo admin / dev-password-123, phục vụ tại http://127.0.0.1:8000
```

Đăng nhập (`admin` / `dev-password-123`) và mở Dashboard: `SCEN-REAL-WIN-T1003-001` kích hoạt CRITICAL ở 1.0
trên `WORKSTATION5.theshire.local`, xuất hiện banner **REAL DATASET** chỉ-đọc, và ghi chú trung thực của lớp
IOC phản ánh telemetry thật (IP đích là thật, không phải dải tài liệu RFC-5737).

**Lối tắt Makefile:** `make demo-real` (chạy console trên tập dữ liệu thật) · `make dev-real` (hot-reload API + Vite :5173 trên tập dữ liệu thật).

**Wave 1 — sáu phát hiện thật bổ sung (luật command-line `process_create` EID-1):** `SCEN-REAL-WIN-T1003-003-001`
(NTDS.dit qua `ntdsutil` IFM, CRITICAL), `SCEN-REAL-WIN-T1003-002-001` (SAM qua `esentutl /vss`, HIGH),
`SCEN-REAL-WIN-T1218-005-001` (`mshta vbscript:`, HIGH), `SCEN-REAL-WIN-T1548-002-001` (UAC bypass `fodhelper` —
2 bước theo lineage powershell→fodhelper, HIGH), `SCEN-REAL-WIN-T1197-001` (BITS `bitsadmin /transfer`, MEDIUM),
`SCEN-REAL-WIN-T1053-005-001` (`schtasks /ru system`, HIGH).
Mỗi luật được kiểm chứng kích hoạt ở độ gần 1.0 trên bản ghi OTRF công khai của riêng nó và nằm trong
`scenarios_real/` (không bao giờ tự gộp vào thư viện mặc định bị synth-gate). Mỗi tệp mang một header trung thực:
**phát hiện thật trên bản ghi công khai, sạch khi demo ≠ đã tinh chỉnh cho production — cần allowlist production.**

**Wave 2 — ba phát hiện hành vi (vượt khỏi command line `process_create`).** Ánh xạ các EID Sysmon /
PowerShell mới vào kind `behavior` sẵn có của engine nên khớp **không cần đổi engine**: `SCEN-REAL-WIN-T1055-001`
(tiêm tiến trình — Sysmon EID 8 `CreateRemoteThread`, `powershell→LoadLibraryA→notepad`),
`SCEN-REAL-WIN-T1547-001` (bền vững Run-key — Sysmon EID 13 `RegistryEvent` SetValue dưới `CurrentVersion\Run`),
`SCEN-REAL-WIN-T1059-001` (PowerShell ScriptBlock độc hại — **EID 4104**, phản chiếu bypass AMSI
`System.Management.Automation.Utils`). **Ghi chú trung thực định hình Wave 2:** các bản ghi Wave-1 mang EID 8/13
chỉ ở dạng *nền lành tính* (csrss→svchost CtrlRoutine, ghi W32Time), nên Wave 2 tải **bản ghi mới** nơi kỹ thuật
là thực thể độc hại thật; test khẳng định thực thể độc hại kích hoạt **và** nền lành tính thì không. EID 4104
không mang GUID Sysmon nên hành vi neo trên một nút tổng hợp tất định theo `(host,PID)` — tín hiệu trung thực
"đã thấy script block độc hại", không phải tuyên bố cây tiến trình.

**Bộ SUITE thật (cả 10 cùng lúc):**

```bash
# Tải + gắn thẻ mọi bản ghi (idempotent), rồi phục vụ cả 10 phát hiện thật trên một Dashboard:
uv run python scripts/fetch_real_datasets.py --suite all
uv run python -m augur.demo --real all          # topology kết hợp, mọi nguồn, không hot-reload
#   kiểm chứng headless: uv run python -m augur.demo --real all --no-serve   # in cả 10 phát hiện thật
```

`make demo-real-all` là lối tắt. Suite nạp topology kết hợp đã commit `datasets/real/topology_wave1.yaml`
(siêu tập của topology theshire, khai báo thêm DC `pandalab.com` và cả hai dạng tên ngắn + FQDN của
`WORKSTATION5`). `--real all` không hot-reload (suite đa nguồn không dùng được `AUGUR_LOGS` đơn-đường-dẫn);
`make dev-real` vẫn dùng một tập dữ liệu.

Kiểm chứng không trình duyệt:

```bash
uv run python -m augur.demo --real --no-serve   # in ra phát hiện thật rồi thoát
```

**Giới hạn đã biết (v1):** endpoint quét cảnh báo thủ công và bộ giám sát nền (env-gated) vẫn mặc định dùng
kịch bản/topology tổng hợp, nên sẽ không hiển thị kịch bản thật ở chế độ `--real`. Các route phân tích trên
Dashboard (detections / host risk / timeline / pivot / IOC / rarity) là phần bàn giao của v1; việc luồng
scenarios/topology vào quét cảnh báo là một bước tiếp theo sạch sẽ.
