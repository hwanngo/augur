[English](../en/SCENARIO_FORMAT.md) | **Tiếng Việt**

# Augur — Tài Liệu Tham Khảo Định Dạng Kịch Bản

Kịch bản là các tệp YAML trong cây thư mục `scenarios/`, được nhóm theo chiến thuật MITRE ATT&CK
(ví dụ: `scenarios/credential_access/`, `scenarios/execution/`). Mỗi tệp được nạp và xác thực
nghiêm ngặt theo schema Pydantic trong `src/augur/scenarios/schema.py` (`extra="forbid"` trên mọi
model — các trường không xác định sẽ gây ra lỗi khi nạp). Một `scenario_id` trùng lặp trên bất kỳ hai tệp nào
cũng làm thất bại khi khởi động.

Tài liệu này là tài liệu tham khảo soạn thảo có thẩm quyền. Xem [ENGINE.md](ENGINE.md) để hiểu cách
engine đánh giá kịch bản, và [DATA_MODEL.md](DATA_MODEL.md) để hiểu mô hình dữ liệu bên dưới.

---

## Cấu Trúc Cấp Cao Nhất

Một YAML kịch bản hợp lệ có đúng bốn khối cấp cao nhất:

```yaml
scenario_metadata:   # định danh, severity, MITRE, OS family
  ...
spatial_constraints: # zone/asset nào mà kịch bản này áp dụng
  ...
attack_sequence_flow: # các bước phát hiện có thứ tự
  steps:
    - ...
actionable_hunting_outputs: # các truy vấn KQL/Sigma để chạy khi kịch bản kích hoạt
  validation_queries:
    - ...
```

---

## 1. `scenario_metadata`

| Trường | Kiểu | Bắt buộc | Mô tả |
|---|---|---|---|
| `scenario_id` | `str` | có | ID duy nhất; theo lược đồ tiền tố OS bên dưới |
| `name` | `str` | có | Tiêu đề ngắn dễ đọc |
| `description` | `str` | có | Kẻ tấn công đang làm gì; 1–3 câu |
| `severity` | `str` | có | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `mitre_mappings` | `list` | có (≥1) | Một hoặc nhiều cặp `{tactic, technique}` |
| `os_family` | `str` | không | `windows` (mặc định) / `linux` / `macos` |

### Lược Đồ ID Kịch Bản

ID theo mẫu `SCEN-<OS>-<NNN>` trong đó `<NNN>` là số ba chữ số có đệm số 0:

| Tiền tố | OS family | Ví dụ |
|---|---|---|
| `SCEN-WIN-` | windows | `SCEN-WIN-001` |
| `SCEN-LNX-` | linux | `SCEN-LNX-001` |
| `SCEN-MAC-` | macos | `SCEN-MAC-001` |
| `SCEN-CLD-` | cloud stub (endpoint telemetry) | `SCEN-CLD-001` |

Tất cả 40 kịch bản hiện tại đều được xác định duy nhất trong không gian tên tiền tố của chúng. Trường `os_family`
điều khiển tài liệu và công cụ; nó không được thực thi bởi bộ so khớp (vốn độc lập với đồ thị).

### Các Mục `mitre_mappings`

Mỗi mục phải có đúng `tactic` và `technique`:

```yaml
mitre_mappings:
  - tactic: "TA0006"
    technique: "T1003.001"
```

---

## 2. `spatial_constraints`

Kiểm soát các máy chủ nào trong đồ thị đủ điều kiện tham gia vào kịch bản này.

| Trường | Kiểu | Bắt buộc | Mặc định | Mô tả |
|---|---|---|---|---|
| `applicable_zones` | `list[str]` | có (≥1) | — | Các giá trị Zone đủ điều kiện; xem enum `Zone` |
| `critical_assets_only` | `bool` | không | `false` | Khi `true`, chỉ các máy chủ có `Criticality.CRITICAL` mới đủ điều kiện |
| `required_log_sources` | `list[str]` | không | `[]` | Nhãn thông tin (không được bộ so khớp đánh giá) |

Các chuỗi zone hợp lệ: `DMZ`, `Internal_Server`, `User_Endpoint`, `Cloud_SaaS`,
`Active_Directory`, `Unknown`. Zone và criticality luôn được đọc từ topology, không bao giờ từ
các sự kiện log. Một máy chủ với `Zone.Unknown` tự động thất bại tất cả các kiểm tra zone.

```yaml
spatial_constraints:
  applicable_zones: ["User_Endpoint", "Internal_Server"]
  critical_assets_only: false
  required_log_sources: ["Windows_Sysmon", "EDR_Telemetry"]
```

---

## 3. `attack_sequence_flow`

Chứa một danh sách `steps` duy nhất. Các bước phải được đánh số `1..N` liên tiếp không có khoảng trống.

### 3.1 Schema Bước

| Trường | Kiểu | Bắt buộc | Ghi chú |
|---|---|---|---|
| `step_id` | `int` | có | Phải tạo thành một chuỗi liên tiếp bắt đầu từ `1` |
| `name` | `str` | có | Nhãn ngắn cho bước phát hiện này |
| `temporal_link` | object | bước 1: bị cấm; bước 2+: bắt buộc | Liên kết bước này với bước trước |
| `matching_criteria` | `dict` | có | Phải bao gồm `Node_Type`; xem §3.3 |

**Bước 1 không được có `temporal_link`. Bước 2 trở đi phải có một.** Vi phạm bất kỳ ràng buộc nào
sẽ gây ra lỗi xác thực khi nạp.

### 3.2 `temporal_link`

Định nghĩa cửa sổ thời gian và mối quan hệ phạm vi máy chủ giữa bước này và bước trước.

| Trường | Kiểu | Bắt buộc | Mặc định | Mô tả |
|---|---|---|---|---|
| `previous_step` | `int` | có | — | Phải bằng `step_id - 1` |
| `link_scope` | `str` | không | `same_host` | `same_host` / `cross_host` / `any` |
| `min_time_delta_seconds` | `int` | không | `0` | Thời gian tối thiểu đã trôi qua kể từ bước trước |
| `max_time_delta_seconds` | `int` | có | — | Thời gian tối đa; phải ≥ `min_time_delta_seconds` |

```yaml
temporal_link:
  previous_step: 2
  link_scope: same_host
  min_time_delta_seconds: 0
  max_time_delta_seconds: 120
```

### 3.3 `matching_criteria`

Một dictionary các tiêu chí trường được áp dụng lên các nút đồ thị. Engine đánh giá chúng đối với
các thuộc tính `ProcessNode` hoặc `FileNode` tùy thuộc vào `Node_Type`.

**`Node_Type` là bắt buộc** và phải là `"Process"` hoặc `"File"`.

#### Các khóa tiêu chí nút Process

| Khóa tiêu chí | Trường `ProcessNode` | Ghi chú |
|---|---|---|
| `ProcessName` | `name` | Tên cơ sở tệp thực thi |
| `ProcessPath` | `path` | Đường dẫn đầy đủ |
| `CommandLine` | `command_line` | Chuỗi đối số đầy đủ |
| `ParentProcessName` | `parent_process_name` | Tên cơ sở của tiến trình cha |
| `IntegrityLevel` | `integrity_level` | ví dụ: `"High"` |
| `ProcessGuid` | `id` | Định danh tiến trình ổn định |

#### Các khóa tiêu chí nút File

| Khóa tiêu chí | Trường `FileNode` | Ghi chú |
|---|---|---|
| `FileName` | `name` | Tên cơ sở của tệp được nạp |
| `Path` | `path` | Đường dẫn đầy đủ |
| `Extension` | `extension` | Chữ thường, có dấu chấm (ví dụ: `".dll"`) |
| `IsSigned` | `is_signed` | Boolean |
| `IsInjected` | `is_injected` | Boolean |
| `ApiHookingDetected` | `api_hooking_detected` | Boolean |
| `SignatureVendor` | `signature_vendor` | Chuỗi danh tính ký |

#### Các khóa tiêu chí Behavior (chỉ dành cho bước behavior)

Các khóa này khớp với các thuộc tính cạnh `EXHIBITED` thay vì trực tiếp với các trường nút.

| Khóa tiêu chí | Thuộc tính cạnh | Mô tả |
|---|---|---|
| `TargetProcess` | `target` | Tên tiến trình đích, ví dụ: `"lsass.exe"` |
| `GrantedAccess` | `granted_access` | Chuỗi hex mặt nạ truy cập, ví dụ: `"0x1410"` |
| `Behavior_Markers` | `behavior` | Kiểm tra thành viên: chuỗi behavior phải xuất hiện trong danh sách đã cho |

Một bước sử dụng bất kỳ `TargetProcess`, `GrantedAccess`, hoặc `Behavior_Markers` nào được xử lý như
bước behavior. Các bước behavior vẫn yêu cầu `Node_Type: "Process"` cho nút nguồn.

### 3.4 Toán Tử So Khớp

Mỗi giá trị tiêu chí có thể là **literal** hoặc **đối tượng toán tử**:

| Dạng | Ví dụ | Ngữ nghĩa |
|---|---|---|
| Literal | `"rundll32.exe"` | Bằng nhau: `actual == value` |
| `{in: [...]}`  | `{in: ["cmd.exe", "powershell.exe"]}` | Thành viên: `actual in list` |
| `{equals: ...}` | `{equals: false}` | Bằng nhau tường minh (hữu ích cho boolean) |
| `{exists: true}` | `{exists: true}` | Kiểm tra khác null: `actual is not None` |
| `{exists: false}` | `{exists: false}` | Kiểm tra null: `actual is None` |
| `{regex: "..."}` | `{regex: ".*comsvcs.*"}` | `re.search(pattern, str(actual)) is not None` |

Các regex được biên dịch và xác thực khi nạp; một mẫu không hợp lệ sẽ gây ra lỗi ngay lập tức.
Dạng literal và `{equals: ...}` sử dụng Python `==`, vì vậy kiểu dữ liệu quan trọng (`"1"` ≠ `1`).

---

## 4. `actionable_hunting_outputs`

Chứa một danh sách `validation_queries` với ít nhất một mục. Mỗi mục là một `HuntingQuery`:

| Trường | Kiểu | Bắt buộc | Mô tả |
|---|---|---|---|
| `engine` | `str` | có | Ngôn ngữ truy vấn, ví dụ: `"KQL"`, `"Sigma"` |
| `query` | `str` | một trong `query`/`query_path` | Chuỗi truy vấn nội tuyến |
| `query_path` | `str` | một trong `query`/`query_path` | Đường dẫn đến tệp truy vấn (tương đối với gốc repo) |

Đúng một trong `query` hoặc `query_path` phải có mặt; cung cấp cả hai hoặc không cái nào đều gây ra
lỗi xác thực.

```yaml
actionable_hunting_outputs:
  validation_queries:
    - engine: "KQL"
      query: >
        DeviceProcessEvents
        | where FileName == 'rundll32.exe'
        and ProcessCommandLine has 'comsvcs'
        and ProcessCommandLine has 'MiniDump'
```

---

## 5. Các Bất Biến Schema

Các ràng buộc sau được thực thi bởi các validator Pydantic và sẽ gây ra lỗi khi nạp nếu bị vi phạm:

1. `extra="forbid"` trên mọi model — các khóa YAML không xác định bị từ chối.
2. `scenario_id` phải là duy nhất trên toàn bộ thư mục kịch bản (`load_scenarios` phát sinh lỗi khi
   phát hiện trùng lặp).
3. `step_ids` phải chính xác là `[1, 2, …, N]` không có khoảng trống và không có trùng lặp.
4. Bước 1 phải có `temporal_link: null` (hoặc bỏ qua trường).
5. Bước 2..N mỗi bước phải có một `temporal_link` với `previous_step == step_id - 1`.
6. `max_time_delta_seconds >= min_time_delta_seconds`.
7. `matching_criteria` phải chứa `Node_Type` được đặt thành `"Process"` hoặc `"File"`.
8. Mọi giá trị `{regex: ...}` phải biên dịch không có lỗi.
9. `mitre_mappings` phải có ít nhất một mục.
10. `applicable_zones` phải có ít nhất một mục.

---

## 6. Soạn Thảo Thân Thiện Với Bộ Tổng Hợp

Bộ mô phỏng kịch bản (`augur.simulator`) là **nghịch đảo của bộ chuẩn hóa**: cho một kịch bản,
nó tạo ra các fixture log JSONL thực tế kích hoạt kịch bản ở proximity 100%. Để dữ liệu mẫu được tạo
có thể kiểm tra được:

- Sử dụng các mẫu `{regex: "..."}` khớp với tên nhị phân thực tế và các mẫu đối số điển hình.
- Ưu tiên `{in: [...]}` cho các tập nhỏ tên tiến trình đã biết thay vì các ký tự đại diện rộng.
- Đặt `max_time_delta_seconds` thành một cửa sổ thực tế (60–300 giây cho hầu hết các chuỗi lateral movement).
- Sử dụng phạm vi liên kết `same_host` trừ khi kỹ thuật yêu cầu rõ ràng hoạt động cross-host (ví dụ:
  bước lateral movement từ workstation đến server).

Mỗi kịch bản trong thư viện hiện tại có một fixture `<tactic>/<id>_tp.jsonl` tương ứng trong
`sample_data/` kích hoạt ở proximity 1.0 và sử dụng các command line chính xác về mặt kỹ thuật.

---

## 7. Ví Dụ Được Chú Thích — SCEN-WIN-001

Kịch bản Windows chuẩn `scenarios/credential_access/win_lsass_comsvcs.yaml` minh họa
cả bốn khối trong một chuỗi năm bước thực tế:

```yaml
scenario_metadata:
  scenario_id: "SCEN-WIN-001"
  name: "LSASS Credential Dump via comsvcs.dll MiniDump"
  description: >
    Adversary spawns a LOLBin chain (rundll32 -> comsvcs.dll MiniDump) to dump
    LSASS memory for offline credential extraction.
  severity: "CRITICAL"
  mitre_mappings:
    - { tactic: "TA0006", technique: "T1003.001" }
  os_family: "windows"

spatial_constraints:
  applicable_zones: ["User_Endpoint", "Internal_Server"]
  critical_assets_only: false
  required_log_sources: ["Windows_Sysmon", "EDR_Telemetry"]

attack_sequence_flow:
  steps:
    # Bước 1 — không có temporal_link (đây là điểm neo)
    - step_id: 1
      name: "Rundll32_Launch"
      matching_criteria:
        Node_Type: "Process"
        ProcessName: { in: ["rundll32.exe"] }    # toán tử thành viên
        CommandLine: { regex: ".*comsvcs.*" }     # toán tử regex

    # Bước 2 — same_host, trong vòng 60 giây kể từ bước 1
    - step_id: 2
      name: "MiniDump_CommandLine"
      temporal_link:
        previous_step: 1
        link_scope: same_host
        min_time_delta_seconds: 0
        max_time_delta_seconds: 60
      matching_criteria:
        Node_Type: "Process"
        ProcessName: { in: ["rundll32.exe"] }
        CommandLine: { regex: ".*MiniDump.*" }

    # Bước 3 — bước behavior; khớp với các thuộc tính cạnh EXHIBITED
    - step_id: 3
      name: "LSASS_Access_Behavior"
      temporal_link:
        previous_step: 2
        link_scope: same_host
        min_time_delta_seconds: 0
        max_time_delta_seconds: 120
      matching_criteria:
        Node_Type: "Process"
        TargetProcess: "lsass.exe"     # bằng nhau literal trên edge.target
        GrantedAccess: "0x1410"        # bằng nhau literal trên edge.granted_access

actionable_hunting_outputs:
  validation_queries:
    - engine: "KQL"
      query: >
        DeviceProcessEvents
        | where FileName == 'rundll32.exe'
        and ProcessCommandLine has 'comsvcs'
        and ProcessCommandLine has 'MiniDump'
```

Khi kịch bản này kích hoạt ở proximity 100%, phản hồi `/api/detections` sẽ hiển thị:
- `proximity: 1.0`
- `matched_steps: 3`
- `total_steps: 3`
- `affected_hosts: ["HR_User_PC"]` (hoặc bất kỳ máy chủ nào có các sự kiện)

---

## 8. Thêm Kịch Bản Mới — Danh Sách Kiểm Tra

1. Chọn thư mục tactic phù hợp trong `scenarios/` (tạo nó nếu chưa tồn tại).
2. Sử dụng ID duy nhất theo định dạng `SCEN-WIN/LNX/MAC/CLD-NNN`; xác minh không có kịch bản hiện có nào sử dụng nó.
3. Đặt `os_family` khớp với bộ chuẩn hóa sẽ tạo ra các sự kiện.
4. Viết `matching_criteria` mô tả chính xác các tạo phẩm có thể quan sát được — kiểm tra với các
   toán tử regex đối với tên tiến trình thực tế và chuỗi đối số.
5. Đặt các cửa sổ `temporal_link` đủ rộng để bao gồm jitter trong thực tế nhưng không quá rộng
   đến mức các sự kiện lành mạnh không liên quan có thể vô tình thỏa mãn bước.
6. Bao gồm ít nhất một `mitre_mapping` và một `validation_query`.
7. Chạy `uv run pytest tests/test_scenario_library.py` — bộ nạp sẽ xác thực tất cả các tệp YAML
   và đánh dấu các lỗi schema ngay lập tức.
8. Thêm fixture `sample_data/<tactic>/<id>_tp.jsonl` và bao gồm nó trong
   `tests/test_scenario_tp_fixtures.py` nếu kịch bản là load-bearing.

---

## Xem Thêm

- [DATA_MODEL.md](DATA_MODEL.md) — các trường NormalizedEvent và các thuộc tính nút đồ thị
- [ENGINE.md](ENGINE.md) — cách các bước được so khớp và proximity được tính điểm
- [API.md](API.md) — các REST endpoint để liệt kê kịch bản và kích hoạt tạo sinh
- [CONTRIBUTING.md](CONTRIBUTING.md) — quy trình phát triển và quy ước kiểm thử
