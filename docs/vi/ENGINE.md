[Tiếng Anh](../en/ENGINE.md) | **Tiếng Việt**

# Augur — Tìm Hiểu Sâu về Detection Engine

Tài liệu liên quan: [ARCHITECTURE.md](ARCHITECTURE.md) | [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) | [DATA_MODEL.md](DATA_MODEL.md)

---

## Tổng Quan

Detection engine của Augur trả lời một câu hỏi cho mỗi kịch bản: *"với đồ thị tri thức hiện tại, bao nhiêu phần của chuỗi tấn công này đã hiện diện?"* Nó thực hiện điều này bằng cách tìm tiền tố liên tiếp dài nhất của các bước kịch bản có thể được thỏa mãn bởi các phần tử trong đồ thị — tuân theo các ràng buộc không gian, thời gian và quan hệ host — rồi biểu thị kết quả dưới dạng điểm `proximity` từ 0.0 đến 1.0.

Ba module triển khai engine:

| Module | Trách nhiệm |
|--------|-------------|
| `engine/criteria.py` | Các toán tử tiêu chí và các hàm vị từ node/edge |
| `engine/matcher.py` | DFS tiền tố hợp lệ dài nhất (`match_scenario`) |
| `engine/scoring.py` | Xây dựng phát hiện và xếp hạng (`build_detection`, `rank`) |

`engine/runner.py::run_engine(backend, scenarios, min_proximity)` điều khiển vòng lặp ngoài: một lời gọi `match_scenario` cho mỗi kịch bản, một lời gọi `build_detection` cho bất kỳ kết quả khớp nào khác không, rồi `rank`.

---

## Các Toán Tử Tiêu Chí — `engine/criteria.py`

### `match_value(criterion, actual)`

Mọi kiểm tra trường trong engine đều kết thúc tại `match_value`. Hàm này xử lý năm dạng:

| Dạng tiêu chí | Quy tắc khớp |
|---------------|-------------|
| Scalar đơn thuần — `"lsass.exe"`, `false`, `42` | `actual == criterion` |
| `{"regex": "<pattern>"}` | `re.search(pattern, str(actual)) is not None` — pattern được biên dịch và kiểm tra khi tải kịch bản |
| `{"equals": value}` | `actual == value` — hữu ích khi giá trị là một dict literal |
| `{"in": [v1, v2, ...]}` | `actual in [v1, v2, ...]` |
| `{"exists": true/false}` | `(actual is not None) == bool(exists)` — kiểm tra sự có mặt/vắng mặt |

Một khóa dict tiêu chí không rõ (bất cứ thứ gì khác `regex`, `equals`, `in`, `exists`) ném ra `ValueError` khi đánh giá.

### Bảng Ánh Xạ Khóa Tiêu Chí

Các tiêu chí bước kịch bản sử dụng tên khóa thân thiện với miền mà engine ánh xạ sang các thuộc tính dataclass được lưu trong đồ thị.

**Process nodes** (`PROCESS_KEY_MAP`):

| Khóa tiêu chí | Thuộc tính `ProcessNode` | Nội dung điển hình |
|---------------|------------------------|-------------------|
| `ProcessName` | `name` | Tên tệp ảnh, ví dụ `"rundll32.exe"` |
| `ProcessPath` | `path` | Đường dẫn thực thi đầy đủ |
| `CommandLine` | `command_line` | Chuỗi dòng lệnh đầy đủ |
| `ParentProcessName` | `parent_process_name` | Tên tệp ảnh tiến trình cha |
| `IntegrityLevel` | `integrity_level` | Ví dụ `"High"`, `"System"` |
| `ProcessGuid` | `id` | ID node đồ thị nội bộ (= `process_guid` từ nhật ký) |

**File nodes** (`FILE_KEY_MAP`):

| Khóa tiêu chí | Thuộc tính `FileNode` | Nội dung điển hình |
|---------------|---------------------|-------------------|
| `FileName` | `name` | Tên tệp không có đường dẫn |
| `Path` | `path` | Đường dẫn tệp đầy đủ |
| `Extension` | `extension` | Chữ thường, có dấu chấm, ví dụ `".dll"` |
| `IsSigned` | `is_signed` | Boolean |
| `IsInjected` | `is_injected` | Boolean |
| `ApiHookingDetected` | `api_hooking_detected` | Boolean |
| `SignatureVendor` | `signature_vendor` | Ví dụ `"Microsoft Windows"` |

**Behavior edges** (`BEHAVIOR_KEYS`):

Các khóa `TargetProcess`, `GrantedAccess`, và `Behavior_Markers` được xử lý đặc biệt. Sự hiện diện của chúng trong `matching_criteria` đánh dấu bước là một **bước behavior** (xem bên dưới).

| Khóa tiêu chí | Thuộc tính cạnh `EXHIBITED` | Quy tắc khớp |
|---------------|--------------------------|-------------|
| `TargetProcess` | `attrs["target"]` | `match_value(criterion, attrs["target"])` |
| `GrantedAccess` | `attrs["granted_access"]` | `match_value(criterion, attrs["granted_access"])` |
| `Behavior_Markers` | `attrs["behavior"]` | `attrs["behavior"] in criterion` — criterion phải là một list |

### `node_matches(node, criteria)`

Lặp qua tất cả các khóa trong dict criteria, bỏ qua `Node_Type` và ba khóa behavior. Với mỗi khóa còn lại:

1. Tra cứu khóa trong bảng ánh xạ phù hợp (`PROCESS_KEY_MAP` hoặc `FILE_KEY_MAP`).
2. Nếu khóa không có trong bảng, trả về `False` ngay lập tức.
3. Đọc `getattr(node, attr, None)` và gọi `match_value(criterion, actual)`.
4. Trả về `False` khi tiêu chí đầu tiên thất bại; `True` nếu tất cả đều vượt qua.

`node_matches_nonbehavior` là một alias của `node_matches` được dùng trong đường bước behavior để làm rõ ý định: chỉ phần tiêu chí không phải behavior được kiểm tra so với process node; các khóa behavior được kiểm tra riêng so với cạnh EXHIBITED.

---

## Các Phần Tử Được Khớp và Loại Bước

Mỗi bước kịch bản xác định chính xác một *phần tử* đồ thị — là một node hoặc một cạnh. Engine phân biệt hai loại bước:

**Bước không phải behavior** (`is_behavior_step(criteria) == False`):

- Khớp một `ProcessNode` (khi `Node_Type = "Process"`) hoặc một `FileNode` (`Node_Type = "File"`).
- Timestamp ứng viên: trường `timestamp` của node (được đặt tại thời điểm xây dựng đồ thị từ timestamp sự kiện).
- Host ứng viên: `backend.host_of(node.id)`.

**Bước behavior** (`is_behavior_step(criteria) == True`):

- Khớp một cạnh tự vòng `EXHIBITED` trên một process node.
- Engine trước tiên tìm các `ProcessNode` có thuộc tính không phải behavior thỏa mãn criteria, sau đó với mỗi tiến trình như vậy, lặp qua các cạnh `EXHIBITED` của nó và kiểm tra các thuộc tính behavior.
- Mỗi cặp `(process, EXHIBITED_edge)` khớp trở thành một `Candidate` với ID tổng hợp `{proc_id}|EXH|{i}` (chỉ số sequence trong các cạnh EXHIBITED của tiến trình).
- Timestamp ứng viên: `Edge.timestamp`.
- Host ứng viên: host của process node nguồn.

---

## Thuật Toán Tiền Tố Hợp Lệ Dài Nhất — `engine/matcher.py`

### Giai Đoạn Tính Trước

Trước khi DFS bắt đầu, `match_scenario` gọi `_find_candidates(scenario, step, backend)` cho mỗi bước. Hàm này:

1. Gọi `backend.find_nodes(node_type, predicate)` (không phải behavior) hoặc `backend.find_nodes("Process", predicate)` + `backend.edges_from(proc.id, "EXHIBITED")` (behavior).
2. Áp dụng **cổng không gian** cho mỗi ứng viên thô.
3. Trả về các ứng viên còn lại được sắp xếp theo `(timestamp, element_id)`.

Nếu tập ứng viên cho bước 1 rỗng, `match_scenario` trả về `(0, [])` ngay lập tức.

### Cổng Không Gian — `_spatial_ok(host, spatial_constraints)`

Một ứng viên thất bại cổng không gian — và bị loại khỏi tập ứng viên trước khi DFS bắt đầu — nếu bất kỳ điều kiện nào sau đây đúng:

- `host` là `None` (node không có host được phân giải).
- `host.zone == Zone.Unknown` (host không được tìm thấy trong tệp topology).
- `host.zone.value` không có trong `spatial_constraints.applicable_zones`.
- `spatial_constraints.critical_assets_only == True` và `host.criticality != Criticality.CRITICAL`.

Các host không rõ luôn thất bại cổng này vì `topology.enrich()` gán cho chúng `Zone.Unknown`.

### Giai Đoạn DFS — `extend(idx, prev, chain)`

Sau giai đoạn tính trước, DFS tiến hành:

```
best = (0, [])

for each anchor in cands[step 1]:
    call extend(idx=1, prev=anchor, chain=[anchor])

def extend(idx, prev, chain):
    if len(chain) > best[0]:
        best = (len(chain), copy(chain))   # update best at every depth
    if idx >= len(steps):
        return                             # all steps matched — chain is complete
    step = steps[idx]
    for cand in cands[step.step_id]:       # pre-sorted by (timestamp, element_id)
        if not _temporal_ok(prev.timestamp, cand.timestamp, step):
            continue                       # fails time-window gate
        if not _link_ok(prev, cand, step.temporal_link.link_scope):
            continue                       # fails host-relationship gate
        chain.append(cand)
        extend(idx + 1, cand, chain)       # recurse
        chain.pop()                        # backtrack
```

`best` được cập nhật bên trong đệ quy, không chỉ tại các lá. Điều này có nghĩa là nếu bước *k* khớp nhưng không có ứng viên nào cho bước *k+1* vượt qua các cổng, `best` đã giữ chuỗi độ dài *k* khi đệ quy mở ra.

Các sự kiện không liên quan xảy ra giữa hai bước đã khớp không làm gián đoạn chuỗi; thuật toán là tìm kiếm dãy con trên danh sách ứng viên đã được sắp xếp, không phải quét cửa sổ trượt.

### Cổng Thời Gian — `_temporal_ok(prev_ts, cand_ts, step)`

```python
link = step.temporal_link
if cand_ts < prev_ts:
    return False                           # must be non-decreasing
lo = prev_ts + timedelta(seconds=link.min_time_delta_seconds)
hi = prev_ts + timedelta(seconds=link.max_time_delta_seconds)
return lo <= cand_ts <= hi
```

Cả `min_time_delta_seconds` (mặc định 0) và `max_time_delta_seconds` đều được đặt theo từng bước trong YAML kịch bản. Một bước bị loại nếu timestamp của phần tử khớp nằm ngoài `[prev + min, prev + max]`.

### Cổng Quan Hệ Host — `_link_ok(prev, cand, scope)`

```python
same = prev.host.hostname.lower() == cand.host.hostname.lower()
if scope == LinkScope.same_host:   return same
if scope == LinkScope.cross_host:  return not same
if scope == LinkScope.any:         return True
```

`link_scope` được đặt theo từng bước trong khối `temporal_link` của YAML. Mặc định là `same_host`.

---

## Đảm Bảo Tính Tất Định

Engine được thiết kế để tạo ra **đầu ra byte-identical cho đầu vào giống nhau**. Các đảm bảo là:

1. **Sắp xếp ứng viên.** `_find_candidates` trả về các ứng viên được sắp xếp theo `(timestamp, element_id)`. Cả `NetworkXBackend.find_nodes()` và `NetworkXBackend.edges_from()` đều sắp xếp đầu ra trước khi trả về. Backend Neo4j áp dụng cùng thứ tự qua `ORDER BY` trong các truy vấn Cypher.

2. **Thứ tự lặp DFS.** `extend()` lặp qua các danh sách ứng viên đã được sắp xếp theo thứ tự cố định, tất định. Không có lặp dict hoặc set trên các đối tượng Python mà thứ tự phụ thuộc vào hash.

3. **Phá vỡ ràng buộc.** `best` được cập nhật với so sánh `>` nghiêm ngặt trên độ dài chuỗi. Khi hai chuỗi có độ dài bằng nhau được tìm thấy, chuỗi được khám phá trước (timestamp sớm hơn và/hoặc element_id thấp hơn) sẽ thắng.

4. **Không có trạng thái bên ngoài trong đường nóng.** Không đọc đồng hồ thực (`datetime.now()`), không tạo số ngẫu nhiên (`random`, `uuid4`), không đọc môi trường bên trong `match_scenario` hoặc `_find_candidates`.

5. **Xếp hạng ổn định.** `rank()` sắp xếp theo một tuple float `(-proximity, -severity_rank, -latest_ts_epoch)`. So sánh float hoàn toàn tất định.

6. **Sắp xếp sự kiện tại đầu vào pipeline.** `pipeline.build_backend` sắp xếp danh sách sự kiện theo `timestamp` trước khi truyền cho `build_graph`, vì vậy đồ thị luôn được xây dựng theo cùng một thứ tự bất kể thứ tự nối tệp.

Với đầu vào JSONL giống nhau và `scenarios/*.yaml` giống nhau, một lần chạy phát hiện sẽ tạo ra cùng một danh sách xếp hạng — bao gồm các giá trị proximity giống nhau, chuỗi bước khớp giống nhau, và các host bị ảnh hưởng giống nhau — trên các máy khác nhau, các lần gọi Python khác nhau, và theo thời gian.

---

## Công Thức Proximity

```
proximity = round(matched_prefix_length / scenario.step_count, 4)
```

Trong đó:
- `matched_prefix_length` = `len(chain)` được trả về bởi `match_scenario` — số bước được khớp, bắt đầu từ bước 1.
- `scenario.step_count` = `len(scenario.attack_sequence_flow.steps)`.
- Kết quả được làm tròn đến 4 chữ số thập phân.

**Tiền tố phải liên tiếp.** Nếu bước *k* không thể được khớp (không có ứng viên nào vượt qua tất cả các cổng), các bước *k+1* đến *N* không thể đóng góp, ngay cả khi các sự kiện khớp tồn tại trong đồ thị. Điều này được thực thi bởi cấu trúc DFS: một khi `extend` hết ứng viên hợp lệ ở độ sâu *k*, chuỗi dừng lại và `best` không được cập nhật thêm từ nhánh đó.

### Ngưỡng Báo Cáo Mặc Định

`run_engine` và `rank` chấp nhận tham số `min_proximity` (mặc định `0.30`). Chỉ các phát hiện với `proximity >= min_proximity` và `proximity > 0` được đưa vào đầu ra.

Ví dụ theo số bước:

| Số bước | Số bước khớp tối thiểu để xuất hiện | Proximity tối thiểu |
|---------|-------------------------------------|---------------------|
| 3 | 1 | 0.3333 |
| 4 | 2 | 0.50 |
| 5 | 2 | 0.40 |
| 10 | 3 | 0.30 |

---

## Quy Tắc Xếp Hạng

```python
sorted(kept, key=lambda d: (-d.proximity, -d._severity_rank, -d._latest_ts_epoch))
```

Ba khóa sắp xếp theo thứ tự ưu tiên:

1. **Proximity giảm dần** — tỷ lệ phần trăm chuỗi tấn công khớp cao nhất đứng trước.
2. **Severity giảm dần** — `SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}`. Hạng số nguyên được tính một lần trong `build_detection` và lưu trong trường private `_severity_rank`.
3. **Sự kiện khớp gần đây nhất đứng trước** — `_latest_ts_epoch` là float Unix epoch của timestamp mới nhất trong tất cả các ứng viên bước được khớp. Hoạt động gần đây hơn hiện ra trước các kết quả khớp cũ hơn ở cùng proximity và severity.

Ba trường sắp xếp private (`_latest_ts`, `_latest_ts_epoch`, `_severity_rank`) bị loại bỏ bởi `api/app.py::_public()` trước khi `Detection` được tuần tự hóa vào phản hồi HTTP.

---

## Dataclass Detection — `engine/scoring.py`

```python
@dataclass
class Detection:
    scenario_id:    str          # e.g. "SCEN-WIN-001"
    name:           str          # scenario human name
    severity:       str          # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    proximity:      float        # round(matched_len / step_count, 4)
    matched_steps:  list[dict]   # [{step_id, name, element_id, host, timestamp}, ...]
    missing_steps:  list[dict]   # [{step_id, name}, ...] for unmatched suffix
    affected_hosts: list[str]    # sorted unique hostnames in the matched chain
    affected_zones: list[str]    # sorted unique zone values in the matched chain
    hunting_queries: list[dict]  # [{engine, query, query_path}, ...]
    _latest_ts:      str         # ISO timestamp of latest matched element (sort only)
    _latest_ts_epoch: float      # Unix epoch float of latest matched element (sort only)
    _severity_rank:  int         # integer rank of severity (sort only)
```

`build_detection(scenario, matched_len, chain)` xây dựng `Detection` từ chuỗi đã khớp: `affected_hosts` và `affected_zones` được suy ra bằng cách lặp qua các trường `Candidate.host` của chuỗi và loại trùng lặp. `hunting_queries` đến từ `scenario.actionable_hunting_outputs.validation_queries`.

---

## Ví Dụ Minh Họa: Chuỗi LSASS comsvcs của SCEN-WIN-001

**Kịch bản:** LSASS Credential Dump via comsvcs.dll MiniDump (`SCEN-WIN-001`), 3 bước, CRITICAL.

```yaml
# scenarios/credential_access/win_lsass_comsvcs.yaml (abridged)
scenario_metadata:
  scenario_id: "SCEN-WIN-001"
  severity: "CRITICAL"
  os_family: "windows"
spatial_constraints:
  applicable_zones: ["User_Endpoint", "Internal_Server"]
attack_sequence_flow:
  steps:
    - step_id: 1
      name: "Rundll32_Launch"
      matching_criteria:
        Node_Type: "Process"
        ProcessName: {in: ["rundll32.exe"]}
        CommandLine: {regex: ".*comsvcs.*"}
    - step_id: 2
      name: "MiniDump_CommandLine"
      temporal_link: {previous_step: 1, link_scope: same_host,
                      min_time_delta_seconds: 0, max_time_delta_seconds: 60}
      matching_criteria:
        Node_Type: "Process"
        ProcessName: {in: ["rundll32.exe"]}
        CommandLine: {regex: ".*MiniDump.*"}
    - step_id: 3
      name: "LSASS_Access_Behavior"
      temporal_link: {previous_step: 2, link_scope: same_host,
                      min_time_delta_seconds: 0, max_time_delta_seconds: 120}
      matching_criteria:
        Node_Type: "Process"
        TargetProcess: "lsass.exe"
        GrantedAccess: "0x1410"
```

**Trạng thái đồ thị** sau khi xử lý `full_detection.jsonl` trên host `CORP-WS-01`
(zone = `User_Endpoint`, criticality = `MEDIUM`):

```
HostNode    id="corp-ws-01"  zone=User_Endpoint  criticality=MEDIUM

ProcessNode id="proc-a"  name="rundll32.exe"
            command_line="rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump ..."
            timestamp=T+00:00

ProcessNode id="proc-b"  name="rundll32.exe"
            command_line="rundll32.exe comsvcs.dll MiniDump 636 C:\temp\lsass.dmp full"
            timestamp=T+00:15

EXHIBITED edge  src=proc-b  dst=proc-b
    attrs={behavior="lsass_memory_read", target="lsass.exe", granted_access="0x1410"}
    timestamp=T+00:45
```

**Giai đoạn tính trước:**

```
Step 1 candidates:
  find_nodes("Process", predicate):
    proc-a → ProcessName in ["rundll32.exe"] ✓
              CommandLine matches .*comsvcs.* ✓
    host corp-ws-01 → zone=User_Endpoint ∈ ["User_Endpoint","Internal_Server"] ✓
    proc-b → CommandLine "...MiniDump..." does NOT match .*comsvcs.* ✗
  cands[1] = [Candidate(element_id="proc-a", ts=T+00:00, host=corp-ws-01)]

Step 2 candidates:
  find_nodes("Process", predicate):
    proc-a → CommandLine "comsvcs.dll, MiniDump..." matches .*MiniDump.* ✓
    proc-b → CommandLine "comsvcs.dll MiniDump..." matches .*MiniDump.* ✓
  both pass spatial gate
  cands[2] = [Candidate("proc-a", T+00:00), Candidate("proc-b", T+00:15)]
              (sorted by timestamp then element_id)

Step 3 candidates:  (behavior step — TargetProcess in criteria)
  find_nodes("Process", all):
    proc-b has EXHIBITED edge with target="lsass.exe" and granted_access="0x1410" ✓
  cands[3] = [Candidate("proc-b|EXH|0", T+00:45, host=corp-ws-01)]
```

**Giai đoạn DFS:**

```
Anchor = proc-a (T+00:00)  →  extend(idx=1, prev=proc-a, chain=[proc-a])
  best = (1, [proc-a])

  Try cand proc-a for step 2:
    temporal_ok? T+00:00 - T+00:00 = 0s, 0 ≤ 0s ≤ 60s ✓
    link_ok? corp-ws-01 == corp-ws-01 (same_host) ✓
    chain = [proc-a, proc-a]  →  extend(idx=2, prev=proc-a, chain=[proc-a, proc-a])
      best = (2, [proc-a, proc-a])
      Try cand proc-b|EXH|0 for step 3:
        temporal_ok? T+00:45 - T+00:00 = 45s ≤ 120s ✓
        link_ok? same_host ✓
        chain = [proc-a, proc-a, proc-b|EXH|0]  →  extend(idx=3, ...)
          best = (3, [proc-a, proc-a, proc-b|EXH|0])
          idx >= len(steps)=3 → return
        chain.pop()
      (no more step-3 cands)
    chain.pop()  → chain=[proc-a]

  Try cand proc-b for step 2:
    temporal_ok? T+00:15 - T+00:00 = 15s ≤ 60s ✓
    link_ok? same_host ✓
    chain = [proc-a, proc-b]  →  extend(idx=2, prev=proc-b, chain=[proc-a, proc-b])
      best stays (3, ...) — 2 < 3
      Try cand proc-b|EXH|0 for step 3:
        temporal_ok? T+00:45 - T+00:15 = 30s ≤ 120s ✓
        link_ok? same_host ✓
        chain = [proc-a, proc-b, proc-b|EXH|0]  →  extend(idx=3, ...)
          best still (3, ...) — 3 not > 3, no update (tie goes to first-found)
          return
        chain.pop()
    chain.pop()
```

**Kết quả:**

```
match_scenario returns: matched_len=3, chain=[proc-a, proc-a, proc-b|EXH|0]

build_detection:
  proximity = round(3 / 3, 4) = 1.0
  severity  = "CRITICAL"
  matched_steps = [
    {step_id: 1, name: "Rundll32_Launch",       element_id: "proc-a",       host: "CORP-WS-01", timestamp: "T+00:00"},
    {step_id: 2, name: "MiniDump_CommandLine",   element_id: "proc-a",       host: "CORP-WS-01", timestamp: "T+00:00"},
    {step_id: 3, name: "LSASS_Access_Behavior",  element_id: "proc-b|EXH|0", host: "CORP-WS-01", timestamp: "T+00:45"},
  ]
  missing_steps  = []
  affected_hosts = ["CORP-WS-01"]
  affected_zones = ["User_Endpoint"]
  _latest_ts_epoch = T+00:45 as Unix float
  _severity_rank   = 3  (CRITICAL)

rank output: Detection(scenario_id="SCEN-WIN-001", proximity=1.0, ...)
  → top of the ranked list
```

### Biến Thể Khớp Một Phần

Nếu chỉ có sự kiện bước 1 và bước 2 (hành vi truy cập LSASS của bước 3 vắng mặt):

```
cands[3] = []
extend from proc-a → extend from proc-a for step 2 → step 3 has no cands → returns
best = (2, [proc-a, proc-a])

proximity = round(2 / 3, 4) = 0.6667
→ appears in results at min_proximity ≤ 0.6667
missing_steps = [{step_id: 3, name: "LSASS_Access_Behavior"}]
```

### Biến Thể Vi Phạm Thời Gian

Nếu timestamp của cạnh EXHIBITED truy cập LSASS là T+03:00 (180 giây sau bước 2 tại T+00:00):

```
Step 3 temporal gate (max=120s):
  T+03:00 - T+00:00 = 180s > 120s → _temporal_ok returns False → cand dropped

best = (2, [proc-a, proc-a])  →  proximity = 0.6667
Step 3 is suppressed and appears in missing_steps.
```

---

## Phạm Vi Bao Phủ Bài Kiểm Tra Chấp Nhận

Hành vi của engine được cố định bởi các bài kiểm tra chấp nhận trong `tests/test_acceptance.py`:

| Tệp fixture | Kết quả mong đợi |
|---|---|
| `acceptance/full_detection.jsonl` | Kịch bản được khớp tại `proximity == 1.0` |
| `acceptance/partial_detection.jsonl` | Cùng kịch bản tại `proximity == 0.6` (hoặc giá trị riêng của kịch bản) |
| `acceptance/no_detection_temporal_gap.jsonl` | Không phát hiện (cổng thời gian kích hoạt) |
| `acceptance/no_detection_wrong_zone.jsonl` | Không phát hiện (cổng không gian kích hoạt) |
| `acceptance/no_detection_benign.jsonl` | Không phát hiện nào trên `min_proximity=0.30` |
| `acceptance/demo_multi_os.jsonl` | Nhiều kịch bản với điểm đúng, sự kiện đa hệ điều hành |

Bộ bài kiểm tra chạy 1164 bài kiểm tra (3 bỏ qua cho Neo4j / AI extras). Xem [CONTRIBUTING.md](CONTRIBUTING.md) để biết cách thêm kịch bản mới và fixture chấp nhận của nó.

## Kiểm định độ bền phát hiện (ranh giới âm tính giả)

Độ chính xác của engine dựa trên ba cổng kiểm soát: **thời gian** (`max_time_delta_seconds`), **không
gian** (`applicable_zones`), và **liên kết** (`link_scope`). Mọi trình kiểm định dương tính
(detectability, drill, campaign) chỉ chứng minh một kịch bản *kích hoạt*; không có cái nào chứng minh
engine *ngừng kích hoạt đúng lúc*. Một lỗi hồi quy nới lỏng một cổng thành luôn-chấp-nhận sẽ giữ mọi
kiểm thử dương tính ở trạng thái xanh trong khi phá huỷ độ chính xác.

**Kiểm định độ bền phát hiện** (`augur.metrics.robustness`) lấp khoảng trống đó **mà không chạm vào
engine**. Nó biến đổi vết tổng hợp tất định của một kịch bản và khẳng định engine suy giảm về đúng giá
trị proximity mà đặc tả quy định:

| Biến đổi | Đối tượng nhiễu loạn | Proximity kỳ vọng (`n = step_count`) |
|----------|----------------------|---------------------------------------|
| `drop_step(k)` | loại bỏ các sự kiện của bước *k* | `round((k-1)/n, 4)` — tiền tố một phần (None nếu `k == 1`) |
| `stretch_temporal(k)` | đẩy bước *k* vượt cổng thời gian đúng 1 giây | `round((k-1)/n, 4)` — cắt trước bước *k* |
| `relocate_zone` | chuyển mọi sự kiện sang host ngoài vùng | **không phát hiện** (mỏ neo trượt cổng không gian) |
| `relink_host(k)` | chuyển bước *k*..cuối sang một host hợp lệ thứ hai, phá liên kết `same_host` | `round((k-1)/n, 4)` — cắt trước bước *k* (cổng liên kết từ chối nhịp k-1→k) |

Toàn bộ **80** liên kết liên-bước trên **40** kịch bản thư viện đều là `link_scope: same_host`, nên biến
đổi liên kết duy nhất hiện thực hoá được là chuyển bước *k* sang một host hợp lệ *khác* với bước *k-1* —
điều mà một cổng `same_host` đúng phải từ chối. Host được chuyển vẫn nằm trong vùng hợp lệ và cùng lớp
mức-quan-trọng, nên `_spatial_ok` vẫn qua và chỉ `_link_ok` có thể từ chối (bảo vệ chống vòng lặp luẩn
quẩn). Khi topology của một kịch bản chỉ có một host hợp lệ, dòng được ghi `no_distinct_host` và loại
khỏi mẫu số tỷ lệ pass (giống `no_offzone_host`).

Lần chạy mặc định kiểm tra bước **cuối cùng** (cổng sâu nhất) của mỗi kịch bản. Dùng `--all-steps` để
quét **mọi** bước áp dụng được cho từng cổng (`stretch_temporal` & `relink_host` 2..n; `drop_step` và
`relocate_zone` giữ ở bước cuối/đơn), chứng minh các cổng từ chối tại *mọi* vị trí tiền tố — không chỉ
vị trí sâu nhất. `drop_step` chỉ chạy ở bước cuối **theo thiết kế**: nó không phải đột biến cổng (nó loại
bỏ sự kiện của một bước, không kích hoạt từ chối thời gian/không gian/liên kết), và ở bước *giữa* tiền tố
khớp **không** suy ra được từ schema thành `(k-1)/n` — DFS có thể tạo một tiền tố liên tục hợp lệ từ các
bước còn lại, hoặc `matching_criteria` của một bước sau có thể được thỏa bởi các sự kiện còn lại của bước
bị loại (vị từ tiến trình chồng lấn).

Bản thân tính chất đó là một **tín hiệu độ chính xác thật về thư viện kịch bản**, nên `--all-steps` còn
phát ra một chẩn đoán riêng **chồng lấn tiêu chí xuyên bước** (`criteria_overlap_diagnostic`). Nó loại
từng bước *không-cuối* (k trong 1..n-1) và gắn cờ các kịch bản mà chuỗi vẫn khớp **cao hơn** mốc cắt ngây
thơ `(k-1)/n`. Trong thư viện hiện tại hai kịch bản bị gắn cờ: `SCEN-LNX-005` (mỏ neo `bash`/`sh` là tập
cha của `bash` ở bước 3, nên một sự kiện bước-3 còn lại tái-neo tiền tố 1 bước → 0.3333) và `SCEN-MAC-001`
(`{sh,bash,curl}` ở bước 2 là tập cha của `curl` ở bước 3, nên chuỗi đầy đủ hoàn tất mà không cần sự kiện
riêng của bước 2 → 1.0). Đây là **thông tin tham khảo, KHÔNG phải lỗi cổng** — ba cổng từ chối đúng — và
nó **bị loại khỏi tổng pass/fail của robustness** (nó gắn cờ khả năng khớp-thừa dưới bằng chứng một phần,
một tính chất lành tính đã biết của tiêu chí thân thiện-tổng-hợp, được phơi bày trung thực thay vì giấu đi). Kỳ vọng được **suy ra từ schema, không phải chụp lại** — một kiểm thử "chấp
nhận những gì engine làm" sẽ là vòng lặp luẩn quẩn. Một **kiểm thử lính canh chống-vòng-lặp** vá
`_link_ok` thành luôn-True và khẳng định dòng relink lật sang `unexpected_fire`, chứng minh khẳng định
gắn với cổng chứ không phải với synth.

Chạy từ báo cáo metrics:

```bash
uv run python -m augur.metrics --fail-on-robustness
uv run python -m augur.metrics --all-steps --fail-on-robustness
```

`--fail-on-robustness` thoát với mã khác 0 nếu bất kỳ cổng nào không từ chối đúng — một bẫy hồi quy cho
CI. Dùng trực tiếp: `detection_robustness(default_scenarios(), default_topology())` trả về
`{rows, aggregate, honesty_note}`.

**Trung thực:** một kết quả PASS chứng minh mỗi cổng hiện *từ chối đúng trên thư viện kịch bản* — một
cổng kiểm tra tính toàn vẹn cấu trúc / hồi quy — **KHÔNG** phải tuyên bố về tỷ lệ âm tính giả trong thế
giới thực và **không** phải bằng chứng chống lại đối thủ thực.
