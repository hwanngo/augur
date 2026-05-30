[English](../en/API.md) | **Tiếng Việt**

# Augur — Tài Liệu Tham Khảo REST API

Augur API là một ứng dụng FastAPI (`src/augur/api/app.py`). Theo mặc định nó lắng nghe trên cổng
**8000** (`make demo` / `uvicorn augur.api.app:create_app --factory`).

---

## Mô Hình Xác Thực

Augur sử dụng **cookie phiên phía máy chủ** — không có bearer token hay API key.

- **Cookie:** `fs_session` (HttpOnly, SameSite=Strict; Secure trong môi trường production khi
  `AUGUR_COOKIE_SECURE=true`).
- **Mật khẩu** được băm bằng argon2id. Một lần xác minh giả cân bằng thời gian chạy cho các người dùng
  không xác định hoặc đã bị vô hiệu hóa để ngăn chặn việc liệt kê tên người dùng qua thời gian.
- **Bảo vệ CSRF:** mẫu double-submit. `POST /api/auth/login` trả về `csrf_token` trong phần thân
  JSON của nó. Tất cả các yêu cầu thay đổi trạng thái (POST/PUT/PATCH/DELETE, ngoại trừ `/login`) phải bao gồm token này
  trong tiêu đề yêu cầu `X-CSRF-Token`. Các GET chỉ đọc không yêu cầu tiêu đề CSRF.
- **Giới hạn tốc độ / khóa tài khoản:** bộ đếm theo tên người dùng trong tiến trình. Vượt quá ngưỡng được cấu hình
  sẽ trả về `429 Too Many Requests` cho đến khi cửa sổ khóa hết hạn.
- **Vai trò (RBAC):** `viewer` < `analyst` < `admin`. Vai trò cao hơn thỏa mãn bất kỳ cổng vai trò thấp hơn nào.
  Các yêu cầu chưa xác thực đến các endpoint có cổng bảo vệ trả về `401 Unauthorized`.

### Luồng Đăng Nhập

```
POST /api/auth/login          (form data: username, password)
← 200  { "user": "alice", "role": "admin", "csrf_token": "<token>" }
        Set-Cookie: fs_session=<sid>; HttpOnly; SameSite=Strict

# Tất cả các yêu cầu thay đổi trạng thái tiếp theo:
X-CSRF-Token: <token>
Cookie: fs_session=<sid>
```

---

## SPA và Tệp Tĩnh

Khi `frontend/dist/` tồn tại (đầu ra build React), ứng dụng phục vụ nó tại `/`. Bất kỳ GET nào không
khớp với route `/api/*` đều trả về `index.html` (phương án dự phòng SPA cho React Router deep-link). Khi chỉ
thư mục `src/augur/web/` cũ tồn tại, nó được phục vụ qua FastAPI `StaticFiles` với
`html=True`.

---

## Tham Chiếu Endpoint

Các route được nhóm bên dưới theo khu vực chức năng. Các vai trò bắt buộc là **tối thiểu** cần thiết; admin
luôn thỏa mãn các cổng analyst và viewer.

### Kiểm Tra Sức Khỏe

#### `GET /api/health`

Không yêu cầu xác thực.

**Phản hồi `200`:**
```json
{ "status": "ok" }
```

---

### Dữ Liệu Phát Hiện

Tất cả các endpoint dữ liệu yêu cầu ít nhất vai trò `viewer`.

#### `GET /api/detections`

Trả về các phát hiện được xếp hạng từ nguồn log hiện tại. Danh sách phát hiện được tính toán một lần khi khởi động
và được lọc theo từng yêu cầu.

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Điểm proximity tối thiểu (0.0–1.0); lọc danh sách được tính toán trước |
| `from` | `str \| null` | `null` | Mốc thời gian giới hạn dưới tuyệt đối (ISO 8601). Các phát hiện có sự kiện mới nhất trước mốc này bị loại bỏ |
| `to` | `str \| null` | `null` | Mốc thời gian giới hạn trên tuyệt đối (ISO 8601). Các phát hiện có sự kiện mới nhất sau mốc này bị loại bỏ |

Khi cả `from` và `to` đều được bỏ qua, yêu cầu sử dụng đường nhanh trên danh sách phát hiện được
tính toán trước. Khi một trong hai được cung cấp, các phát hiện được tính toán lại cho cửa sổ tuyệt đối đó.

**Lưu ý về tính tất định:** `from`/`to` phải là các mốc thời gian ISO 8601 **tuyệt đối** — engine không
bao giờ quan sát "now" theo đồng hồ. Các cửa sổ tương đối (ví dụ "24 giờ qua") được phía gọi giải quyết
thành các mốc tuyệt đối trước khi gửi yêu cầu. Các timestamp không có offset được hiểu là UTC. Khi chỉ
cung cấp một mốc, mốc còn lại mặc định là mốc mở (epoch / tương lai xa). `min_proximity` được áp dụng
**sau khi** cửa sổ hóa.

**Vai trò yêu cầu:** `viewer`

**Phản hồi lỗi:**
- `422 Unprocessable Entity` — một timestamp ISO không phân tích được, hoặc các mốc bị đảo ngược (`from` > `to`)

**Phản hồi `200`** — mảng các đối tượng phát hiện:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | ví dụ: `"SCEN-WIN-001"` |
| `scenario_name` | `str` | Tên dễ đọc |
| `severity` | `str` | `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` |
| `proximity` | `float` | `round(matched / total, 4)` |
| `matched_steps` | `int` | Các bước tiền tố liên tiếp đã khớp |
| `total_steps` | `int` | Tổng số bước trong kịch bản |
| `affected_hosts` | `list[str]` | Các tên máy chủ trong chuỗi đã khớp |
| `chain` | `list` | Các nút đồ thị đã khớp có thứ tự |

Các trường phát hiện riêng tư (`_latest_ts`, `_latest_ts_epoch`, `_severity_rank`) bị loại bỏ
bởi `_public()` và không bao giờ xuất hiện trong phản hồi.

**Săn tìm bước tiếp theo (F1).** Mỗi mục trong `missing_steps` mang thêm — bên cạnh `step_id` và
`name` hiện có — `matching_criteria` của bước (dict trường/toán-tử/giá-trị, với các giá trị vô hướng
gốc JSON) và `temporal`: liên kết thời gian đã tuần-tự-hóa (`previous_step`, `link_scope`,
`min_time_delta_seconds`, `max_time_delta_seconds`) hoặc `null` cho bước 1 / các bước không có liên
kết. Nhờ đó bảng điều khiển hiển thị *cần tìm gì tiếp theo* trên một phát hiện một phần. Các bên chỉ
đọc `step_id`/`name` không bị ảnh hưởng (các khóa hoàn toàn là bổ sung).

**Chẩn đoán điểm dừng (F3).** Một phát hiện dưới 100% (proximity `< 1.0`, với `matched_len ≥ 1`)
mang thêm một đối tượng `stall` chỉ-đọc, bổ sung, giải thích vì sao **bước chưa khớp đầu tiên (k+1)**
bị dừng. Nó **vắng mặt ở phát hiện đầy đủ (100%)**. Chẩn đoán được tính **một lần mỗi cửa sổ và được
lưu cache** (bên trong các builder phát hiện — không bao giờ trên đường xử lý nóng theo từng yêu cầu)
và không bao giờ thay đổi đường tính điểm. `kind` của nó là một trong:

| `kind` | Trường bổ sung | Ý nghĩa |
|---|---|---|
| `no_candidate` | `step_id`, `step_name` | Không thấy sự kiện nào giống bước này |
| `temporal` | `step_id`, `host`, `delta_seconds`, `window_seconds` | Ứng viên gần nhất vượt quá cửa sổ thời gian |
| `spatial` | `step_id`, `host`, `zone`, `applicable_zones` | Host ứng viên ở vùng không hợp lệ |
| `link` | `step_id`, `host`, `link_scope` | Ứng viên vi phạm phạm vi liên kết cùng/khác host của bước |

**Đà proximity (F2) được hoãn lại** — hiện chưa có trường đà/xu hướng nào trên phản hồi này.

#### `GET /api/host_risk`

Trả về **bảng rủi ro theo từng máy chủ** đã xếp hạng, trả lời câu hỏi *"nên điều tra máy nào
trước?"*. Rủi ro được tổng hợp trên cùng nguồn phát hiện như `/api/detections`, kết hợp với cấu trúc
mạng (topology) có thẩm quyền, và được **máy chủ sắp xếp theo rủi ro giảm dần**.

**Tham số truy vấn:** giống hệt `GET /api/detections` (dùng lại đúng nhánh chọn nguồn và cửa sổ thời
gian):

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Điểm proximity tối thiểu; lọc các phát hiện **trước khi** tổng hợp |
| `from` | `str \| null` | `null` | Mốc thời gian dưới tuyệt đối (ISO 8601) |
| `to` | `str \| null` | `null` | Mốc thời gian trên tuyệt đối (ISO 8601) |

Khi bỏ qua cả `from`/`to`, dùng đường nhanh trên danh sách phát hiện đã tính sẵn; khi cung cấp một
trong hai, các phát hiện được tính lại cho cửa sổ tuyệt đối đó. `min_proximity` được áp dụng **sau**
khi cắt cửa sổ và trước khi tổng hợp.

**Vai trò yêu cầu:** `viewer`

**Phản hồi lỗi:**
- `422 Unprocessable Entity` — mốc thời gian ISO không phân tích được, hoặc mốc bị đảo ngược (`from` > `to`)

**Công thức tính điểm.** Mỗi phát hiện đóng góp cho mọi host trong `affected_hosts`:

```
contribution = proximity × CRIT_WEIGHT[criticality] × SEV_WEIGHT[severity]
host.score    = round(TỔNG các contribution, 4)
```

với `SEV_WEIGHT = {LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4}` (khóa bằng chuỗi) và
`CRIT_WEIGHT = {CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, UNKNOWN:1}` (mức nghiêm trọng lấy từ topology —
nguồn có thẩm quyền; vùng trong sự kiện bị bỏ qua). Các hàng được sắp xếp theo `(-score, hostname tăng
dần)`, nên các máy sạch (`score == 0`) rơi xuống cuối.

**Mức (band)** được suy ra từ điểm: `CRITICAL` ≥ 8, `HIGH` ≥ 4, `WATCH` ≥ 1.5, `LOW` > 0,
`CLEAR` = 0.

**Tập máy chủ.** Mọi tài sản trong topology đều được trả về (máy sạch xuất hiện ở mức `CLEAR`), cộng
thêm các host ngoài topology xuất hiện trong phát hiện (trả về với vùng `Unknown` / mức `UNKNOWN`).
Tên máy được so khớp không phân biệt hoa thường; dùng cách viết hoa chuẩn của topology để hiển thị.

**Phản hồi `200`** — `{ "hosts": [...] }` trong đó mỗi đối tượng host là:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `hostname` | `str` | Tên hiển thị chuẩn (topology), hoặc cách viết thấy đầu tiên nếu ngoài topology |
| `zone` | `str` | Vùng từ `Topology.enrich` (`Unknown` nếu ngoài topology) |
| `criticality` | `str` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN` |
| `score` | `float` | `round(TỔNG(proximity × CRIT_WEIGHT × SEV_WEIGHT), 4)` |
| `band` | `str` | `CRITICAL` / `HIGH` / `WATCH` / `LOW` / `CLEAR` |
| `detection_count` | `int` | Số phát hiện đóng góp |
| `max_proximity` | `float` | Proximity cao nhất trong các phát hiện đóng góp (`0` nếu sạch) |
| `top_severity` | `str \| null` | Mức nghiêm trọng cao nhất trong các phát hiện đóng góp (`null` nếu sạch) |
| `top_scenarios` | `list` | Tối đa 3 đóng góp hàng đầu, sắp theo `(contribution giảm, scenario_id tăng)` |

Mỗi mục `top_scenarios` là `{ scenario_id, name, severity, proximity }`.

Endpoint này **chỉ đọc và mang tính bổ sung**: không chạy lượt engine nào và không bao giờ import
đường scoring / matcher, nên tính tất định của engine được giữ nguyên. Hai lần gọi giống nhau trả về
kết quả giống nhau.

#### `GET /api/momentum`

Trả về tín hiệu **đà tiến độ gần (proximity momentum)** cho từng kịch bản, trả lời câu hỏi *"cuộc tấn
công này còn đang tiến triển ngay lúc này không?"*. Với mỗi kịch bản, nó cho biết độ gần đang *tăng /
ổn định / giảm* theo thời gian, kèm chuỗi điểm để vẽ sparkline, một giá trị delta và một vận tốc. Chuỗi
thời gian là **thật**, được dựng từ các lượt chạy engine theo cửa sổ thực trên cùng nguồn corpus — không
có gì bịa ra, nội suy hay lưu trữ.

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Ngưỡng sàn trên độ gần toàn cửa sổ; chọn tập kịch bản đưa vào chuỗi |
| `steps` | `int` | `6` | Số mốc thời gian (số điểm sparkline); **giới hạn 3–12** |
| `from` | `str \| null` | `null` | Cận dưới tuyệt đối (ISO 8601) — **chỉ kẹp khoảng lưới (grid span)** (xem dưới) |
| `to` | `str \| null` | `null` | Cận trên tuyệt đối (ISO 8601) — chỉ kẹp khoảng lưới |

**Vai trò yêu cầu:** `viewer`

**Phản hồi lỗi:**
- `422 Unprocessable Entity` — dấu thời gian ISO không phân tích được, hoặc cận bị đảo (`from` > `to`)

**Phản hồi `200`:**

```json
{
  "from": "1970-01-01T00:00:00+00:00",
  "to":   "9999-12-31T00:00:00+00:00",
  "bounds": ["<iso>", "... × N"],
  "series": [
    {
      "scenario_id": "SCEN-WIN-001",
      "points": [0.25, 0.5, 0.75, 1.0],
      "trend": "rising",
      "delta": 0.75,
      "velocity": 0.25
    }
  ]
}
```

| Trường | Kiểu | Mô tả |
|---|---|---|
| `from` / `to` | `str` | Cận yêu cầu (echo lại), ISO 8601 |
| `bounds` | `list[str]` | `N == steps` cận trên lũy kế, ISO 8601, tăng nghiêm ngặt |
| `series[].scenario_id` | `str` | Id kịch bản (Dashboard join với `/api/detections`) |
| `series[].points` | `list[float]` | `round(proximity_tại_mốc_i, 4)`, hoặc `0.0` nếu vắng ở mốc đó (độ dài `N`) |
| `series[].trend` | `str` | `"rising"` (delta > 0.05) / `"falling"` (delta < −0.05) / `"flat"` |
| `series[].delta` | `float` | `round(points[-1] - points[0], 4)` |
| `series[].velocity` | `float` | `round(delta / (N - 1), 4)` |

**Ngữ nghĩa.** Cửa sổ là **lũy kế**: cận dưới của mọi cửa sổ là `_EPOCH_MIN` (epoch); `N` cận trên cách
đều trên khoảng thời-gian-sự-kiện của corpus `[min_ts, max_ts]` với `t_N == max_ts`
(`t_i = min_ts + (max_ts − min_ts) × i / N`). Vì sự kiện của một tấn công nhiều bước tích lũy theo thời
gian, mở rộng cửa sổ làm lộ thêm các bước tiền tố khớp → một đường cong tăng thật. Mỗi `t_i` làm khóa
cho `_windowed_cached(_EPOCH_MIN, t_i)` dùng chung, có cache LRU (maxsize tăng 16→32 để ≤12 mốc của
momentum cộng các cửa sổ detection không bị thrash) — nên chi phí là **N lượt engine tổng cộng**, độc
lập với số kịch bản, không phải N × số kịch bản. Tập kịch bản là kết quả toàn cửa sổ tại `t_N` có độ gần
≥ `min_proximity`.

Ghi chú trung thực / biên:
- `from`/`to` **chỉ kẹp khoảng lưới** `[min_ts, max_ts]` (giao với `[from, to]`); cận dưới cửa sổ vẫn là
  `_EPOCH_MIN` (chuỗi vẫn lũy kế).
- Nguồn chỉ một dấu thời gian (`min_ts == max_ts`) khiến mọi mốc gộp về `max_ts` → một đường phẳng đầy
  chiều cao, `trend = "flat"` (tín hiệu trung thực, không phải lỗi); không chia cho 0.
- Dấu thời gian nguồn "naive" (không offset) được giả định UTC nên phép so sánh theo cửa sổ không bao giờ
  ném lỗi.
- Nguồn rỗng trả về `{ "bounds": [], "series": [] }`.

**Tính tất định.** Chỉ dùng cận tuyệt đối — lưới được suy ra từ dấu thời gian sự kiện (cache lúc khởi
động `corpus_time_span`), **không bao giờ dùng `now`**. Cùng nguồn + cùng `from`/`to`/`steps`/
`min_proximity` → cùng mốc → cùng kết quả cửa sổ đã cache → chuỗi giống hệt từng byte.

**Đường tích lũy (seam no-op).** Endpoint này tính momentum **trực tiếp** từ các lượt chạy engine theo
cửa sổ thực; không lưu trữ gì. Seam `alerting/scan.py::record_proximity` vẫn là **no-op** — **monitor
của alerting (`alerting/monitor.py`) là đường tích lũy sản xuất được ghi nhận** cho một bản dựng
`proximity_samples` lưu trữ trong tương lai.

#### `GET /api/handover`

**Khác biệt bàn giao ca trực**: *"có gì thay đổi trên bảng kể từ ca trước?"* Nó chạy lại engine theo cửa
sổ (chỉ đọc) tại hai mốc ca trực (`to=from` so với `to=to`) và so sánh hai trạng thái bảng **thực** — đây
là trường hợp `N=2` của cơ chế momentum. Không bịa, không lưu trữ; cả hai trạng thái đều là trạng thái
thật của cùng một corpus tại hai mốc thời gian thật.

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Sàn proximity (áp cho cả hai cửa sổ; một kịch bản trong phạm vi nếu vượt sàn ở *một trong hai* cửa sổ) |
| `from` | `str \| null` | **trung điểm** corpus | Mốc bắt đầu ca (ISO 8601). Mặc định `_corpus_min_ts + (_corpus_max_ts − _corpus_min_ts)/2` |
| `to` | `str \| null` | **max** corpus | Mốc kết thúc ca (ISO 8601). Mặc định `_corpus_max_ts` |

**Vai trò yêu cầu:** `viewer`

**Phản hồi lỗi:**
- `422 Unprocessable Entity` — dấu thời gian ISO không phân tích được, hoặc cận bị đảo (`from` > `to`)

**Phản hồi `200`:**

```json
{
  "window": { "from": "<iso>", "to": "<iso>" },
  "meta": { "min_proximity": 0.30, "basis": "corpus-windowed", "deterministic": true },
  "detections": {
    "new":       [{ "scenario_id": "...", "name": "...", "severity": "HIGH",
                    "proximity_prior": null, "proximity_current": 0.9, "proximity_delta": 0.9,
                    "band_prior": null, "band_current": "HIGH", "band_changed": true,
                    "affected_hosts": ["..."] }],
    "escalated": [], "decayed": [], "gone": [], "unchanged_count": 0
  },
  "host_risk": { "entered": [], "left": [], "escalated": [], "deescalated": [] },
  "summary": { "counts": { "new": 1, "escalated": 0, "decayed": 0, "gone": 0, "unchanged": 0,
                           "hosts_entered": 0, "hosts_left": 0,
                           "hosts_escalated": 0, "hosts_deescalated": 0 } }
}
```

| Trường | Kiểu | Mô tả |
|---|---|---|
| `detections.new` | `list` | Có trên bảng hiện tại, vắng ở bảng trước (`proximity_prior == null`) |
| `detections.escalated` / `decayed` | `list` | Có ở cả hai; proximity (hoặc band) tăng / giảm. Mỗi mục mang `proximity_prior→current` + `proximity_delta` |
| `detections.gone` | `list` | Có ở bảng trước, nay không còn khớp nữa (`proximity_current == null`) |
| `detections.unchanged_count` | `int` | Có ở cả hai với proximity y hệt (không liệt kê) |
| `host_risk.entered` / `left` | `list` | Máy vừa vào / rời bảng rủi ro (`band != CLEAR`) giữa hai cửa sổ |
| `host_risk.escalated` / `deescalated` | `list` | Ở trên bảng cả hai; điểm rủi ro tăng / giảm |
| `summary.counts` | `object` | Số đếm từng nhóm cho dòng tóm tắt bàn giao |

**Ngữ nghĩa.** Như momentum, hai lượt chạy engine **tích lũy từ `_EPOCH_MIN`** (so khớp tiền tố cần toàn
bộ lịch sử trước mốc); các cận `from`/`to` là **mốc ca trực**, không phải sàn cửa sổ. Cả hai lượt dùng
chung LRU `_windowed_cached`. Một kịch bản suy giảm *xuống dưới* sàn vẫn là `decayed` (vẫn khớp, yếu hơn);
`gone` nghĩa là không còn khớp nữa. Endpoint này là **khác biệt bảng** theo giờ sự kiện corpus; **khác
biệt phân loại** (giao việc / xử lý trong ca) nằm trên một endpoint wall-clock riêng — xem
`GET /api/triage_handover` bên dưới.

**Tính tất định.** Chỉ dùng cận tuyệt đối, suy ra từ `corpus_time_span` cache lúc khởi động, **không bao
giờ dùng `now`**. Cùng nguồn + cùng `from`/`to`/`min_proximity` → khác biệt giống hệt từng byte. Chỉ đọc
và bổ sung — đường tính điểm/so khớp không bị đụng. Nguồn rỗng trả về khác biệt rỗng hợp lệ.

#### `GET /api/triage_handover`

**Nửa phân loại** của bàn giao ca — *"đội đã làm gì trong ca này?"* — theo **giờ thực của người trực**
(cố ý tách biệt với khác biệt bảng theo giờ sự kiện corpus trong `/api/handover`; hai đồng hồ không bao
giờ trộn trong một payload). Phân hoạch vòng đời cảnh báo đã lưu thành các nhóm trong một cửa sổ tường minh.

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `from` | `str \| null` | min activity-span của store | Cận dưới wall-clock (ISO 8601) |
| `to` | `str \| null` | max activity-span của store | Cận trên wall-clock (ISO 8601) |

**Vai trò yêu cầu:** `viewer`. **Lỗi:** `422` khi cận không phân tích được / bị đảo.

**Phản hồi `200`:**

```json
{
  "window": { "from": "<iso>|null", "to": "<iso>|null" },
  "meta": { "basis": "alert-lifecycle-wallclock", "deterministic": true },
  "triage": {
    "new_alerts": [{ "alert_id": "...", "scenario_id": "...", "scenario_name": "...",
                     "severity": "HIGH", "assignee": "", "status": "open",
                     "ts": "<iso>", "ts_field": "created_at" }],
    "assigned": [], "resolved": [], "reopened": []
  },
  "summary": { "counts": { "new_alerts": 1, "assigned": 0, "resolved": 0, "reopened": 0 } }
}
```

`new_alerts` = `created_at` trong cửa sổ; `assigned` = `assigned_at`; `resolved` = `resolved_at`;
`reopened` = một chuyển trạng thái terminal→non-terminal (từ nhật ký sự kiện; gồm `set_status` thủ công và
`auto_resolved`/tái xuất hiện của engine). `ts_field` của mỗi dòng cho biết đồng hồ vòng đời nào đưa nó vào
nhóm. Một cảnh báo vừa được giao **và** xử lý trong cùng cửa sổ xuất hiện ở cả hai nhóm (hai sự thật trung
thực). Cửa sổ mặc định là activity span của store (`AlertStore.activity_span()`) — tất định, không bao giờ
`now`; store rỗng trả về `window {from:null,to:null}` và các nhóm rỗng. Chỉ đọc và bổ sung; đường tính
điểm của engine không bị đụng.

#### `GET /api/attack_paths`

**Đường kỹ thuật tới tài sản trọng yếu** — với mỗi tài sản CRITICAL, một tiến trình kỹ thuật hợp lý theo
chuỗi kill-chain qua một *mô hình vùng được khai báo* (`ZONE_SPINES`); mỗi vùng là một **stop** ở trạng
thái **observed** (engine thực sự đã phát hiện trong vùng đó) hoặc **hypothetical** (kỹ thuật trong thư
viện áp dụng cho vùng đó nhưng chưa thấy). **Không phải tuyên bố về khả năng tiếp cận mạng hay khai thác** —
topology không có liền kề host và mọi liên kết kịch bản đều same-host. Chỉ đọc, tất định.

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Sàn; phát hiện dưới sàn không tính là stop "observed" |
| `from` / `to` | `str \| null` | toàn dải | Cận ISO tuyệt đối cho cửa sổ phát hiện (không bao giờ `now`) |
| `entry_zone` | `str \| null` | điểm vào spine | Vùng bắt đầu (một giá trị `Zone`); phải nằm trước trên spine của mục tiêu |
| `target` | `str \| null` | tất cả CRITICAL | Một hostname mục tiêu thay vì mọi tài sản CRITICAL |

**Vai trò yêu cầu:** `viewer`. **Lỗi:** `422` khi `entry_zone`/`target` không hợp lệ hoặc cận sai/đảo.

**Phản hồi `200`:** `{ "paths": [AttackPath], "honesty_note": str, "from": iso, "to": iso }` — mỗi
`AttackPath` = `{ entry:{zone}, target:{hostname,zone,criticality}, realized_pct, mean_observed_proximity,
observed_stop_count, total_stop_count, max_severity, stops:[{zone, scenario_id, scenario_name, tactic,
severity, status, observed_proximity, matched_steps, total_steps, host}], honesty_note }`.

Một đường là lát cắt liên tục của một bước đi `ZONE_SPINES` từ vùng vào tới vùng của mục tiêu; mỗi vùng là
một **stop** được phủ bởi kịch bản áp dụng tốt nhất (observed ưu tiên hơn hypothetical). `realized_pct =
round(Σ matched_steps / Σ total_steps, 4)` trên các stop — "log đã cho thấy bao nhiêu phần của cả chuỗi".
Một đường cho mỗi (điểm vào, mục tiêu CRITICAL), giới hạn 50, sắp xếp theo `(-realized_pct, -severity,
entry_zone, target_zone, target_hostname)`. Cửa sổ mặc định suy ra từ corpus, không bao giờ `now`. Chỉ đọc
và bổ sung; đường tính điểm của engine không bị đụng.

#### `GET /api/campaign`

**Bảng điểm Kiểm định Phát hiện của Đội Tím** — chạy hàng loạt **Diễn tập Đội Tím** trên một tập kịch bản
con và tổng hợp bảng điểm detected/missed. Với mỗi kịch bản, nó tiêm cuộc tấn công vào trình mô phỏng tất
định trên một máy chủ hợp lệ rồi chạy engine chỉ-đọc, sau đó báo cáo detected vs missed + độ gần đạt được,
tổng hợp **% detected**, và các lỗ hổng. **TRUNG THỰC (đọc kỹ):** một ô "detected" nghĩa là cuộc tấn công
*được tiêm* của trình mô phỏng đã kích hoạt kịch bản tại/trên ngưỡng — một **kiểm tra hồi quy + độ phủ
liên-kỹ-thuật + lỗ hổng topology trên thư viện+trình mô phỏng, KHÔNG phải tuyên bố hiệu quả phát hiện ngoài
thực tế** (kịch bản được viết để phát hiện sẽ phát hiện chính emitter của nó). Caveat được mang trong trường
`honesty` của phản hồi và hiển thị dưới dạng banner cố định trên console.

**Tham số truy vấn** (một bộ chọn chính; ưu tiên `scenario_ids` > `tactic` > `os_family` > tất cả):

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `scenario_ids` | `str \| null` | — | Tập con tường minh, phân tách bằng dấu phẩy (id lạ → 422) |
| `tactic` | `str \| null` | — | Mọi kịch bản có `mitre_mappings[].tactic` chứa nó |
| `os_family` | `str \| null` | — | Mọi kịch bản với `os_family` đó (windows/linux/macos) |
| `min_proximity` | `float` | `1.0` | "detected" = proximity ≥ giá trị này (mặc định 1.0 = toàn chuỗi đã kích hoạt) |

**Vai trò yêu cầu:** `viewer`. **Lỗi:** `422` khi `scenario_ids` lạ hoặc phạm vi vượt **giới hạn 50 kịch
bản** (không bao giờ cắt ngầm — vì sẽ làm `% detected` nói dối). Cache LRU theo định nghĩa chuẩn tắc (tất
định → cùng yêu cầu trả về cùng bảng điểm). Chạy nguội toàn thư viện ≈ 1–2s (~40 diễn tập tuần tự); tức thì
khi đã cache.

**Phản hồi `200`:** `{ definition, rows, aggregate, honesty }`. Mỗi `row` =
`{scenario_id, name, tactic, technique, os_family, host, status, detected, proximity, matched_steps,
total_steps, feed_summary, note}` (sắp theo scenario_id). `aggregate` = `{runnable, detected, missed,
no_eligible_host, errors, pct_detected = round(detected/runnable,4), gaps_by_tactic,
no_eligible_host_scenarios}`. **`no_eligible_host`** (kịch bản không có máy chủ topology nào khớp họ OS +
vùng) là lỗ hổng topology — **loại khỏi mẫu số `runnable`/`% detected`**, không bao giờ tính là miss. Chỉ
đọc/bổ sung; chạy hàng loạt `run_drill` (engine không bị đụng); tất định (seed/base-time diễn tập cố định,
không `now`).

#### `GET /api/timeline`

**Dòng thời gian Vụ việc** — chuỗi sự kiện có thứ tự, tất định, của một phát hiện mà nhà phân tích IR dựng
lại bằng tay. Trả về các bước kịch bản đã khớp (từ `matched_steps` của chính phát hiện) đan xen với các sự
kiện ngữ cảnh xung quanh trên (các) máy chủ bị ảnh hưởng, trong một dải thời gian tuyệt đối suy ra từ các
mốc đã khớp. **Chỉ đọc, tất định, engine không bị đụng** (xương sống đã khớp đến từ phát hiện đã cache; sự
kiện ngữ cảnh được đọc lại từ feed qua đường chuẩn hóa — không chạy lại engine).

> **TRUNG THỰC:** dòng thời gian là các sự kiện thật theo đúng thứ tự. Các dòng "context" đơn giản là mọi sự
> kiện đã chuẩn hóa trên (các) máy chủ bị ảnh hưởng trong dải — hiển thị để có nhận thức tình huống, **KHÔNG
> nhất thiết liên quan tới cuộc tấn công**. Chỉ các dòng `matched_step` mới là sự kiện engine gắn với kịch
> bản. (Mang trong trường `honesty_note`.)

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `scenario_id` | `str` | — (bắt buộc) | scenario id của phát hiện |
| `host` | `str \| null` | tất cả host bị ảnh hưởng | Giới hạn một host (phải thuộc `affected_hosts`) |
| `from` / `to` | `str \| null` | dải đã khớp ±300s | Cận ISO tuyệt đối ghi đè cạnh dải tự động |

**Vai trò yêu cầu:** `viewer`. **Lỗi:** `404` `scenario_id` lạ (không có trong thư viện) **hoặc** kịch bản
không tạo phát hiện nào trong feed (không có vụ việc); `422` cận sai/đảo hoặc `host ∉ affected_hosts`. Cache
LRU theo `(scenario_id, host, from, to)`.

**Phản hồi `200`:** `{scenario_id, name, severity, hosts, band: {from, to, pad_seconds: 300}, rows,
matched_count, context_shown, context_total, context_truncated, honesty_note}`. Mỗi `row` =
`{timestamp, host, kind, event_kind, label, step_id, step_name, element_id}`, **sắp xếp toàn phần** theo
`(timestamp, host, event_kind, label, command_line, element_id)` → tính lại giống hệt từng byte. Dải là
`[first_matched − 300s, last_matched + 300s]` (có thể ghi đè). Context **giới hạn 500** (dòng matched không
bao giờ bị cắt); vượt giới hạn → `context_truncated: true` với `context_shown`/`context_total` trung thực
(không bao giờ bỏ ngầm). Một sự kiện matched không bị lặp thành dòng context (dedup theo `(host, timestamp)`).
Frontend tới đây qua deep-link "Xem hồ sơ" của Dashboard.

#### `POST /api/ioc_match`

**Lớp phủ IOC / Threat-Intel** — đối chiếu một watchlist từ bên ngoài với telemetry đã nạp (vòng lặp làm
giàu CTI → SOC). Chỉ đọc, tất định. **Vai trò yêu cầu:** `viewer` + **CSRF** (là POST chỉ vì mang body
danh sách; không thay đổi trạng thái).

> **TRUNG THỰC:** lớp phủ chỉ đánh giá các loại IOC mà telemetry này thực sự mang. **IOC `hash`, `domain`
> và `ip` ĐƯỢC đánh giá**: `hash` đối chiếu file-hash *tổng hợp* suy ra tất định, `domain` (host chính xác,
> không phân biệt hoa thường) đối chiếu domain được truy vấn trong telemetry DNS-query *tổng hợp* (Sysmon EID
> 22), và `ip` (chuỗi v4 chính xác) đối chiếu dest IP trong telemetry kết nối mạng *tổng hợp* (Sysmon EID 3),
> dùng **dải tài liệu RFC 5737** không bao giờ trùng với địa chỉ thực — telemetry DNS + dest-IP tồn tại trên
> **Windows, Linux và macOS** (native trên Windows Sysmon và syscall `connect(2)` của auditd Linux; lớp phủ
> agent/EDR rõ ràng cho DNS Linux và DNS/kết nối macOS), và khớp nghĩa là xác thực pipeline săn lùng, KHÔNG phải mức phổ
> biến thực tế. **IOC `ipv6` và CIDR bị từ chối cứng (`422`)** — luồng tổng hợp chỉ khớp v4 chính xác (hoãn
> lại). IOC `technique` khớp với **thư viện kịch bản + phát hiện**, không phải sự kiện thô (một mục tiêu khác).
> Caveat mang trong `summary.honesty_note`.

**Body** (`extra="forbid"`): `{ "iocs": [ {"type": "...", "value": "..."} ] }`. `type` khớp được ∈
`{process_name (chính xác, không phân biệt hoa thường), image (chuỗi con trên image_loaded/process_path),
command (chuỗi con trên command_line), hash (không phân biệt hoa thường, mọi thuật toán, vs
NormalizedEvent.hashes), domain (chính xác, không phân biệt hoa thường, vs NormalizedEvent.domain), technique
(chính xác, vs mitre của kịch bản), ip (chuỗi v4 chính xác, vs NormalizedEvent.dest_ip)}`. **Lỗi (`422`):**
`iocs` rỗng; `> 256` IOC; loại `ipv6`/`cidr`/lạ (kèm lý do trung thực); value rỗng; trường body thừa.
`matched_field` của một hash hit là tên thuật toán (`sha256`/`md5`); của một domain hit là `domain`; của một
ip hit là `dest_ip`.

**Phản hồi `200`:** `{ summary: {iocs_total, iocs_matched, hosts_touched, honesty_note}, iocs: [...], hosts:
[...] }`. Mỗi `iocs[]` = `{type, value, target: "event"|"scenario", matched, hit_count, hits, truncated}`
(IOC technique còn mang `covered`/`covered_scenarios`). Event hit = `{host, timestamp, label, matched_field,
snippet}` (sắp theo `(timestamp, host, matched_field, snippet)`, giới hạn **200**/IOC với `truncated`/
`hit_count` trung thực); scenario hit = `{scenario_id, name, proximity, affected_hosts}`. `hosts` = bảng
tổng hợp làm giàu từ topology của mọi host chạm ≥1 IOC `{hostname, zone, criticality, ioc_count, types}`
(sắp `(-ioc_count, hostname)`). Chỉ đọc/bổ sung; một lượt đọc feed (tái dùng read+normalize); engine không
bị đụng; tất định (không `now`); không lưu trữ.

#### `POST /api/ioc_extract`

**Trích xuất IOC từ Báo cáo Mối đe dọa** — dán báo cáo CTI / khuyến cáo / email lừa đảo và nhận kết quả
trích xuất chỉ báo **tất định, chỉ dùng regex (không LLM)**, đã được refang và chia thành matchable-tại-đây
vs trích-xuất-cho-công-cụ-khác. Chỉ đọc, không lưu trữ, không chạy engine. **Vai trò yêu cầu:** `viewer` +
**CSRF** (POST vì mang body text; không thay đổi trạng thái). Đây là bước chuẩn bị *trước* `POST /api/ioc_match`;
analyst xem tập matchable, đẩy vào watchlist rồi chạy match như thường.

> **TRUNG THỰC:** trích xuất rộng, đối sánh hẹp. Mọi loại chỉ báo đều được trích xuất, nhưng mỗi chỉ báo
> được phân loại `matchable: true/false` theo telemetry của Augur. **`technique`, `process_name`, `file_path`
> (→ `image`), `md5`/`sha1`/`sha256` (→ `hash`), `domain` (→ `domain`) và `ip` (IPv4 → `ip`)** là matchable
> — chính xác là các type mà `POST /api/ioc_match` chấp nhận (hash, domain và dest IP khớp telemetry
> endpoint/DNS/kết nối đa-OS (Windows/Linux/macOS) tổng hợp dùng dải tài liệu RFC 5737, không phải nguồn reputation). IPv4
> private/reserved bị lọc bỏ (không bao giờ là IOC CTI).
> `ipv6` / URL / email / CVE / registry được trả về trong mảng `unmatchable` riêng, mỗi mục kèm lý do
> verbatim ("IPv6 dest addresses are not yet in the corpus (synthetic stream is v4-only)", "…no registry
> fields", "CVE is context only — not an Augur telemetry field"). Sự phân tách là cấu trúc (hai mảng), không
> bao giờ là cờ im lặng, và các type không matchable không bao giờ được tự động đưa vào matcher. Chỉ hỗ trợ
> dán văn bản thuần.

**Body** (`extra="forbid"`): `{ "text": "<báo cáo dán vào, văn bản thuần>" }`. **Lỗi (`422`):** text rỗng;
text `> 200.000` ký tự; trường body thừa.

**Phản hồi `200`:** `{ summary, matchable: [...], unmatchable: [...] }`.
`summary = {extracted_total, matchable_count, unmatchable_count, truncated, honesty_note}` (`truncated` là
true khi tổng dedup vượt giới hạn **256** IOC). Mỗi chỉ báo = `{type, value (luôn là dạng đã refang/live),
category, confidence ("high"|"medium" — nhãn tin cậy theo loại pattern, không phải điểm danh tiếng), matchable}`
với `defanged_from` tùy chọn (provenance khi refang thay đổi giá trị) và, trên các mục `unmatchable`, trường
`reason`. Các type được trích xuất: `ipv4` (nhận dạng defanged; bỏ private/reserved; ánh xạ thành matchable `ip`), `ipv6`, `domain`
(danh sách TLD cho phép), `url` (`hxxp`→`http`), `email`, `md5`/`sha1`/`sha256` (loại FP ký tự đồng nhất),
`cve`, `technique` (`T####[.###]`/`TA####`), `process_name` (danh sách extension cho phép), `file_path`
(thư mục gốc Win/Unix có neo; ánh xạ thành `image`), `registry_key`. Dedup `(type, value.casefold())`; đầu
ra sắp theo `(type, value)`. Regex thuần + refang; tất định; không `now()`, không ngẫu nhiên, không LLM;
engine không bị đụng.

#### `GET /api/pivot_graph`

**Đồ thị Pivot Điều tra** — vùng lân cận k-bước giới hạn của một phát hiện, được kết xuất dưới dạng đồ
thị node-link tĩnh để điều tra viên SOC thực hiện thao tác pivot. Khởi tạo từ `matched_steps` của phát
hiện (giải quyết `element_id` hành vi tổng hợp `|EXH|` về process sở hữu), mở rộng BFS đến độ sâu `hops`,
và trả về đồ thị con Host/Process/File đầy đủ được làm giàu criticality từ topology. **Chỉ đọc, tất định,
engine không bị đụng** (không chạy lại engine; dùng public detection dict + đồ thị kiến thức được xây một
lần từ feed tĩnh lúc khởi động).

**Quy tắc hàng xóm BFS:** Node Process và File mở rộng theo cả hai chiều (`edges_from + edges_to`). **Node
Host là ngữ cảnh kết thúc (terminal)** — chỉ `edges_from(host)` được theo; `edges_to(host)` (tức là các
process cùng host qua RUNS_ON) **không** được mở rộng. Điều này ngăn danh sách process đầy đủ của một host
bận tiêu hết ngân sách `MAX_NODES` trước khi các node nhân quả quan trọng của seed (process con được spawn,
module được load) được khám phá. Host của seed luôn được đưa vào kết quả; nhấp vào node host để pivot vào
danh sách process đầy đủ của nó.

> **TRUNG THỰC:** các cạnh là quan hệ nhân quả nội-host — spawn tiến trình (`SPAWNED`), nạp module
> (`LOADED`), hành vi biểu hiện (`EXHIBITED`), thành viên host (`RUNS_ON`). Chúng **KHÔNG phải khả năng
> tiếp cận mạng hay bằng chứng di chuyển ngang**: topology không mang adjacency giữa các host và mọi quan
> hệ hiển thị đều cùng host. Các hàng xóm mở rộng được lấy từ đồ thị kiến thức đầy đủ cho ngữ cảnh,
> không chỉ từ phát hiện đã khớp. (Mang trong `summary.honesty_note`.)

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `detection` | `str` | — (bắt buộc) | `scenario_id` của phát hiện để khởi tạo (cùng khóa như `/api/timeline`) |
| `hops` | `int` | `2` | Độ sâu mở rộng BFS — kẹp vào `1..3`; giá trị ngoài khoảng bị kẹp, không bao giờ `422` |

**Vai trò yêu cầu:** `viewer`. **Lỗi:** `401`/`403` chưa xác thực hoặc không đủ vai trò; `404` `detection`
lạ (không phải `scenario_id` đã biết hoặc kịch bản không tạo phát hiện trong feed); `422` seed không giải
quyết được (tất cả `element_id` trong `matched_steps` giải quyết thành node đồ thị không tồn tại — trường
hợp ngoại lệ tính toàn vẹn dữ liệu, không phải tham số không hợp lệ). Cache LRU theo `(scenario_id, hops)`.

**Phản hồi `200`:**

```jsonc
{
  "seed": {
    "scenario_id": "SCEN-WIN-001",
    "name": "Pass-the-Hash",
    "severity": "CRITICAL",
    "seed_node_ids": ["p1"],          // id node đồ thị đã giải quyết (sau khi xử lý |EXH|)
    "affected_hosts": ["WS-FIN-07"]
  },
  "nodes": [
    {
      "id": "p1",
      "node_type": "Process",          // "Host" | "Process" | "File"
      "label": "evil.exe",             // tên host | tên process | tên file
      "host": "WS-FIN-07",
      "criticality": "HIGH",           // giá trị topology.enrich; "UNKNOWN" nếu host ngoài topology
      "zone": "User_Endpoint",         // giá trị topology.enrich; "Unknown" nếu host ngoài topology
      "seed": true,                    // node này có phải là node matched-step không?
      "hop": 0,                        // 0 = seed; độ sâu BFS cho các node khác
      // Trường chỉ của Process:
      "name": "evil.exe",
      "command": "evil.exe --inject",
      "integrity_level": "High",
      // Trường chỉ của File:
      "path": "C:\\Windows\\x.dll",
      "is_signed": false,
      "is_injected": true,
      "extension": ".dll"
    }
  ],
  "edges": [
    {
      "id": "p1->ws-fin-07:RUNS_ON:2026-...",  // id ổn định duy nhất: "{src}->{dst}:{edge_type}:{ts}"
      "src": "p1",
      "dst": "ws-fin-07",
      "edge_type": "RUNS_ON",           // "SPAWNED" | "LOADED" | "EXHIBITED" | "RUNS_ON"
      "timestamp": "2026-05-01T10:00:00+00:00",
      "is_injected": true               // chỉ cạnh LOADED; boolean từ attrs cạnh
    }
  ],
  "summary": {
    "node_count": 5,
    "edge_count": 4,
    "nodes_total": 5,                   // phát hiện trước giới hạn (số lượng trung thực trước cắt)
    "edges_total": 4,
    "nodes_truncated": false,           // true khi > MAX_NODES (300) được phát hiện
    "edges_truncated": false,           // true khi > MAX_EDGES (600) được phát hiện
    "hops": 2,
    "honesty_note": "Edges are host-local causal relationships..."
  }
}
```

- **Nodes** sắp theo `(hop, node_type, id)`; **edges** sắp theo `(timestamp, edge_type, src, dst)` — tính lại giống hệt từng byte (Bất biến 1).
- **Giới hạn:** `MAX_NODES = 300`, `MAX_EDGES = 600`; cạnh chỉ được phát nếu cả hai endpoint đều trong tập node giữ lại. Cắt đặt `nodes_truncated`/`edges_truncated` và báo cáo `nodes_total`/`edges_total` trung thực.
- **`is_injected`** chỉ xuất hiện trên cạnh `LOADED` (từ attrs cạnh); vắng trên tất cả loại cạnh khác.
- Frontend tới đây qua deep-link "Pivot" của Dashboard (`/pivot?detection=<scenario_id>`).

#### `GET /api/rarity` — Độ hiếm / xếp chồng tần suất (viewer)

Phân tích tần suất xuất hiện thấp nhất ("xếp chồng") xác định trên toàn bộ corpus đã nạp. Đếm thuần túy —
không có engine, không có scoring, không có `now()`, không có ML. **Giá trị hiếm là MANH MỐI để triage,
không phải phát hiện hay kết luận.**

**Tham số truy vấn**

| Tham số | Kiểu | Mặc định | Ghi chú |
|---|---|---|---|
| `dimension` | `str` | `process` | `process` (tệp thực thi hiếm) · `parent_child` (quan hệ hiếm `cha → con`) · `host_binary` (phân bố bất thường — tệp xuất hiện trên ít máy nhất). Giá trị không hợp lệ → **422**. |
| `max_count` | `int` | `5` | Chỉ trả về bucket có `occurrences ≤ max_count`. Kẹp vào `[1, 50]` — không bao giờ 422. |
| `limit` | `int` | `100` | N hàng hiếm nhất sau ngưỡng. Kẹp vào `[1, 500]` — không bao giờ 422. |

**Vai trò yêu cầu:** `viewer` (GET chỉ đọc; không cần CSRF).

**Chỉ đếm — không bao giờ là điểm tổng hợp.** Chỉ hoạt động trên sự kiện `process_create`. Bucket là
`process_name` viết thường (process), cặp `(cha, con)` (parent_child), hoặc tên tệp nhị phân theo số máy
(host_binary). Với `process`/`parent_child`: xếp hạng hiếm nhất trước (tăng dần `occurrences`, rồi
`host_count`, rồi `value`); với `host_binary`: xếp hạng ít máy nhất trước (tăng dần `host_count`, rồi
`occurrences`, rồi `value`). Thứ tự hoàn toàn xác định. `first_seen`/`last_seen` là min/max thời gian
**trong corpus này** — lần đầu trong dữ liệu này, không phải lần đầu tiên từng có.

**Phản hồi lỗi:**
- `401 Unauthorized` — chưa xác thực.
- `422 Unprocessable Entity` — giá trị `dimension` không hợp lệ (các lỗi tham số khác được kẹp, không bị từ chối).

**Phản hồi `200`:**

```jsonc
{
  "dimension": "parent_child",
  "params": { "max_count": 5, "limit": 100 },
  "summary": {
    "total_values": 412,
    "rare_values": 87,
    "returned": 87,
    "truncated": false,
    "honesty_note": "Rarity is a LEAD for triage, not a detection or verdict. Most rare activity is benign …"
  },
  "rows": [
    {
      "value": "winword.exe → rundll32.exe",
      "occurrences": 1,
      "host_count": 1,
      "single_host": true,
      "unique": true,
      "first_seen": "2026-05-01T10:00:00+00:00",
      "last_seen":  "2026-05-01T10:00:00+00:00",
      "hosts": [
        { "hostname": "FIN-CFO-PC", "zone": "Finance", "criticality": "CRITICAL", "count": 1 }
      ],
      "hosts_truncated": false,
      "samples": [
        { "host": "FIN-CFO-PC", "timestamp": "2026-05-01T10:00:00+00:00", "command": "rundll32.exe …" }
      ],
      "samples_truncated": false
    }
  ]
}
```

| Trường phản hồi | Kiểu | Mô tả |
|---|---|---|
| `dimension` | `str` | Dimension đã gửi lại |
| `params` | `object` | `max_count` + `limit` sau khi kẹp |
| `summary.total_values` | `int` | Tổng bucket khác biệt trong corpus (trước lọc ngưỡng) |
| `summary.rare_values` | `int` | Bucket có `occurrences ≤ max_count` |
| `summary.returned` | `int` | Hàng thực sự trả về (≤ `limit`) |
| `summary.truncated` | `bool` | `true` khi `rare_values > returned` — đuôi dài hơn `limit` |
| `summary.honesty_note` | `str` | Lưu ý trung thực, hiển thị trong bảng điều khiển trên trang console |
| `rows[].value` | `str` | Khóa hiển thị: tên tệp nhị phân viết thường, hoặc chuỗi `"cha → con"` |
| `rows[].occurrences` | `int` | Tổng số sự kiện cho bucket này |
| `rows[].host_count` | `int` | Số máy khác biệt bucket xuất hiện |
| `rows[].single_host` | `bool` | `host_count == 1` |
| `rows[].unique` | `bool` | `occurrences == 1` |
| `rows[].first_seen` | `str` | ISO 8601 thời gian sự kiện sớm nhất trong corpus |
| `rows[].last_seen` | `str` | ISO 8601 thời gian sự kiện muộn nhất trong corpus |
| `rows[].hosts` | `list` | Tối đa 25 máy, sắp theo số lần đếm per-host giảm dần rồi tên máy; mỗi mục `{hostname, zone, criticality, count}` |
| `rows[].hosts_truncated` | `bool` | `true` khi có hơn 25 máy; các đếm (`host_count`) vẫn chính xác |
| `rows[].samples` | `list` | Tối đa 5 sự kiện mẫu sắp theo `(timestamp, host)`: mỗi mục `{host, timestamp, command}` |
| `rows[].samples_truncated` | `bool` | `true` khi bucket có hơn 5 mẫu |

**Lưu ý trung thực (ghi trong `summary.honesty_note` và hiển thị như bảng điều khiển cố định trên trang
`/stack`):** Độ hiếm là MANH MỐI để triage, không phải phát hiện hay kết luận. Phần lớn hoạt động hiếm là
lành tính — công cụ quản trị, cài đặt một lần, một script hợp lệ. Những hàng này là điểm khởi đầu cho một
cuộc săn, không phải phát hiện. Các đếm chỉ tính trong corpus này: "lần đầu thấy" nghĩa là lần đầu trong
dữ liệu này, không phải lần đầu tiên từng có. Giá trị hiếm trên máy CRITICAL là manh mối mạnh hơn nhưng
vẫn cần con người xem xét. Không có scoring, không có ML, không có xác suất — chỉ là đếm số lần xuất hiện.

Cờ `*_truncated` tiết lộ nơi danh sách máy hoặc mẫu bị kẹp trong khi giữ đếm tổng hợp chính xác. LRU-cached
theo `(dimension, max_count, limit)`. Engine không bị chạm; xác định; không có `now()`, không ngẫu nhiên.

Frontend tới đây qua mục điều hướng Investigate dưới dạng trang `/stack` (Xếp chồng).

#### `GET /api/detection_health`

Tình trạng kích hoạt theo từng kịch bản trên tập dữ liệu đã nạp. Vai trò: `viewer`. Tất định, chỉ đọc,
chỉ dùng giờ trong tập dữ liệu.

Mỗi kịch bản: `state` (`FIRING` / `PARTIAL` / `SILENT` / `NEVER`), `max_proximity`, `fire_count` (số ảnh
chụp cửa sổ tăng dần mà kịch bản đạt độ gần bất kỳ), `last_fired` (mốc thời gian trong tập dữ liệu hoặc
`null`), `affected_host_count`, cùng tổng hợp `summary.by_state` và `summary.corpus_span`.

**Trung thực:** `SILENT`/`NEVER` nghĩa là kịch bản không kích hoạt trong tập dữ liệu NÀY — KHÔNG phải phát
hiện bị hỏng trong môi trường thật. `last_fired` là mốc thời gian trong tập dữ liệu, không phải thời gian
thực. Fire-count là tín hiệu sống còn, không phải số lượng cảnh báo. Lời cảnh báo nguyên văn nằm trong
`summary.honesty_note`.

#### `GET /api/scenarios`

Liệt kê tất cả các kịch bản đã nạp.

**Vai trò yêu cầu:** `viewer`

**Phản hồi `200`** — mảng:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | ví dụ: `"SCEN-WIN-001"` |
| `name` | `str` | Tên kịch bản |
| `severity` | `str` | Giá trị severity |
| `steps` | `int` | Tổng số bước |
| `os_family` | `str` | Họ HĐH mục tiêu — `windows` / `linux` / `macos` (từ `scenario_metadata.os_family`) |
| `applicable_zones` | `list[str]` | Các vùng mà kịch bản có thể kích hoạt (cổng không gian, từ `spatial_constraints.applicable_zones`) |
| `mitre` | `list` | Mảng các đối tượng `{tactic, technique}` |

> `os_family` và `applicable_zones` là các trường **bổ sung** (các khóa hiện có không đổi). Trang Diễn tập
> Đội Tím dùng chúng để lọc danh sách máy chủ `<select>` xuống các tài sản có họ HĐH khớp **và** có `zone` ∈
> `applicable_zones`, nên người dùng chỉ được cung cấp những máy chủ thực sự sẽ kích hoạt.

#### `GET /api/scenarios/{id}`

Trả về toàn bộ siêu dữ liệu **và nội dung các bước** của một kịch bản đơn. Chỉ đọc và mang tính xác định —
đọc thuần từ danh sách kịch bản trong closure; không chạy engine, graph, tính điểm, lưu trữ, `now()`, hay
ngẫu nhiên.

**Vai trò yêu cầu:** `viewer`.

**Tham số đường dẫn:**

| Tham số | Kiểu | Mô tả |
|---|---|---|
| `id` | `str` | ID kịch bản, ví dụ `"SCEN-WIN-001"` |

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | ví dụ: `"SCEN-WIN-001"` |
| `name` | `str` | Tên kịch bản |
| `severity` | `str` | Giá trị severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) |
| `os_family` | `str` | Họ HĐH mục tiêu — `windows` / `linux` / `macos` |
| `applicable_zones` | `list[str]` | Các vùng có thể kích hoạt (từ `spatial_constraints.applicable_zones`) |
| `mitre` | `list` | Mảng các đối tượng `{tactic, technique}` (từ `scenario_metadata.mitre_mappings`) |
| `step_count` | `int` | Tổng số bước phát hiện (số nguyên) |
| `steps` | `list` | Mảng nội dung bước đầy đủ (xem dạng bên dưới) — **khác với trường `steps` là số nguyên của endpoint danh sách** |

Mỗi mục trong `steps`:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `step_id` | `int` | Chỉ số bước bắt đầu từ 1; liên tiếp `1..step_count` |
| `name` | `str` | Tên bước |
| `temporal_link` | `object \| null` | `null` với bước 1; `{ previous_step, min_time_delta_seconds, max_time_delta_seconds, link_scope }` với các bước sau |
| `matching_criteria` | `object` | Dict tiêu chí khớp thô của bước này (engine dùng để đánh giá ứng viên) |

**Lỗi:**

- `401` — chưa xác thực.
- `404` — `id` không khớp với bất kỳ kịch bản nào đã nạp.

#### `GET /api/scenarios/{id}/sigma`

Tạo **quy tắc phát hiện Sigma trung lập với nhà cung cấp** từ các bước của kịch bản — một quy tắc **cho
mỗi bước**. Chỉ đọc, biến đổi thuần từ schema kịch bản (không engine, không tính điểm, không lưu trữ,
không `now()`, không ngẫu nhiên).

> **Lưu ý trung thực:** một quy tắc Sigma phẳng là một lựa chọn sự kiện đơn. Nó **không thể** biểu diễn
> tương quan thời gian giữa các bước (`link_scope`/time-delta) hoặc kiểm soát vùng không gian
> (`applicable_zones`, được giải quyết bởi topology Augur) của Augur. Mỗi quy tắc do đó chỉ khớp **một
> bước kỹ thuật riêng lẻ** — một khối xây dựng hunting/alerting, **không phải** là bản tái tạo 1:1 của
> chuỗi kịch bản Augur đã được xác thực. Các bước không có trường Sigma-biểu diễn được sẽ phát ra quy
> tắc không kích hoạt `status: unsupported` (lựa chọn sentinel không bao giờ khớp) thay vì quy tắc
> luôn-đúng nguy hiểm. Ghi chú trung thực này có trong `description` + mục `falsepositives` của mỗi
> quy tắc, comment header YAML, và trường `honesty_note` trong phản hồi.

Chuyển đổi Sigma sang phương ngữ SIEM thực tế bằng [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli),
ví dụ `sigma convert -t splunk` / `-t microsoft_xdr` / `-t elasticsearch`.

**Vai trò yêu cầu:** `viewer`.

**Tham số đường dẫn:**

| Tham số | Kiểu | Mô tả |
|---|---|---|
| `id` | `str` | ID kịch bản, ví dụ `"SCEN-WIN-001"` |

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `format` | `str` | `json` | `json` → body có cấu trúc (bên dưới); `yaml` → body `text/yaml` thô dạng multi-doc |

**Phản hồi `200` (`format=json`):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | ví dụ: `"SCEN-WIN-001"` |
| `rules` | `list` | Một dict quy tắc Sigma cho mỗi bước (theo thứ tự bước) |
| `yaml` | `str` | YAML multi-doc (comment header đầu tiên) — blob tải xuống |
| `honesty_note` | `str` | Lưu ý trung thực từng bước nguyên văn |

`?format=yaml` trả về cùng YAML multi-doc dưới dạng body `text/yaml` thô (phù hợp để dùng với
`curl … | sigma convert`).

**Lỗi:** `401` chưa xác thực · `404` `id` không tồn tại.

**Tương đương CLI:** `python -m augur.sigma --scenario <ID>` (stdout) hoặc `--out <DIR>` (một `.yml` mỗi bước).

---

#### `GET /api/sigma_pack`

Xuất **toàn bộ thư viện kịch bản** thành một tệp Sigma multi-doc. Mang tính xác định: thứ tự nạp kịch
bản, sau đó thứ tự bước trong mỗi kịch bản. Lưu ý trung thực tương tự như route từng kịch bản áp dụng
cho mọi quy tắc.

**Vai trò yêu cầu:** `viewer`.

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `format` | `str` | `yaml` | `yaml` → tệp đính kèm `text/yaml` (`augur-sigma-pack.yml`); `json` → `{rule_count, scenario_count, yaml, honesty_note}` |

**Phản hồi `200` (`format=yaml`):** tệp đính kèm `text/yaml` (`Content-Disposition: attachment; filename=augur-sigma-pack.yml`) chứa tất cả các quy tắc dưới dạng luồng YAML multi-doc.

**Phản hồi `200` (`format=json`):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `rule_count` | `int` | Tổng số quy tắc (Σ `step_count` trên tất cả kịch bản) |
| `scenario_count` | `int` | Số kịch bản trong thư viện |
| `yaml` | `str` | Cùng blob YAML multi-doc |
| `honesty_note` | `str` | Lưu ý trung thực từng bước nguyên văn |

**Tương đương CLI:** `python -m augur.sigma` (tất cả kịch bản → stdout) hoặc `--out <DIR>` (một `.yml` mỗi quy tắc).

**Lỗi:** `401` chưa xác thực.

---

#### `GET /api/topology`

Trả về thông tin zone và asset từ tầng topology.

**Vai trò yêu cầu:** `viewer`

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `zones` | `list[str]` | Tất cả các giá trị enum Zone có trong topology |
| `assets` | `list` | Các đối tượng asset được tuần tự hóa từ `topology.assets` |

#### `GET /api/coverage_gaps`

Trả về ma trận lỗ hổng phạm vi **chiến thuật × họ hệ điều hành**, cho thấy theo từng họ hệ điều hành đã
triển khai, kịch bản nào trong 14 chiến thuật ATT&CK mà thư viện kịch bản chưa có độ phủ. Chỉ đọc và mang
tính xác định — nó tái sử dụng scenarios + topology đã tải, không chạy engine và không lưu trữ gì.

**Vai trò yêu cầu:** `viewer`

**Tham số:** không có (ngoài xác thực).

**Loại trừ Cloud:** các cột là các họ hệ điều hành có trong topology giao với `{windows, linux, macos}`.
Tài sản Cloud/SaaS cố tình **không tạo ra cột Cloud** — các kịch bản mô phỏng đám mây mang `os_family` là
`windows`/`linux` (chúng xấp xỉ đám mây qua telemetry điểm cuối), nên một cột cloud theo nghĩa đen sẽ luôn
hiển thị 14/14 lỗ hổng và làm sai lệch thiết kế.

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `tactics` | `list[{id,name}]` | 14 chiến thuật ATT&CK theo thứ tự chuẩn |
| `os_families` | `list[str]` | Các họ cột có trong topology ∩ `{windows,linux,macos}` |
| `cells` | `object` | `{ "TAxxxx": { "<family>": { "covered": bool, "count": int } } }` — `covered` đúng khi ≥1 kịch bản của họ đó liệt kê chiến thuật; `count` là số kịch bản bao phủ |
| `summary` | `object` | `{ os_families, total_cells, covered_cells, gap_cells, coverage_pct }` trên lưới 14×N (`coverage_pct = round(covered_cells/total_cells, 4)`) |

#### `GET /api/navigator_layer`

Tuần tự hóa độ phủ kịch bản hiện tại hoặc các phát hiện trực tiếp thành một **lớp MITRE ATT&CK Navigator**
(schema **v4.5**) — một tài liệu JSON mà [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
chính thức và các công cụ tương thích mở trực tiếp. Chỉ đọc và mang tính xác định — nó tái sử dụng scenarios
đã tải (và, với `detections`, đúng đường dẫn chọn nguồn/cửa sổ thời gian của `/api/detections`), không tự
chạy engine và không lưu trữ gì.

**Vai trò yêu cầu:** `viewer`

**Tham số:**

| Tham số | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `type` | `str` | `coverage` | `coverage` hoặc `detections`; giá trị khác → `422` |
| `min_proximity` | `float` | `0.30` | (chỉ `detections`) proximity tối thiểu để một phát hiện đóng góp |
| `from` | `str` | – | (chỉ `detections`) cận dưới ISO bao gồm; chạy lại engine theo cửa sổ phía máy chủ |
| `to` | `str` | – | (chỉ `detections`) cận trên ISO bao gồm; cận không phân tích được hoặc đảo ngược → `422` |

Với `type=detections`, việc chọn nguồn giống hệt `/api/detections`: nếu không có `from`/`to` thì dùng tập
phát hiện đã tính sẵn; ngược lại cửa sổ `[from, to]` được chạy lại và cache, rồi lọc theo `min_proximity`.

**Loại lớp & thang điểm:**

- `coverage` — một kỹ thuật cho mỗi cặp `(tactic, technique)` mà bất kỳ kịch bản nào ánh xạ tới;
  **score = 100** (nhị phân "được thư viện bao phủ"). `comment` liệt kê các ID kịch bản bao phủ.
- `detections` — chỉ các kỹ thuật đạt được bởi một phát hiện đã kích hoạt; **score = `round(maxProximity × 100)`**
  (0–100), lấy proximity lớn nhất trên các phát hiện ánh xạ tới cặp đó.

Các kỹ thuật được khử trùng lặp theo cặp `(tactic, technique)` và sắp xếp theo `(tactic, techniqueID)`, nên
kết quả ổn định từng byte qua các yêu cầu giống nhau. ID kỹ thuật con (`Txxxx.xxx`) được phát ra nguyên dạng.
Một phát hiện có `scenario_id` không còn phân giải được, hoặc một tactic ngoài bản đồ 14 shortname, sẽ bị bỏ
qua một cách phòng vệ.

**Phản hồi `200`:** một đối tượng lớp Navigator v4.5:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `name` | `str` | `Augur — Coverage <ngày>` / `Augur — Detections <ngày>` |
| `versions` | `object` | `{ "attack": "15", "navigator": "4.9.0", "layer": "4.5" }` |
| `domain` | `str` | `enterprise-attack` |
| `description` | `str` | Ghi chú xuất dễ đọc |
| `techniques` | `list[{techniqueID, tactic, score, comment, enabled}]` | Một mục cho mỗi cặp `(tactic, technique)`; `tactic` là shortname Navigator; `score` theo thang ở trên |
| `gradient` | `object` | `{ colors, minValue: 0, maxValue: 100 }` |
| `legendItems` | `list` | Các mục chú giải (coverage vs. dải proximity) |
| `sorting` | `int` | `0` |
| `hideDisabled` | `bool` | `false` |

#### `GET /api/metrics`

Trả về các chỉ số đánh giá nền tảng (độ phủ MITRE, tỷ lệ FP, khả năng phát hiện theo kịch bản).

**Vai trò yêu cầu:** `admin`

**Phản hồi `200`:** đối tượng metrics (hình dạng phụ thuộc vào `augur.api.metrics_endpoint.platform_metrics`).

#### `POST /api/drill`

**Diễn tập Đội Tím.** Tổng hợp một luồng sự kiện nền lành tính với kịch bản tấn công đã chọn được tiêm vào
máy chủ đã chọn, chạy **engine chỉ-đọc** chuẩn trên đó, và trả về kết quả phát hiện — biến tuyên bố "chúng tôi
có thể phát hiện điều này" thành một phát hiện *có thể chứng minh*.

Diễn tập có tính **xác định** (cố định `seed=1337` + thời gian gốc cố định `2026-01-01T09:00:00Z`, không bao
giờ dùng đồng hồ thực), tổng hợp một `MachineProfile` một-máy-chủ từ tài sản topology, và **không lưu trữ gì** —
bộ tiền-tính `/api/detections` trực tiếp không bao giờ bị đọc hay thay đổi và đường dẫn chấm điểm chạy không đổi.

**Vai trò yêu cầu:** `analyst` — **bắt buộc CSRF** (`X-CSRF-Token`).

**Thân yêu cầu:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | Kịch bản cần tiêm, ví dụ `"SCEN-WIN-001"` |
| `host` | `str` | Máy chủ mục tiêu (hostname trong topology), ví dụ `"HR_User_PC"` |

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `detection` | `object \| null` | Dict phát hiện công khai (cùng hình dạng với các hàng `/api/detections`) cho kịch bản đã tiêm, hoặc `null` nếu không kích hoạt |
| `feed_summary` | `object` | `{ total_events, baseline_events, injected_events }` — số đếm của luồng đã tổng hợp |
| `scenario_id` | `str` | Lặp lại kịch bản đã yêu cầu |
| `host` | `str` | Lặp lại máy chủ đã yêu cầu |

**Lỗi:**

- `403` — vai trò thấp hơn `analyst`, hoặc thiếu/sai token CSRF.
- `422` — diễn tập không thể kích hoạt và lý do được trả về trong `detail`:
  - **máy chủ không xác định** — `host` không có trong topology;
  - **kịch bản không xác định** — `scenario_id` chưa được nạp;
  - **lệch HĐH** — `os_family` của kịch bản không khớp HĐH của máy chủ;
  - **sai vùng** — `zone` của máy chủ không nằm trong `applicable_zones` của kịch bản (cổng không gian).

  Giao diện Diễn tập lọc danh sách máy chủ `<select>` theo họ HĐH **và** `applicable_zones` để tránh các lỗi
  này, nhưng `422` phía máy chủ vẫn là phương án dự phòng.

---

### Sổ Tay Ứng Phó — `/api/playbook`, `/api/dispatch`

Mỗi phát hiện có thể đi kèm một sổ tay chuẩn **ngăn chặn / loại bỏ / khôi phục / xác minh**
(`GET /api/playbook`) cùng một nút **Gửi đi** một chạm (`POST /api/dispatch`) gửi phát hiện *thật* qua các
Sink connector hiện có. Cả hai đều **bổ sung và chỉ-đọc** đối với đường tính điểm — `/api/detections` không
thay đổi và engine không bao giờ được chạy lại.

#### `GET /api/playbook`

Trả về sổ tay ứng phó chuẩn suy ra từ chiến thuật và mức độ nghiêm trọng của một kịch bản.

> **Lưu ý trung thực.** Sổ tay là một **mẫu chuẩn**, không phải nội dung ứng phó sự cố được biên soạn riêng
> cho từng kịch bản. Nó được suy ra từ chiến thuật ATT&CK có **TA-id thấp nhất** (chiến thuật chủ đạo có
> tính tất định) và `severity` của kịch bản — kịch bản `HIGH`/`CRITICAL` thêm một dòng leo thang vào
> `contain`. Phần `validate` chính là `validation_queries` của kịch bản.

**Vai trò yêu cầu:** `viewer`.

**Tham số truy vấn:**

| Tham số | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | Kịch bản để suy ra sổ tay, ví dụ `"SCEN-WIN-001"` |

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | Lặp lại kịch bản được yêu cầu |
| `derived_from` | `object` | `{ tactic, tactic_name, severity }` — chiến thuật chủ đạo (TA-id thấp nhất) và mức độ nghiêm trọng mà mẫu được suy ra |
| `label` | `str` | `"Standard playbook — <tên chiến thuật>"` |
| `sections` | `object` | `{ contain: str[], eradicate: str[], recover: str[], validate: HuntingQuery[] }` — `validate` phản chiếu `validation_queries` của kịch bản (`{ engine, query?, query_path? }`) |

**Lỗi:**

- `401` — chưa xác thực.
- `404` — `scenario_id` không được nạp.

#### `GET /api/incident_response`

Trả về kế hoạch ứng phó **tiêu chuẩn** hợp nhất cho mỗi sự cố đã được nhóm — runbook khống
chế / loại bỏ / khôi phục / kiểm chứng đã hợp nhất và khử trùng lặp trên các kịch bản thành viên
của từng sự cố, giới hạn theo các host của sự cố, kèm nguồn gốc theo từng hành động
(`from_scenarios`) và các chiến thuật chủ đạo. Vai trò viewer. LRU singleton (làm mới khi khởi
động lại). Chỉ đọc: một phép gập thuần trên kết quả đã cache của `/api/incidents` và
`response/playbook.py::build_playbook`; không chạy engine.

**Cam kết trung thực:** kế hoạch là HỢP của các runbook mẫu TIÊU CHUẨN dẫn xuất theo chiến thuật —
đúng bằng playbook tiêu chuẩn theo từng kịch bản, đã hợp nhất và khử trùng lặp. Đây KHÔNG phải kế
hoạch ứng phó sự cố riêng biệt, KHÔNG phải quy kết nhân quả, và KHÔNG phải bảo đảm khống chế.
Host/zone/độ trọng yếu lấy từ topology có thẩm quyền trên kho dữ liệu này.

Cấu trúc phản hồi: `{ "responses": [ { "incident_id", "top_severity", "member_count",
"driving_tactics": [{"tactic", "tactic_name"}], "hosts": [{"hostname", "zone", "criticality"}],
"sections": { "contain"|"eradicate"|"recover": [{"action", "from_scenarios"}],
"validate": [{"engine", "query", "query_path", "from_scenarios"}] }, "unresolved_scenarios", "note",
"honesty_note" } ], "honesty_note" }`.

#### `GET /api/incident_report/{incident_id}`

Trả về một **báo cáo sau sự cố** xác định cho một sự cố đã gom cụm — một tài liệu bàn giao duy nhất
kết hợp tương quan sự cố và phản ứng hợp nhất của nó. Vai trò viewer, chỉ đọc. Là một phép gấp thuần
trên CÙNG payload đã cache của `/api/incidents` và `/api/incident_response` (không bao giờ gom cụm lại
hay gấp lại runbook); LRU thừa hưởng từ hai singleton đã cache đó. `incident_id` không tồn tại → `404`.
Đăng ký trước SPA catch-all.

Hai biểu diễn từ một builder:
- **JSON** (mặc định) — `{ "incident_id", "header": { "top_severity", "max_proximity", "score",
  "member_count", "host_count", "technique_count", "first_ts", "last_ts", "relations",
  "members_truncated" }, "affected_assets", "techniques", "detection_summary",
  "response": { …mục /api/incident_response đầy đủ, nhúng nguyên văn… },
  "source_notes": {"incident","response"}, "honesty_note", "markdown" }`. Mọi trường được CHỌN từ hai
  payload thượng nguồn — không tính toán lại, không `now()`.
- **Markdown** (`?format=markdown`) — `PlainTextResponse` với `Content-Type: text/markdown` và
  `Content-Disposition: attachment; filename=augur-incident-{incident_id}.md`. Giống hệt theo byte với
  trường `markdown` của thân JSON. Thứ tự mục ổn định; dòng "(N trên M thành viên được hiển thị)" trung
  thực khi thành viên bị cắt; chân trang trung thực dẫn cả hai ghi chú thượng nguồn nguyên văn.

**Cam kết trung thực:** báo cáo là một phép LẮP GHÉP xác định của một tương quan engine và các mẫu
tiêu chuẩn dẫn xuất từ chiến thuật trên corpus NÀY. Nó KHÔNG phải là một chiến dịch đối thủ đã xác nhận,
KHÔNG phải quy kết nhân quả, KHÔNG phải kế hoạch ứng phó sự cố tùy chỉnh, và KHÔNG phải bảo đảm ngăn chặn.
Mọi dòng đều truy vết được tới một phát hiện, một sự kiện topology, hoặc một playbook tiêu chuẩn — không
có tường thuật nào được bịa ra. Dấu thời gian là thời gian corpus (lặp lại); báo cáo không mang dấu
thời điểm tạo `now()`.

#### `POST /api/dispatch`

Gửi phát hiện công khai **thật** của một kịch bản qua một Sink connector, khép kín vòng từ săn lùng đến ứng
phó.

> **Không cần hạ tầng theo mặc định.** Chỉ `preview` (mặc định), `stdout` và `jsonl` có thể chọn mà không cần
> cấu hình quản trị và không bao giờ cần mạng. `preview` **không gọi mạng** — nó trả về nguyên văn dict phát
> hiện công khai đã lưu. `stdout`/`jsonl` phát qua các sink connector; đường ghi `jsonl` do **máy chủ chọn**
> (không bao giờ đọc từ thân yêu cầu). Bất kỳ tên sink nào khác (`webhook`, `slack`, `jira`, `xsoar`, …) chỉ
> phân giải từ cấu hình `AlertConfigStore` của quản trị viên đã lưu và trả về `422` nếu tên không xác định
> hoặc chưa cấu hình — một sink mạng trực tiếp không bao giờ được điều khiển từ URL/kwargs do yêu cầu cung cấp.

**Vai trò yêu cầu:** `analyst` — **yêu cầu CSRF** (`X-CSRF-Token`). Thân nghiêm ngặt (`extra="forbid"`).

**Thân yêu cầu:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `scenario_id` | `str` | Kịch bản có phát hiện đã lưu để gửi, ví dụ `"SCEN-WIN-001"` |
| `sink` | `str` | Tên sink; mặc định `"preview"`. `preview`/`stdout`/`jsonl` không cần cấu hình; tên khác phải được cấu hình trong `AlertConfigStore` |

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `ok` | `bool` | Luôn `true` khi thành công |
| `sink` | `str` | Lặp lại sink đã phân giải |
| `payload` | `object` | Dict phát hiện công khai đã lưu (cùng dạng với các hàng `/api/detections`) đã được gửi |

**Lỗi:**

- `403` — vai trò dưới `analyst`, hoặc thiếu/sai token CSRF.
- `404` — không có phát hiện đã lưu cho `scenario_id`.
- `422` — trường thừa trong thân, hoặc tên sink không xác định / chưa cấu hình trong `AlertConfigStore`.

---

### Xác Thực — `/api/auth`

#### `POST /api/auth/login`

Xác thực người dùng và tạo phiên.

**CSRF:** không yêu cầu (thiết lập phiên phát hành token).

**Yêu cầu:** `application/x-www-form-urlencoded`

| Trường | Mô tả |
|---|---|
| `username` | Tên tài khoản |
| `password` | Mật khẩu tài khoản |

**Phản hồi `200`:**
```json
{ "user": "alice", "role": "analyst", "csrf_token": "<token>" }
```
Đặt cookie `fs_session`.

**Phản hồi lỗi:**
- `401 Unauthorized` — thông tin xác thực không hợp lệ
- `429 Too Many Requests` — khóa giới hạn tốc độ đang hoạt động cho tên người dùng này

#### `POST /api/auth/logout`

Kết thúc phiên hiện tại và xóa cookie phiên.

**CSRF:** bắt buộc (tiêu đề `X-CSRF-Token`).
**Vai trò yêu cầu:** bất kỳ người dùng đã xác thực nào.

**Phản hồi `200`:** `{ "ok": true }`

#### `GET /api/auth/me`

Trả về danh tính của người dùng đã xác thực.

**Vai trò yêu cầu:** bất kỳ người dùng đã xác thực nào.

**Phản hồi `200`:**
```json
{ "id": 1, "username": "alice", "role": "analyst" }
```

#### `POST /api/auth/change-password`

Thay đổi mật khẩu của người dùng đã xác thực. Thu hồi tất cả các phiên khác của người dùng đó khi thành công.

**CSRF:** bắt buộc.
**Vai trò yêu cầu:** bất kỳ người dùng đã xác thực nào.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `current_password` | `str` | Phải khớp với mật khẩu hiện tại |
| `new_password` | `str` | Mật khẩu mới (phải qua kiểm tra chính sách) |

**Phản hồi `200`:** `{ "ok": true }`

**Phản hồi lỗi:**
- `401 Unauthorized` — `current_password` không chính xác

#### `GET /api/auth/sessions`

Liệt kê tất cả các phiên đang hoạt động của người dùng đã xác thực.

**Vai trò yêu cầu:** bất kỳ người dùng đã xác thực nào.

**Phản hồi `200`** — mảng:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `id` | `str` | ID phiên |
| `created_at` | `str` | Timestamp ISO |
| `last_seen` | `str` | Timestamp ISO |
| `expires_at` | `str` | Timestamp ISO |
| `current` | `bool` | Liệu đây có phải là phiên đang hoạt động của người gọi không |

#### `DELETE /api/auth/sessions/{sid}`

Thu hồi một phiên cụ thể thuộc về người dùng đã xác thực.

**CSRF:** bắt buộc.
**Vai trò yêu cầu:** bất kỳ người dùng đã xác thực nào (chỉ có thể thu hồi phiên của chính họ).

**Phản hồi `200`:** `{ "ok": true }`

**Phản hồi lỗi:**
- `404 Not Found` — phiên không tồn tại hoặc thuộc về người dùng khác

---

### Quản Lý Người Dùng — `/api/users`

Tất cả các endpoint quản lý người dùng yêu cầu vai trò `admin` và CSRF cho các thao tác thay đổi trạng thái.

#### `GET /api/users`

Liệt kê tất cả các tài khoản người dùng.

**Vai trò yêu cầu:** `admin`

**Phản hồi `200`** — mảng các đối tượng người dùng:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `id` | `int` | ID người dùng nội bộ |
| `username` | `str` | Tên đăng nhập |
| `role` | `str` | `"viewer"` / `"analyst"` / `"admin"` |
| `disabled` | `bool` | Liệu tài khoản có bị vô hiệu hóa không |
| `created_at` | `str` | Timestamp ISO |
| `updated_at` | `str` | Timestamp ISO |

#### `POST /api/users`

Tạo tài khoản người dùng mới.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `username` | `str` | Ít nhất 1 ký tự |
| `password` | `str` | Phải qua chính sách mật khẩu |
| `role` | `str` | `"viewer"` / `"analyst"` / `"admin"` |

**Phản hồi `201`:** đối tượng người dùng đã được tạo (cùng hình dạng như mục danh sách ở trên).

**Phản hồi lỗi:**
- `409 Conflict` — tên người dùng đã tồn tại
- `422 Unprocessable Entity` — vai trò không hợp lệ hoặc vi phạm chính sách mật khẩu

#### `PATCH /api/users/{uid}`

Cập nhật vai trò hoặc trạng thái vô hiệu hóa của người dùng.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phần thân yêu cầu (JSON, tất cả trường đều tùy chọn):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `role` | `str \| null` | Vai trò mới cần gán |
| `disabled` | `bool \| null` | `true` để vô hiệu hóa (thu hồi ngay lập tức tất cả các phiên) |

**Phản hồi `200`:** đối tượng người dùng đã được cập nhật.

**Phản hồi lỗi:**
- `404 Not Found` — không có người dùng với ID đó
- `409 Conflict` — thao tác sẽ xóa admin cuối cùng

#### `POST /api/users/{uid}/reset-password`

Đặt lại mật khẩu phía admin cho bất kỳ người dùng nào. Thu hồi tất cả các phiên của người dùng đó khi thành công.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `password` | `str` | Mật khẩu mới (phải qua kiểm tra chính sách) |

**Phản hồi `200`:** `{ "ok": true }`

**Phản hồi lỗi:**
- `404 Not Found` — không có người dùng với ID đó

#### `DELETE /api/users/{uid}`

Xóa vĩnh viễn tài khoản người dùng.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phản hồi `200`:** `{ "ok": true }`

**Phản hồi lỗi:**
- `404 Not Found` — không có người dùng với ID đó
- `409 Conflict` — không thể xóa admin cuối cùng

#### `POST /api/users/{uid}/revoke-sessions`

Thu hồi tất cả các phiên của người dùng được chỉ định (ví dụ: sau khi nghi ngờ bị xâm phạm).

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phản hồi `200`:** `{ "ok": true }`

---

### Nhật Ký Kiểm Toán — `/api/audit`

#### `GET /api/audit`

Trả về các sự kiện kiểm toán xác thực và quản trị gần đây.

**Vai trò yêu cầu:** `admin`

**Tham số truy vấn:**

| Tham số | Kiểu | Mặc định | Ràng buộc |
|---|---|---|---|
| `limit` | `int` | `100` | 1–1000 |

**Phản hồi `200`:** mảng các bản ghi sự kiện kiểm toán (hình dạng từ `AuthState.events.recent()`).

---

### Kịch Bản Tạo Sinh — `/api/generate`, `/api/candidates`

Module tạo sinh là tính năng tùy chọn (`[ai]` extra; yêu cầu `AUGUR_ANTHROPIC_API_KEY`).
LLM (`claude-opus-4-8`) đề xuất các kịch bản ứng viên; một bộ kiểm tra bảo vệ tất định
(xác thực schema → loại trùng → kiểm tra FP → kiểm tra khả năng phát hiện) và cổng phê duyệt
bắt buộc của con người kiểm soát những gì vào thư viện. Không có gì được thăng cấp tự động.

#### `POST /api/generate`

Yêu cầu LLM tạo ra các kịch bản ứng viên. Phụ thuộc vào giới hạn tốc độ theo admin.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `seed` | `str \| null` | `null` | ID kịch bản gốc để biến đổi từ đó |
| `category` | `str \| null` | `null` | Tên thư mục tactic (chữ thường alphanum + `_`) |
| `technique` | `str \| null` | `null` | Gợi ý chuỗi kỹ thuật MITRE |
| `n` | `int` | `5` | Số ứng viên được yêu cầu (bị giới hạn bởi `AUGUR_AI_MAX_N`) |
| `axes` | `list[str]` | `[]` | Các trục biến đổi để hướng dẫn tạo sinh |

**Phản hồi `200`:**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `requested` | `int` | Số ứng viên được yêu cầu |
| `passed` | `int` | Ứng viên đã qua bộ kiểm tra bảo vệ |
| `candidates` | `list` | Kết quả theo ứng viên: `scenario_id`, `passed`, `reject_stage`, `reason`, `plausibility`, `notes` |

**Phản hồi lỗi:**
- `429 Too Many Requests` — đạt giới hạn tốc độ tạo sinh theo admin

#### `GET /api/candidates`

Liệt kê tất cả các kịch bản ứng viên.

**Vai trò yêu cầu:** `analyst`

**Tham số truy vấn:**

| Tham số | Kiểu | Mô tả |
|---|---|---|
| `status` | `str \| null` | Lọc theo trạng thái: `pending` / `approved` / `rejected` |

**Phản hồi `200`** — mảng các đối tượng ứng viên:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `id` | `str` | UUID ứng viên |
| `scenario_id` | `str` | ID kịch bản được đề xuất |
| `category` | `str` | Thư mục tactic |
| `status` | `str` | `"pending"` / `"approved"` / `"rejected"` |
| `plausibility` | `float \| null` | Điểm plausibility do LLM đánh giá |
| `seed_id` | `str \| null` | ID kịch bản nguồn nếu được biến đổi |
| `mutation_axes` | `list` | Các trục được sử dụng trong quá trình tạo sinh |
| `created_by` | `str` | Tên người dùng đã kích hoạt tạo sinh |
| `created_at` | `str` | Timestamp ISO |
| `reviewed_by` | `str \| null` | Tên người dùng đã phê duyệt/từ chối |
| `reviewed_at` | `str \| null` | Timestamp ISO của lần xem xét |
| `yaml` | `str` | Văn bản YAML kịch bản đầy đủ |
| `gauntlet_report` | `dict \| null` | Kết quả đánh giá bộ kiểm tra bảo vệ |

#### `POST /api/candidates/{cid}/approve`

Thăng cấp một ứng viên `pending` vào thư viện kịch bản trực tiếp. YAML ứng viên được xác thực lại
trước khi được ghi vào `scenarios/<category>/<scenario_id>.yaml`. Thất bại đóng nếu tệp đã
tồn tại trên đĩa.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phản hồi `200`:**
```json
{ "status": "approved", "scenario_id": "SCEN-WIN-042", "path": "scenarios/..." }
```

**Phản hồi lỗi:**
- `404 Not Found` — không tìm thấy ứng viên
- `409 Conflict` — ứng viên không phải `pending`, hoặc tệp với ID đó đã tồn tại trên đĩa
- `422 Unprocessable Entity` — YAML không còn qua xác thực schema

#### `POST /api/candidates/{cid}/reject`

Đánh dấu một ứng viên `pending` là bị từ chối.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `reason` | `str` | `""` | Lý do từ chối dạng văn bản tự do |

**Phản hồi `200`:**
```json
{ "status": "rejected", "scenario_id": "SCEN-WIN-042" }
```

**Phản hồi lỗi:**
- `404 Not Found` — không tìm thấy ứng viên

---

### Cảnh Báo — `/api/alerts`

Cảnh báo là các đối tượng trạng thái theo dõi các phát hiện kịch bản qua các chu kỳ quét. Các dải proximity:
`WATCH` (≥ 0.6), `HIGH` (≥ 0.8), `CONFIRMED` (= 1.0). Mỗi lần vượt dải kích hoạt một
thông báo gửi-một-lần qua các sink được cấu hình. Một monitor nền tự trị chạy các chu kỳ quét
tự động khi `AUGUR_MONITOR_ENABLED=true`.

#### `GET /api/alerts`

Liệt kê cảnh báo với các bộ lọc tùy chọn.

**Vai trò yêu cầu:** `analyst`

**Tham số truy vấn:**

| Tham số | Kiểu | Mô tả |
|---|---|---|
| `state` | `str \| null` | Lọc theo trạng thái: `open` / `acknowledged` |
| `severity` | `str \| null` | Lọc theo severity: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `status` | `str \| null` | Lọc theo trạng thái xử lý: `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `assignee` | `str \| null` | Lọc theo tên người dùng được giao. Giá trị đặc biệt `me` ánh xạ đến người gọi; chuỗi rỗng `""` khớp với các cảnh báo chưa được giao |
| `seen_from` | `str \| null` | Mốc giới hạn dưới (ISO 8601) trên `last_seen` (bao gồm) |
| `seen_to` | `str \| null` | Mốc giới hạn trên (ISO 8601) trên `last_seen` (bao gồm) |

**Phản hồi lỗi:**
- `422 Unprocessable Entity` — một timestamp ISO `seen_from` / `seen_to` không phân tích được

**Phản hồi `200`** — mảng các đối tượng cảnh báo:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `id` | `str` | UUID cảnh báo |
| `scenario_id` | `str` | ID kịch bản đã khớp |
| `scenario_name` | `str` | Tên kịch bản |
| `severity` | `str` | Severity của kịch bản đã khớp |
| `affected_hosts` | `list[str]` | Các máy chủ trong chuỗi phát hiện |
| `proximity` | `float` | Điểm proximity mới nhất |
| `band` | `str` | Dải proximity hiện tại: `WATCH` / `HIGH` / `CONFIRMED` |
| `state` | `str` | `"open"` / `"acknowledged"` |
| `first_seen` | `str` | Timestamp ISO của lần phát hiện đầu tiên |
| `last_seen` | `str` | Timestamp ISO của lần quét gần nhất |
| `count` | `int` | Số chu kỳ quét mà cảnh báo này được kích hoạt |
| `notified_band` | `str \| null` | Dải cao nhất mà thông báo đã được gửi |
| `created_at` | `str` | Timestamp ISO |
| `assignee` | `str` | Tên người dùng được giao, hoặc `""` nếu chưa được giao |
| `status` | `str` | Trạng thái xử lý: `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `resolution_note` | `str` | Ghi chú được lưu khi giải quyết/đóng, hoặc `""` |
| `assigned_at` | `str` | Timestamp ISO của lần giao gần nhất, hoặc `""` |
| `resolved_at` | `str` | Timestamp ISO của lần giải quyết/đóng, hoặc `""` |
| `detection` | `dict` | Snapshot phát hiện gần nhất |

#### `GET /api/alerts/summary`

Trả về số lượng cảnh báo tổng hợp theo dải, trạng thái, và trạng thái xử lý.

**Vai trò yêu cầu:** `analyst`

**Phản hồi `200`** — đối tượng tóm tắt (hình dạng từ `AlertStore.summary()`):

| Trường | Kiểu | Mô tả |
|---|---|---|
| `open_count` | `int` | Cảnh báo ở trạng thái `open` |
| `acknowledged_count` | `int` | Cảnh báo ở trạng thái `acknowledged` |
| `resolved_count` | `int` | Cảnh báo ở trạng thái `resolved` |
| `in_progress_count` | `int` | Cảnh báo có trạng thái xử lý `in_progress` |
| `closed_count` | `int` | Cảnh báo có trạng thái xử lý `closed` |
| `unassigned_count` | `int` | Cảnh báo có `assignee` rỗng |
| `by_status` | `dict` | Số lượng theo từng trạng thái xử lý: `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `max_alert_id` | `int` | Rowid cảnh báo cao nhất (con trỏ phát hiện thay đổi rẻ tiền) |
| `latest_created_at` | `str` | Timestamp ISO của cảnh báo được tạo gần nhất, hoặc `""` |

#### `GET /api/alerts/{aid}`

Trả về một cảnh báo duy nhất cùng với lịch sử sự kiện đầy đủ của nó.

**Vai trò yêu cầu:** `analyst`

**Phản hồi `200`:** đối tượng cảnh báo (cùng trường như mục danh sách) cộng thêm:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `events` | `list` | Nhật ký sự kiện theo thứ tự thời gian: `{ts, actor, event, detail}` |

**Phản hồi lỗi:**
- `404 Not Found` — không có cảnh báo với ID đó

#### `POST /api/alerts/{aid}/ack`

Xác nhận một cảnh báo đang mở.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `analyst`.

**Phản hồi `200`:**
```json
{ "status": "acknowledged", "id": "<aid>" }
```

**Phản hồi lỗi:**
- `404 Not Found` — không có cảnh báo với ID đó

#### `POST /api/alerts/{aid}/assign`

Giao cảnh báo cho một người dùng, hoặc xóa việc giao khi `assignee` rỗng. Khi thành công, một thông
báo gửi-khi-giao theo nỗ lực tốt nhất được gửi qua các sink/quy tắc được cấu hình (không làm gì khi chưa cấu hình).

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `analyst`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `assignee` | `str` | `""` | Tên người dùng cần giao. Chuỗi rỗng sẽ xóa việc giao |

**Phản hồi `200`:** đối tượng cảnh báo đã cập nhật (cùng trường như mục danh sách, bao gồm `assignee` và `assigned_at`).

**Phản hồi lỗi:**
- `404 Not Found` — không có cảnh báo với ID đó
- `422 Unprocessable Entity` — `assignee` chỉ định một người dùng không xác định hoặc đã bị vô hiệu hóa
- `403 Forbidden` — người gọi thấp hơn `analyst`, hoặc tiêu đề CSRF bị thiếu/không hợp lệ

#### `POST /api/alerts/{aid}/status`

Đặt trạng thái xử lý của cảnh báo. Các trạng thái hợp lệ là `open`, `acknowledged`, `in_progress`,
`resolved`, `closed`. Chuyển sang trạng thái kết thúc (`resolved` hoặc `closed`) yêu cầu một `note`
không rỗng, được lưu dưới dạng `resolution_note`.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `analyst`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mặc định | Mô tả |
|---|---|---|---|
| `status` | `str` | — | Một trong `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `note` | `str` | `""` | Ghi chú giải quyết; **bắt buộc** (không rỗng) khi `status` là `resolved` hoặc `closed` |

**Phản hồi `200`:** đối tượng cảnh báo đã cập nhật (cùng trường như mục danh sách, bao gồm `status`, `resolution_note`, và `resolved_at`).

**Phản hồi lỗi:**
- `404 Not Found` — không có cảnh báo với ID đó
- `422 Unprocessable Entity` — `status` không hợp lệ, hoặc thiếu `note` khi giải quyết/đóng
- `403 Forbidden` — người gọi thấp hơn `analyst`, hoặc tiêu đề CSRF bị thiếu/không hợp lệ

#### `POST /api/alerts/{aid}/comment`

Thêm một bình luận dạng văn bản tự do vào lịch sử sự kiện của cảnh báo.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `analyst`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Mô tả |
|---|---|---|
| `text` | `str` | Nội dung bình luận; phải có ít nhất 1 ký tự |

**Phản hồi `201`:** `{ "ok": true }`

**Phản hồi lỗi:**
- `404 Not Found` — không có cảnh báo với ID đó
- `422 Unprocessable Entity` — `text` rỗng
- `403 Forbidden` — người gọi thấp hơn `analyst`, hoặc tiêu đề CSRF bị thiếu/không hợp lệ

#### `GET /api/alerts/config`

Trả về cấu hình cảnh báo hiện tại.

**Vai trò yêu cầu:** `admin`

**Phản hồi `200`:** đối tượng cấu hình khớp với schema `_ConfigBody` (xem PUT bên dưới).

#### `PUT /api/alerts/config`

Thay thế cấu hình cảnh báo.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phần thân yêu cầu (JSON):**

| Trường | Kiểu | Bắt buộc | Mặc định | Mô tả |
|---|---|---|---|---|
| `min_proximity` | `float` | có | — | Proximity tối thiểu để tạo cảnh báo (0.0–1.0) |
| `auto_resolve_cycles` | `int` | không | `0` | Số chu kỳ quét vắng mặt trước khi tự đóng; `0` vô hiệu hóa |
| `rules` | `list` | không | `[]` | Các quy tắc lọc: mỗi quy tắc có `{min_severity?, min_proximity?, sinks?}` |
| `sinks` | `dict` | không | `{}` | Cấu hình sink (Slack, Webhook, Jira, CortexXsoar) |

Xác thực quy tắc: mỗi `min_severity` phải là một trong `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` hoặc null;
`min_proximity` phải trong `[0.0, 1.0]` hoặc null; `sinks` phải là một danh sách.

**Phản hồi `200`:** `{ "status": "ok" }`

#### `POST /api/alerts/scan`

Kích hoạt thủ công một chu kỳ quét đối với nguồn log được cấu hình. Kết quả tương đương với những gì
monitor tự trị sẽ tính toán trong chu kỳ tiếp theo theo lịch trình.

**CSRF:** bắt buộc. **Vai trò yêu cầu:** `admin`.

**Phản hồi `200`:** số lượng kết quả quét (hình dạng từ `run_scan`): bao gồm `created`, `notified`, và
các số liệu thống kê chu kỳ khác.

---

### Bàn làm việc Giả thuyết Săn tìm — `/api/hunts`

Vòng lặp săn tìm theo giả thuyết của đội xanh, dưới dạng một hiện vật hạng nhất. Một cuộc săn tìm chỉ lưu
**giả thuyết, phạm vi, trạng thái, ghi chú và kết luận của con người** — **không bao giờ lưu kết quả của
công cụ**. **Bằng chứng được tính lại trực tiếp** từ công cụ tất định theo phạm vi của cuộc săn tìm mỗi lần
đọc, nên một cuộc săn tìm đã lưu không bao giờ hiển thị độ gần cũ như thể là hiện tại. Bằng chứng lưu duy
nhất là ảnh chụp "tại thời điểm kết luận" được gắn nhãn và đóng dấu thời gian, luôn hiển thị riêng, không
bao giờ như bằng chứng trực tiếp. Bàn làm việc **không tự kết luận** — nhà phân tích sở hữu kết luận.

Một **phạm vi** = `{ scenario_ids?: [], tactic?, zone?, host?, from?, to? }`; bằng chứng = các phát hiện
theo cửa sổ trong phạm vi, mỗi cái kèm độ gần, số bước khớp/tổng, và **bước tiếp theo cần săn**. Trạng thái:
`open · investigating · confirmed · refuted · abandoned`.

| Phương thức | Đường dẫn | Vai trò | Ghi chú |
|---|---|---|---|
| `POST` | `/api/hunts` | analyst | CSRF. Body `{hypothesis, scope}`; xác thực phạm vi (422); `owner` = người gọi. |
| `GET` | `/api/hunts` | viewer | Lọc `status`, `owner` (`owner=me`). Danh sách (không kèm bằng chứng). |
| `GET` | `/api/hunts/{id}` | viewer | Chi tiết kèm `evidence` **tính lại trực tiếp**, `scope_resolved`, `honesty_note`, `verdict_evidence` (gắn nhãn + `verdict_evidence_at`), và `events`. |
| `PATCH` | `/api/hunts/{id}` | analyst | CSRF. Tùy chọn `status`/`verdict_note`/`notes`/`scope`. `confirmed`/`refuted` cần `verdict_note` (422) và chụp ảnh as-of. |
| `POST` | `/api/hunts/{id}/comment` | analyst | CSRF. `{text}`. |
| `DELETE` | `/api/hunts/{id}` | analyst (chủ) / admin | CSRF. Chỉ chủ-hoặc-admin (ngược lại 403). |
| `GET` | `/api/hunts/{id}/report` | viewer | `?format=md` (mặc định) hoặc `json`. |

Chỉ đọc/bổ sung: bằng chứng là tái sử dụng tất định của `_windowed_cached`; đường tính điểm của công cụ
không bị đụng. Store chạy trên kết nối sqlite per-thread dùng chung (an toàn đồng thời).

### Tinh chỉnh FP / Allowlist — `/api/tuning`

Một lớp chính sách tất định sau-engine để kiểm soát dương tính giả (ẩn / hạ cấp các phát hiện lành tính).
Engine và đường tính điểm không bao giờ bị đụng; khi không có mục hoạt động, mọi route bên dưới là no-op và
`GET /api/detections` trả về đúng dạng cũ. Một **mục** allowlist là phép AND của các điều kiện tùy chọn
(`scenario_id`, `technique`, `host`, `zone`, `process_regex`, `command_regex`, `image_regex`,
`ts_from`/`ts_to`) cộng `action` (`SUPPRESS` | `DOWNGRADE` với `downgrade_to` ∈ `{WATCH,HIGH}`) và một
`reason` không rỗng bắt buộc. Cần ít nhất một điều kiện (nếu không 422).

| Method | Route | Vai trò | Ghi chú |
|---|---|---|---|
| `GET` | `/api/tuning` | viewer | Liệt kê mục (`?enabled=true|false`); mỗi mục mang `hit_count` trực tiếp trên tập phát hiện hiện tại. |
| `GET` | `/api/tuning/ledger` | viewer | Sổ "tuned out" trực tiếp: số đếm + các phát hiện bị ẩn/hạ cấp, mỗi cái quy cho mục + lý do (bề mặt trung thực luôn hiển thị). |
| `GET` | `/api/tuning/{id}` | viewer | Một mục + nhật ký `events`. |
| `POST` | `/api/tuning` | analyst | CSRF. Tạo mục. Kiểm tra ≥1 điều kiện, lý do không rỗng, regex/zone/technique/scenario hợp lệ, mức DOWNGRADE. |
| `PATCH` | `/api/tuning/{id}` | analyst | CSRF. Sửa điều kiện/action/lý do/hạn dùng. |
| `POST` | `/api/tuning/{id}/enable` · `/disable` | analyst | CSRF. Bật/tắt mềm (không xóa). |
| `DELETE` | `/api/tuning/{id}` | analyst (tác giả) / admin | CSRF. Chỉ tác giả-hoặc-admin (nếu không 403). |
| `POST` | `/api/tuning/propose_from_alert/{alert_id}` | analyst | CSRF. Trả bản nháp điền sẵn **chưa lưu** (DOWNGRADE→WATCH thận trọng) + `baseline_hint` tư vấn (mức nền rarity của tiến trình). Không lưu gì cho tới khi analyst POST `/api/tuning`. |

**Ảnh hưởng lên `GET /api/detections` (dạng mảng, bổ sung):** khi có mục hoạt động, các hàng bị ẩn biến mất
và các hàng bị hạ cấp nhận thêm trường `band_override`; phản hồi vẫn là `Detection[]` trần. Chi tiết "tuned
out" đọc riêng từ `/api/tuning/ledger`. Tất định: đường khớp không có đồng hồ thực; proximity không bao giờ
bị thay đổi.

---

## Biến Môi Trường

Các biến môi trường chính ảnh hưởng đến hành vi API:

| Biến | Mô tả |
|---|---|
| `AUGUR_LOGS` | Đường dẫn đến nguồn log JSONL được nạp khi khởi động (mặc định: `sample_data/corpus/enterprise_day.jsonl`) |
| `AUGUR_SECRET_KEY` | Khóa ký phiên; phải được đặt trong môi trường production (thất bại đóng nếu vắng mặt) |
| `AUGUR_ADMIN_USER` / `AUGUR_ADMIN_PASSWORD` | Khởi tạo tài khoản admin ban đầu |
| `AUGUR_COOKIE_SECURE` | Đặt thành `true` để bật cờ `Secure` trên cookie phiên (production) |
| `AUGUR_BACKEND` | Đặt thành `neo4j` để sử dụng backend đồ thị Neo4j thay vì NetworkX |
| `AUGUR_MONITOR_ENABLED` | Đặt thành `true` để bật monitor cảnh báo nền tự trị |
| `AUGUR_SCAN_WINDOW_SECONDS` | Cửa sổ trượt cho quét cảnh báo (giây; `0` hoặc không đặt = toàn bộ nguồn) |
| `AUGUR_ANTHROPIC_API_KEY` | Bắt buộc cho module tạo sinh (`[ai]` extra) |
| `AUGUR_AI_MAX_N` | Số ứng viên tối đa mỗi yêu cầu tạo sinh |

---

## Xem Thêm

- [ARCHITECTURE.md](ARCHITECTURE.md) — tổng quan hệ thống đầy đủ bao gồm các module auth và alerting
- [DATA_MODEL.md](DATA_MODEL.md) — các trường đối tượng phát hiện và mô hình dữ liệu đồ thị
- [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) — tài liệu tham khảo soạn thảo YAML kịch bản
- [THREAT_MODEL.md](../en/THREAT_MODEL.md) — các thuộc tính bảo mật và ranh giới tin cậy
