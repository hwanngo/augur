[English](../en/CONFIGURATION.md) | **Tiếng Việt**

# Augur — Tham chiếu Cấu hình

> Mọi tham số runtime đều là một biến môi trường. Không có file cấu hình; ứng dụng đọc `os.environ`
> lúc khởi động (hoặc mỗi lần gọi CLI). Trang này liệt kê **toàn bộ** biến `AUGUR_*`, `NEO4J_*`, và
> `ANTHROPIC_API_KEY`, truy ngược về module tiêu thụ trong `src/augur/`. Giá trị mặc định là giá trị
> dự phòng nguyên văn trong mã nguồn. Xem [`.env.example`](../../.env.example) để có template sẵn dùng và
> [THREAT_MODEL.md](THREAT_MODEL.md) để hiểu cơ sở bảo mật đằng sau các mặc định này.

**Chú thích bắt buộc khi chạy prod:** **Yes** = ứng dụng fail-closed hoặc mất an toàn nếu thiếu biến này
khi `AUGUR_ENV=prod`. **Bootstrap** = chỉ dùng một lần, trên bảng user trống lần đầu. **No** = tùy chọn /
có mặc định an toàn.

---

## Core / auth (lõi / xác thực)

| Biến | Mặc định | Module | Bắt buộc khi prod |
|---|---|---|---|
| `AUGUR_ENV` | `dev` | `auth/config.py` | Yes — phải là một trong `dev` / `prod` / `test`; giá trị không hợp lệ sẽ raise lúc khởi động. Quyết định cookie-secure + fail-closed của secret-key. |
| `AUGUR_SECRET_KEY` | *(không có)* | `auth/config.py` | **Yes** — khóa ký session/CSRF. Ở `prod`, thiếu giá trị sẽ raise `RuntimeError`. Ở `dev`/`test` sinh khóa tạm thời (session không sống sót sau restart). |
| `AUGUR_DB` | `data/augur.db` | `auth/config.py`, `generate.py`, `maintenance.py` | No — đường dẫn sqlite cho connection dùng chung theo từng thread (auth, alerts, hunts, generative). |
| `AUGUR_COOKIE_SECURE` | *(chưa đặt → suy ra)* | `auth/config.py` | No — ghi đè mặc định suy ra. Mặc định `true` khi `AUGUR_ENV=prod`, ngược lại `false`. Chỉ đặt `false` khi prod chạy sau reverse proxy kết thúc TLS trên HTTP thuần. Giá trị truthy = `1`/`true`/`yes`/`on`. |
| `AUGUR_ADMIN_USER` | *(không có)* | `auth/bootstrap.py` | Bootstrap — username admin ban đầu, chỉ tạo khi bảng user còn trống. |
| `AUGUR_ADMIN_PASSWORD` | *(không có)* | `auth/bootstrap.py` | Bootstrap — mật khẩu admin ban đầu (đi kèm `AUGUR_ADMIN_USER`). **Không** có mật khẩu admin mặc định. |
| `AUGUR_LOGS` | `sample_data/corpus/enterprise_day.jsonl` | `api/app.py`, `alerting/router.py`, `demo.py` | No — nguồn log JSONL mà API/alerting scan đọc. Trỏ tới corpus thật khi chạy prod. |

## Graph backend

| Biến | Mặc định | Module | Bắt buộc khi prod |
|---|---|---|---|
| `AUGUR_BACKEND` | *(chưa đặt → NetworkX)* | `pipeline.py` | No — đặt `neo4j` để dùng backend Neo4j opt-in; mọi giá trị khác (hoặc chưa đặt) chọn mặc định NetworkX in-memory. |
| `NEO4J_URI` | `bolt://localhost:7687` | `pipeline.py` | Chỉ khi `AUGUR_BACKEND=neo4j`. |
| `NEO4J_USER` | `neo4j` | `pipeline.py` | Chỉ khi `AUGUR_BACKEND=neo4j`. |
| `NEO4J_PASSWORD` | `augur` | `pipeline.py` | Chỉ khi `AUGUR_BACKEND=neo4j` — hãy đổi giá trị mặc định. |

## Alerting (cảnh báo)

| Biến | Mặc định | Module | Bắt buộc khi prod |
|---|---|---|---|
| `AUGUR_MONITOR_ENABLED` | *(chưa đặt → tắt)* | `alerting/monitor.py` | No — giá trị truthy (`1`/`true`/`yes`/`on`) bật vòng lặp monitor nền. |
| `AUGUR_MONITOR_INTERVAL` | `60` | `alerting/monitor.py` | No — chu kỳ poll của monitor tính bằng giây (float). |
| `AUGUR_MONITOR_DIR` | *(không có)* | `alerting/monitor.py` | No — thư mục drop-feed mà monitor quét. **Phải được kiểm soát truy cập** (ai ghi được vào đây đều có thể tiêm log; xem THREAT_MODEL T8). |
| `AUGUR_ALERT_MIN_PROXIMITY` | `0.6` | `alerting/config.py` | No — proximity tối thiểu để phát cảnh báo (kẹp `0.0`–`1.0`). |
| `AUGUR_ALERT_AUTO_RESOLVE_CYCLES` | `0` | `alerting/config.py` | No — số chu kỳ trước khi một cảnh báo không còn thấy tự resolve (`0` = không bao giờ). |
| `AUGUR_ALERT_SINKS` | *(không có)* | `alerting/acfg.py` | No — JSON object định nghĩa sink, chỉ dùng để **seed** cấu hình alert trên DB mới (`{name: {type, ...}}`). |
| `AUGUR_ALERT_RULES` | *(không có)* | `alerting/acfg.py` | No — JSON array các rule cảnh báo, chỉ dùng để **seed** cấu hình alert trên DB mới. |
| `AUGUR_SCAN_WINDOW_SECONDS` | `0` | `alerting/router.py` | No — cửa sổ scan trượt tính bằng giây; `0` hoặc chưa đặt = toàn bộ feed. |

## Connector CLI (`augur.hunt`)

| Biến | Mặc định | Module | Bắt buộc khi prod |
|---|---|---|---|
| `AUGUR_WEBHOOK_URL` | *(không có)* | `hunt.py` | No — URL mặc định tiêm vào sink `webhook` khi không truyền `--sink-arg url=...`. |
| `AUGUR_SLACK_WEBHOOK_URL` | *(không có)* | `hunt.py` | No — URL mặc định tiêm vào sink `slack` khi không truyền `--sink-arg url=...`. |

## Retention / maintenance (lưu giữ / bảo trì)

| Biến | Mặc định | Module | Bắt buộc khi prod |
|---|---|---|---|
| `AUGUR_RETENTION_DAYS` | `90` | `maintenance.py` | No — mốc tuổi mặc định cho CLI `augur.maintenance prune` (ghi đè bằng `--days`). |

## Generative / AI — extra `[ai]` opt-in

> Lớp generative **không bao giờ được import bởi đường dẫn mặc định**. Các biến này chỉ có tác dụng khi
> đã cài extra `[ai]` và `AUGUR_AI_GENERATOR=claude`. Bật nó sẽ gây egress định nghĩa scenario tới
> Anthropic (xem THREAT_MODEL T5).

| Biến | Mặc định | Module | Bắt buộc khi prod |
|---|---|---|---|
| `AUGUR_AI_GENERATOR` | `fake` | `generative/config.py` | No — `fake` (stub tất định, mặc định) hoặc `claude` (LLM thật). |
| `ANTHROPIC_API_KEY` | *(không có)* | `generative/config.py` | Chỉ khi `AUGUR_AI_GENERATOR=claude` — credential egress tính phí; chỉ đọc từ env, không bao giờ lưu. |
| `AUGUR_AI_MODEL` | `claude-opus-4-8` | `generative/config.py` | No — model id mà generator `claude` dùng. |
| `AUGUR_AI_TEMPERATURE` | `0.7` | `generative/config.py` | No — temperature sampling (float). |
| `AUGUR_AI_MAX_N` | `10` | `generative/config.py` | No — số scenario candidate tối đa yêu cầu mỗi lần generate. |
| `AUGUR_AI_MAX_TOKENS` | `4096` | `generative/config.py` | No — số output token tối đa mỗi lần gọi LLM. |
| `AUGUR_AI_MAX_CALLS` | `30` | `generative/config.py` | No — số lần generate mỗi cửa sổ trước khi lockout theo từng admin. |
| `AUGUR_AI_WINDOW_SECONDS` | `900` | `generative/config.py` | No — cửa sổ rate-limit tính bằng giây cho `AUGUR_AI_MAX_CALLS`. |

---

## Bộ cấu hình prod tối thiểu

Cho một triển khai prod điển hình (backend NetworkX, không AI, TLS tại reverse proxy):

```bash
AUGUR_ENV=prod
AUGUR_SECRET_KEY=<48+ byte ngẫu nhiên>        # bắt buộc, fail-closed
AUGUR_ADMIN_USER=admin                         # bootstrap lần đầu
AUGUR_ADMIN_PASSWORD=<mật khẩu mạnh>           # bootstrap lần đầu
AUGUR_DB=/data/augur.db                         # volume bền vững, kiểm soát truy cập
AUGUR_LOGS=/data/feed/enterprise_day.jsonl      # corpus thật của bạn
AUGUR_COOKIE_SECURE=true                         # hoặc false nếu proxy phục vụ HTTP thuần
```

Mọi biến còn lại đều có mặc định an toàn. Chỉ thêm khối Neo4j, alerting, retention, hoặc AI nếu bạn
dùng các subsystem đó.
