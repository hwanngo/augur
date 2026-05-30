[English](../en/THREAT_MODEL.md) | **Tiếng Việt**

# Augur — Mô hình Mối đe dọa của Nền tảng

> Mô hình mối đe dọa cho **bản thân nền tảng Augur** (không phải các mối đe dọa mà nó phát hiện). Phạm vi:
> dịch vụ self-hosted — engine, ingestion, web API/UI, auth, lớp generative (Phase 2), subsystem alerting,
> và log simulator. Viết dựa trên mã nguồn thực tế; rủi ro tồn dư và khuyến nghị được nêu rõ ràng.

Tài liệu liên quan: [ARCHITECTURE.md](ARCHITECTURE.md) | [API.md](API.md) | [CONTRIBUTING.md](CONTRIBUTING.md)

## Giả định hệ thống / tư thế triển khai
- **Single-tenant, self-hosted**, vận hành bởi một operator đáng tin cậy. Không tuyên bố cách ly multi-tenant.
- **TLS được kết thúc bởi một reverse proxy** đặt trước ứng dụng; đặt `AUGUR_COOKIE_SECURE=true` để
  cookie session chỉ qua HTTPS. Ứng dụng nói HTTP thuần phía sau proxy.
- Host OS, filesystem, và file database sqlite được tin cậy (ACL filesystem bảo vệ chúng).
- Operator có role `admin` được tin cậy; mô hình bảo vệ ranh giới *bên dưới* admin (viewer/analyst →
  admin, và chưa xác thực → đã xác thực), cộng với các bề mặt data/egress mà admin có thể cấu hình.

## Tài sản (Assets)
| Tài sản | Vì sao quan trọng |
|---|---|
| **Tính toàn vẹn của Engine + thư viện scenario** | Độ chính xác phát hiện. Giả mạo = phát hiện thiếu/sai. |
| **Auth store** (`users`, `sessions`, `auth_events`) | Credential tài khoản (hash argon2id), session token. |
| **`AUGUR_SECRET_KEY`** | Toàn vẹn session. |
| **`ANTHROPIC_API_KEY`** | Tính phí, và là credential egress (lớp generative). |
| **Cấu hình routing alert** (định nghĩa sink trong `alert_config`) | Có thể nhúng token/URL webhook → egress đi ra ngoài. |
| **Topology + logs** | Hostname/zone (nhạy cảm nhẹ); log đã ingest (telemetry khách hàng có thể nhạy cảm). |

## Ranh giới tin cậy (Trust boundaries)
1. **Chưa xác thực → đã xác thực** (ranh giới login; mọi route data `/api/*` đều bị gate theo role).
2. **viewer < analyst < admin** (RBAC qua `require_role`).
3. **Log data không tin cậy → engine** (JSONL đã ingest / monitor drop-feed có thể bị kẻ tấn công tác động).
4. **Nền tảng → dịch vụ bên ngoài** (LLM egress tới Anthropic; alert egress tới các Sink đã cấu hình).
5. **Nội dung do LLM sinh ra → thư viện scenario đang chạy** (đường phê duyệt Phase 2).

---

## Mối đe dọa, biện pháp giảm thiểu, rủi ro tồn dư

### T1 — Lạm dụng xác thực & session  *(ranh giới 1)*
- **Biện pháp (trong mã):** hash mật khẩu argon2id; cookie session phía server (`HttpOnly`, `SameSite=Strict`, `Secure` ở prod); một session id mới được tạo lúc login (không có fixation); rate-limit + lockout theo từng username; một dummy-hash verify thời gian hằng định cho user không xác định/bị vô hiệu (chống timing-oracle login); `AUGUR_SECRET_KEY` **fail-closed** ở prod; **không có mật khẩu admin mặc định** (chỉ bootstrap qua env/CLI); CSRF double-submit (`X-CSRF-Token` + `hmac.compare_digest`) trên mọi mutation.
- **Rủi ro tồn dư:** rate-limiter và lockout là **in-process** (chỉ single-box) — triển khai multi-worker/multi-instance sẽ đếm thiếu và làm yếu khả năng chống brute-force. Không có thông báo lockout tài khoản, không 2FA.
- **Khuyến nghị:** ghi rõ chỉ-single-instance cho limiter, hoặc chuyển rate-limit/lockout sang store dùng chung; cân nhắc TOTP tùy chọn cho admin.

### T2 — Phân quyền / leo thang đặc quyền  *(ranh giới 2)*
- **Biện pháp:** gate `require_role` nhất quán; guard "không thể vô hiệu/xóa admin được bật cuối cùng"; phân tách analyst = triage, admin = cấu hình/vận hành được áp dụng đồng nhất (router auth, generative, alerting).
- **Rủi ro tồn dư:** thấp. Đáng để audit định kỳ rằng không endpoint mới nào ship mà thiếu role guard (một test khẳng định mọi route `/api` đều mang một `Depends`).

### T3 — Ingest log không tin cậy → engine  *(ranh giới 3)*  ⭐ bề mặt then chốt
- **Biện pháp:** log là **dữ liệu, không bao giờ là mã** — parse bằng `json.loads`/`yaml.safe_load`, normalize thành dataclass, và chỉ *đối chiếu với* graph; không `eval`/`exec`/thực thi template ở bất kỳ đâu trong đường engine. Dòng lỗi raise `IngestError` kèm số dòng. Các query KQL/Sigma trong scenario được **đưa cho analyst, Augur không bao giờ thực thi**.
- **Lưu ý — overlay IOC mù với engine:** overlay threat-intel (`/api/ioc_match`) cùng các field `NormalizedEvent` hậu thuẫn (`hashes`/`domain`/`dest_ip`/`dest_port`) và các event kind (`dns_query`/`network_connect`) là **chỉ-đọc và bổ sung**. Các field này được cố ý giữ ngoài `PROCESS_KEY_MAP`/`FILE_KEY_MAP` của `criteria.py`, và `build_graph` loại bỏ các kind mới — nên đường engine/matcher/scoring không bao giờ đọc chúng và chúng **không thể ảnh hưởng tới hành vi phát hiện**. Telemetry mới giữ nguyên tư thế ranh giới-3 (log data không tin cậy vẫn là dữ liệu; overlay chỉ đếm nó).
- **Rủi ro tồn dư:** **cạn kiệt tài nguyên / DoS.** Một feed log rất lớn hoặc bệnh lý xây dựng một graph NetworkX in-memory không giới hạn; một regex scenario có thể backtracking thảm họa (gauntlet generative loại bỏ regex quá rộng, nhưng scenario viết tay không được kiểm regex-DoS). Không có ngân sách kích thước/thời gian theo từng feed.
- **Khuyến nghị:** giới hạn kích thước/số lượng event ingest mỗi scan; thêm lint an toàn regex vào scenario loader (timeout hoặc kiểu `re2`); graph có cửa sổ và eviction (xem roadmap).

### T4 — Egress đi ra ngoài qua alert Sink  *(ranh giới 4)*  ⭐ bề mặt then chốt
- **Là gì:** admin cấu hình routing alert dạng định nghĩa sink `{type, url, ...}` lưu trong `alert_config`; khi scan, ứng dụng dựng Sink và **POST tới URL đã cấu hình** (webhook/Slack/Jira/XSOAR).
- **Rủi ro:** **SSRF** — một admin (hoặc bất kỳ ai chạm tới admin) có thể trỏ sink tới URL nội bộ/cloud-metadata và khiến server phát yêu cầu tới chúng. Credential/token của sink **nằm trong URL và được lưu plaintext** trong sqlite. Lỗi của từng sink được cách ly (một sink hỏng không chặn các sink khác), điều này tốt, nhưng **không có allowlist URL, không guard SSRF, không mã hóa secret.**
- **Khuyến nghị:** một allowlist egress (scheme/host) cho URL sink; lưu secret sink trong một field secret, được redact trong phản hồi API và audit; chặn dải link-local/metadata.

### T5 — Lớp generative (LLM)  *(ranh giới 4 & 5)*
- **Biện pháp:** SDK `anthropic` là một **extra `[ai]` opt-in**, không bao giờ được import bởi đường mặc định; việc generate **gate theo admin + CSRF + rate-limit + giới hạn `n` + audit**; prompt chỉ mang **schema scenario công khai**, topology, và exemplar — **không log tenant, không secret**; API key chỉ đọc từ `ANTHROPIC_API_KEY`. Output LLM là **không tin cậy** và chạy qua toàn bộ gauntlet tất định (schema → dedup → FP-guard → detectability) trước khi một con người có thể phê duyệt; không gì tự động vào thư viện.
- **Rủi ro tồn dư:** **egress dữ liệu** — định nghĩa scenario + hostname/zone topology rời khỏi ranh giới tới Anthropic khi generate được bật (chấp nhận được với nhiều bên, nhưng là điều cấm với air-gapped/classified). Prompt-injection của *thư viện/topology* vào model không thể exfiltrate secret (không có secret trong prompt) nhưng có thể làm thiên lệch candidate sinh ra — bị bắt bởi phê duyệt con người. Lạm dụng chi phí bị chặn bởi rate-limit + giới hạn.
- **Khuyến nghị:** làm rõ egress trong tài liệu (vốn đã opt-in); thêm công tắc cứng "AI disabled" cấp tổ chức; log một hash của ngữ cảnh prompt để audit.

### T6 — Nội dung sinh/đã phê duyệt → thư viện đang chạy  *(ranh giới 5)*
- **Biện pháp:** phê duyệt là **admin + CSRF + audit**; YAML candidate được **re-validate** với schema lúc phê duyệt; đích ghi bị ràng buộc — `category` được validate `^[a-z0-9_]+$` ở ranh giới API **và** đích đã giải được xác nhận nằm *bên trong* `scenarios/` (chặn path-traversal), với guard `dest.exists()` → 409 (không clobber âm thầm). *(Những điều này được làm chặt trong review Phase 2.)*
- **Rủi ro tồn dư:** thấp. Một admin độc hại vẫn có thể chủ ý viết một scenario tồi (bất kỳ admin nào cũng có thể ghi `scenarios/` trực tiếp) — ngoài phạm vi mô hình (admin được tin cậy).

### T7 — Secret ở trạng thái nghỉ (at rest)
- **Biện pháp:** mật khẩu là argon2id (không bao giờ plaintext). Secret key và API key đến từ env, không từ DB; không bao giờ log (audit `detail` chỉ mang các field không nhạy cảm).
- **Rủi ro tồn dư:** **cấu hình sink (T4) và mọi credential tích hợp tương lai được lưu plaintext trong sqlite.** Tính bảo mật của file DB hoàn toàn dựa vào ACL filesystem + mã hóa đĩa.
- **Khuyến nghị:** mã hóa secret sink at rest (hoặc tham chiếu một secret store bên ngoài); ghi rõ rằng file sqlite phải nằm trên volume được kiểm soát truy cập, lý tưởng là mã hóa.

### T8 — Monitor drop-feed *(biến thể của ranh giới 3)*
- Monitor 3d đọc mọi file trong `AUGUR_MONITOR_DIR`. Bất kỳ ai ghi được vào thư mục đó đều có thể tiêm "log" tùy ý (→ bề mặt T3) và có thể bịa hoặc đè nén phát hiện.
- **Khuyến nghị:** drop-dir phải được kiểm soát truy cập ở cùng mức tin cậy với operator; ghi rõ điều này.

---

## Ngoài phạm vi (nêu rõ)
Cách ly multi-tenant; làm cứng host/OS; cấu hình reverse proxy / TLS; chuỗi cung ứng của các dependency;
truy cập vật lý; một `admin` độc hại (admin được tin cậy theo giả định); DoS ở tầng mạng.

## Khuyến nghị ưu tiên (đòn bẩy cao nhất trước)
1. **Guard SSRF + secret-at-rest cho alert sink** (T4/T7) — khoảng trống thực rõ nhất cho một sản phẩm bảo mật.
2. **Ngân sách tài nguyên ingest + lint an toàn regex scenario** (T3) — khả năng chống DoS trên input không tin cậy.
3. **Store rate-limit/lockout dùng chung** cho auth multi-instance (T1).
4. **Một công tắc "AI hard-off" + hash ngữ cảnh prompt** (T5) cho triển khai bị quản chế/air-gapped.
5. **Một test phủ route-guard** (T2) để không endpoint tương lai nào ship mà không xác thực.

**Các mục mở tính tới thời điểm viết:** khuyến nghị 1 (guard SSRF sink + secret-at-rest), 2 (ngân sách
tài nguyên ingest + lint an toàn regex), và 4 (ngân sách ingest-DoS) ở trên vẫn chưa được triển khai và
được theo dõi trên roadmap.

*Tài liệu này phản ánh mã nguồn tính tới nhánh eval/hardening. Hãy review lại khi bề mặt egress (sink/LLM)
hoặc ingestion thay đổi.*
