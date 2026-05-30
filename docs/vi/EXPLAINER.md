**English** | [Tiếng Việt](../vi/EXPLAINER.md)

# Augur — Giải thích Đơn giản

Một chuyến tham quan bằng ngôn ngữ dễ hiểu về những gì Augur làm, tại sao nó hoạt động theo cách đó, và cách đọc đầu ra của nó. Để xem các tài liệu chuyên sâu về kỹ thuật, hãy xem [ARCHITECTURE.md](ARCHITECTURE.md), [ENGINE.md](ENGINE.md), [DATA_MODEL.md](DATA_MODEL.md), [API.md](API.md), và [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md).

---

## Ý tưởng trong một câu

Augur là một **máy dò khói cho các cuộc tấn công mạng** — nhưng thay vì chỉ kêu bíp khi khói xuất hiện, nó cho bạn biết *đám cháy nào*, *ở phòng nào*, và *đã lan rộng đến đâu*.

---

## Tại sao không chỉ dùng hệ thống cảnh báo thông thường?

Hãy nghĩ về một tên trộm biết vị trí các cảm biến chuyển động. Hắn di chuyển chậm, chờ đợi giữa các bước, và đảm bảo từng hành động riêng lẻ trông vô hại. Một người mang hộp — bình thường thôi. Nhưng nếu người đó trước đó đã thử cửa sau, rồi kiểm tra bảng báo động, rồi đeo găng tay cao su — đột nhiên cả chuỗi hành động kể một câu chuyện mà từng sự kiện riêng lẻ không bao giờ có thể kể được.

Các công cụ bảo mật thông thường chấm điểm từng sự kiện một. Chúng thấy "PowerShell được khởi chạy" và quyết định: đáng ngờ hay không? Chúng tạo ra hàng nghìn phán quyết riêng lẻ như vậy, và các nhà phân tích chết đuối khi cố gắng phân loại chúng.

Augur hoạt động khác đi. Nó nói: *"Tôi biết một số cuộc tấn công trông như thế nào dưới dạng một chuỗi các bước có thứ tự. Hãy để tôi kiểm tra xem chuỗi đó có đang diễn ra trên các máy của bạn không."*

---

## Ý tưởng playbook

Augur đi kèm với thư viện **40 kịch bản tấn công** — các playbook được viết bởi con người đã nghiên cứu các kỹ thuật tấn công thực tế được ghi lại trong MITRE ATT&CK. Mỗi playbook mô tả một mô hình tấn công cụ thể dưới dạng danh sách các bước có thứ tự:

> **Bước 1:** Một tiến trình chạy từ thư mục Temp của người dùng (dropper đáng ngờ)
> **Bước 2:** Trong vòng 5 phút trên cùng máy, một DLL chưa ký được tải vào tiến trình đó
> **Bước 3:** Trong vòng 2 phút, tiến trình truy cập bộ nhớ LSASS (cố gắng đánh cắp mật khẩu)
> **Bước 4:** Trong vòng 10 phút, một tệp dàn dựng thông tin xác thực xuất hiện trong thư mục temp
> **Bước 5:** Trong vòng 30 phút, dữ liệu được gửi đến một IP bên ngoài

Mỗi bước có ba loại ràng buộc:
- **Cái gì** — loại hoạt động nào chúng ta đang tìm kiếm? (một tiến trình, một lần tải file, một thẻ hành vi từ EDR của bạn)
- **Ở đâu** — máy phải ở trong vùng mạng nào? (ví dụ `User_Endpoint`, `Active_Directory`)
- **Khi nào** — bước này phải xảy ra nhanh đến mức nào sau bước trước?

Thư viện trải rộng **14 chiến thuật ATT&CK** và bao phủ môi trường Windows (`SCEN-WIN-*`), Linux (`SCEN-LNX-*`), và macOS (`SCEN-MAC-*`), cộng với các kịch bản cloud-stub (`SCEN-CLD-*`) xấp xỉ hoạt động nhắm mục tiêu cloud qua telemetry endpoint.

---

## Ý tưởng gần kề: "kẻ tấn công đã đi đến đâu rồi?"

Đây là điểm Augur làm điều khác biệt so với một bộ phát hiện có/không.

Thay vì trả lời "cuộc tấn công này có đang xảy ra không?", nó trả lời: **"chúng ta đã thấy bao nhiêu phần của mô hình tấn công này rồi?"**

```
proximity = số bước đã khớp ÷ tổng số bước
```

Một kịch bản có 5 bước trong đó 3 bước đã được quan sát trên cùng một máy trong các cửa sổ thời gian cho ra:

```
proximity = 3 / 5 = 0.60  →  60%
```

60% đó là một cảnh báo sớm. Kẻ tấn công đã bắt đầu. Chúng chưa hoàn thành. Bạn vẫn còn thời gian để phản ứng.

Một kịch bản ở mức 100% có nghĩa là tất cả các bước đã khớp — toàn bộ chuỗi tấn công đã thực thi. Vẫn hữu ích (bạn muốn biết điều đó đã xảy ra), nhưng sớm hơn thì tốt hơn.

Một kịch bản ở 0% (hoặc dưới ngưỡng báo cáo 30%) đơn giản là không được báo cáo. Không có cảnh báo, không có nhiễu — mô hình không có ở đó.

Đây là lý do tại sao gần kề hữu ích hơn có/không nhị phân: **gần kề 40% trên một kịch bản quan trọng là ưu tiên săn lùng trước khi bất kỳ cảnh báo nào kích hoạt.**

---

## Một ví dụ cụ thể

Giả sử Augur đang theo dõi một máy có tên `HR_User_PC` trên mạng doanh nghiệp của bạn (vùng: `User_Endpoint`).

Nhật ký của bạn trong giờ vừa qua chứa:

```
10:00  dropper.exe  chạy từ  C:\Users\alice\AppData\Local\Temp\dropper.exe
10:02  DLL chưa ký  bad.dll  được tải bởi  dropper.exe
10:03  dropper.exe  truy cập  bộ nhớ LSASS  (behavior: lsass_access)
10:07  tệp dump thông tin xác thực  creds.dmp  được tạo trong thư mục Temp
10:31  powershell.exe  kết nối đến  185.220.x.x  (IP bên ngoài)
```

Augur có kịch bản `SCEN-WIN-001` (Đánh cắp thông tin xác thực qua LSASS comsvcs MiniDump) với chính xác 5 bước khớp với mô hình này, với các cửa sổ thời gian sau:

| Bước | Ràng buộc | Nhật ký này | Đạt? |
|------|----------|------------|------|
| 1 | Tiến trình từ Temp | dropper.exe lúc 10:00 | ✓ |
| 2 | DLL chưa ký được tải, cùng host, trong vòng 10 phút | bad.dll lúc 10:02 (2 phút) | ✓ |
| 3 | Truy cập LSASS, cùng host, trong vòng 5 phút | 10:03 (1 phút) | ✓ |
| 4 | Tệp dàn dựng, cùng host, trong vòng 15 phút | 10:07 (4 phút) | ✓ |
| 5 | Kết nối bên ngoài, cùng host, trong vòng 60 phút | 10:31 (28 phút) | ✓ |

Kết quả: `5/5 bước khớp → proximity = 1.0 → CRITICAL`.

Bây giờ giả sử kết nối 10:31 không bao giờ xảy ra (có thể kẻ tấn công bị gián đoạn). Thì:

```
4/5 bước khớp → proximity = 0.8 → vẫn CRITICAL
Thiếu: Exfiltration_Connection
```

Bước thiếu đó không phải là thất bại — đó là manh mối săn lùng của bạn. Kẻ tấn công đang ở bước 4. Hãy tìm bước 5 trước khi nó xảy ra.

---

## Tại sao engine xác định luận (không có AI đoán mò)

Cụm từ "đường chấm điểm không có AI" có thể nghe như một hạn chế. Đó là một lựa chọn thiết kế có chủ ý.

Khi một LLM chấm điểm các sự kiện, nó có thể đưa ra các câu trả lời khác nhau cho cùng một câu hỏi trong các lần chạy khác nhau. Nó có thể ảo giác các mô hình. Nó không thể giải thích đầy đủ tại sao nó kích hoạt. Trong môi trường SOC, sự không thể đoán trước đó là một vấn đề nghiêm trọng: bạn cần có khả năng kiểm tra tại sao một cảnh báo kích hoạt, tái tạo nó trong môi trường thử nghiệm, và tin tưởng rằng cùng nhật ký sẽ cho cùng câu trả lời vào ngày mai.

Engine của Augur không sử dụng LLM và không có sự ngẫu nhiên trong quá trình chấm điểm. Thuật toán khớp là một tìm kiếm theo chiều sâu xác định luận trên đồ thị tri thức. Các ứng viên ở mỗi bước được sắp xếp theo `(timestamp, element_id)` trước khi tìm kiếm bắt đầu. Không có lần đọc đồng hồ thực, không có hạt giống ngẫu nhiên. Với cùng tệp nhật ký và cùng thư viện kịch bản, Augur luôn tạo ra cùng danh sách phát hiện được xếp hạng.

Điều này làm cho Augur:
- **Có thể kiểm tra** — bạn có thể truy tìm chính xác nút đồ thị nào khớp với tiêu chí bước nào
- **Có thể kiểm thử** — bộ kiểm thử có 1164 khẳng định chạy engine đầy đủ với đầu vào cố định và khẳng định đầu ra chính xác
- **Đáng tin cậy** — một nhà phân tích có thể giải thích mọi phát hiện cho quản lý mà không cần "mô hình đã nghĩ như vậy"

Lớp AI (tùy chọn, tách biệt khỏi chấm điểm) chỉ dùng để *sáng tạo các kịch bản mới* ngoại tuyến — nó không chạm vào đường chấm điểm.

---

## Chứng minh engine biết khi nào *không* kích hoạt

Dễ dàng cho thấy một bộ phát hiện sáng đèn khi có một cuộc tấn công. Câu hỏi khó hơn — và thành thật hơn — là liệu nó có *im lặng* khi cần phải im lặng: nó có thực sự từ chối một chuỗi gần-nhưng-chưa-hẳn khớp không?

Augur kiểm định ranh giới này một cách trực tiếp. Một bộ kiểm thử độ bền (robustness harness) lấy trace tổng hợp hoàn hảo của một kịch bản và *biến đổi* nó dọc theo từng cổng (gate) mà engine thực thi:

- **Bỏ một bước** — xóa các sự kiện của một bước; engine phải giảm xuống đúng proximity mà phần tiền tố còn lại quy định.
- **Đẩy quá cổng thời gian** — dịch một bước một giây ra ngoài cửa sổ thời gian của nó; tiền tố đã khớp phải bị cắt ngay tại đó.
- **Di dời ra ngoài vùng** — chuyển bước neo (anchor) vào sai vùng mạng; cổng không gian phải từ chối toàn bộ kết quả khớp.
- **Phá vỡ liên kết cùng-host** — tách một bước `same_host` sang một máy khác; chuỗi phải dừng tại điểm gãy.

Với mỗi biến đổi, bộ kiểm thử khẳng định engine tạo ra proximity *bắt buộc về mặt toán học* — không phải "thấp hơn", mà là chính xác giá trị mà spec quy định (ví dụ bỏ bước k của n phải cho ra `(k-1)/n`). Nếu bất kỳ cổng nào không từ chối như yêu cầu, lần chạy thất bại:

```bash
uv run python -m augur.metrics --fail-on-robustness
```

Điều này biến "engine không kích hoạt sai" từ một hy vọng thành một cổng kiểm soát hồi quy được kiểm tra, xác định luận. Đây là một bằng chứng toàn vẹn-cấu-trúc trên thư viện kịch bản — không phải một tuyên bố về một đối thủ thực — nhưng nó chứng minh các cổng thời gian, không gian, và liên kết thực sự *từ chối*, chứ không chỉ là đường thuận lợi kích hoạt.

---

## Hỗ trợ đa OS

Augur chuẩn hóa nhật ký từ ba họ OS qua các bộ chuẩn hóa riêng biệt:

- **Windows** — sự kiện Sysmon (event ID 1, 7, và thẻ hành vi EDR)
- **Linux** — auditd (EXECVE, SYSCALL, và thẻ hành vi EDR)
- **macOS** — Endpoint Security Framework (ES_EVENT_NOTIFY_EXEC, MMAP, và thẻ hành vi EDR)

Cả ba đường đều tạo ra cùng cấu trúc `NormalizedEvent`, vì vậy engine và tất cả 40 kịch bản hoạt động giống hệt nhau bất kể OS nguồn. Một nguồn nhật ký duy nhất có thể chứa các sự kiện từ cả ba họ OS đồng thời — registry bộ chuẩn hóa điều phối dựa trên trường `source_type` trong mỗi sự kiện.

Các kịch bản cloud-stub (`SCEN-CLD-*`) hoạt động qua telemetry endpoint: chúng phát hiện các hành vi trên các máy tương quan với hoạt động nhắm mục tiêu cloud (ví dụ đánh cắp thông tin xác thực tiếp theo là sử dụng công cụ API cloud). Các bộ chuẩn hóa CloudTrail hoặc M365 đầy đủ là một dự án tương lai.

---

## Đầu ra trông như thế nào

Chạy `make engine` với nhật ký demo đa OS in ra:

```
========================================================================
Augur — 2 scenario(s) matched (min_proximity=0.3)
========================================================================
[CRITICAL ] Credential Theft via LSASS comsvcs MiniDump
           SCEN-WIN-001 — 5/5 steps — 100% — hosts: HR_User_PC
[CRITICAL ] Ransomware Staging via Shadow Copy Deletion
           SCEN-WIN-009 — 3/4 steps — 75% — hosts: File_Server_01
           missing: Ransom_Note_Drop
========================================================================
```

Dashboard tại `http://127.0.0.1:8000` chuyển mỗi lần phát hiện thành một thẻ với:

- Một **thanh gần kề** (ví dụ 75%) hiển thị mức độ tiến triển của chuỗi tấn công trong nháy mắt
- Một **phân tích từng bước** — xanh lá cho các bước đã khớp, xám cho các bước còn thiếu, mỗi bước hiển thị host, timestamp, và bằng chứng
- **Các truy vấn KQL và Sigma** bạn có thể dán trực tiếp vào SIEM để săn lùng bước còn thiếu hoặc xác nhận kết quả khớp
- Một **thanh trượt min-proximity** để hạ ngưỡng và phát hiện các tín hiệu giai đoạn sớm hơn

`Finance_User_PC` cũng có trong nhật ký — nó chạy Chrome và Notepad, tải các DLL đã ký. Không phát hiện cho host đó. Engine không kích hoạt trên nhiễu loạn.

---

## Từ phát hiện đến sự cố khép kín — vòng lặp của nhà phân tích

Một danh sách phát hiện được xếp hạng là *điểm bắt đầu* của một ngày làm việc của nhà phân tích, không phải điểm kết thúc. Một cuộc tấn công thực hiếm khi xuất hiện dưới dạng một phát hiện gọn gàng — nó rải rác qua nhiều kịch bản, host, và kỹ thuật. Vì vậy nền tảng khép kín vòng lặp *xung quanh* engine, mỗi bước đều bổ sung và chỉ-đọc:

1. **Gom cụm.** Các phát hiện liên quan được tương quan thành một **sự cố (incident)** duy nhất — được nhóm lại vì chúng chia sẻ một host hoặc chia sẻ một kỹ thuật MITRE. Một chiến dịch, một hạng mục công việc, thay vì năm thẻ rời rạc. (Một cách thành thật: đây là một tương quan trên *corpus này*, không phải một chiến dịch đối thủ đã xác nhận hay một tuyên bố di chuyển ngang — các phần tử đơn lẻ vẫn là sự cố một-thành-viên, không bị loại bỏ.)
2. **Phản ứng.** Mỗi sự cố gập lại thành một **runbook phản ứng hợp nhất** duy nhất — hợp của các playbook tiêu chuẩn, dẫn xuất theo chiến thuật (ngăn chặn / loại bỏ / khôi phục / xác nhận) cho các kịch bản của nó, được hợp nhất và khử trùng lặp.
3. **Báo cáo.** Sự cố cùng với phản ứng của nó được lắp ráp thành một **báo cáo hậu sự cố** xác định luận (JSON và Markdown) bạn có thể bàn giao — một sự lắp ráp thành thật của một tương quan engine và một mẫu tiêu chuẩn, không bao giờ là một câu chuyện nhân quả riêng biệt.

Không bước nào trong số này chạy lại hay tái cân nhắc engine. Các phát hiện được tính một lần; mọi thứ phía sau là một phép gập thuần túy trên chúng.

### Lớp phủ thông tin tình báo mối đe dọa

Một nhà phân tích có thể dán một watchlist CTI thực — hash tệp, domain, địa chỉ IPv4 và IPv6, khối CIDR, kỹ thuật ATT&CK — và Augur cho thấy cái gì sáng đèn trên telemetry Windows, Linux, và macOS trong một lần đọc duy nhất, được tổng hợp theo host và mức độ quan trọng.

Sự thành thật ở đây mang tính cấu trúc, không phải một tuyên bố miễn trừ gắn thêm sau đó. Telemetry tổng hợp sử dụng **các dải tài liệu IANA** — RFC 5737 cho IPv4, dải `2001:db8::/32` của RFC 3849 cho IPv6 — vốn được dành riêng và *không bao giờ* có thể trùng với một địa chỉ thực. Vì vậy một kết quả khớp xác nhận rằng đường ống săn lùng hoạt động từ đầu đến cuối; nó không bao giờ tuyên bố về mức độ phổ biến trong thế giới thực. Và ở nơi một nguồn OS thực thực sự không thể mang một tín hiệu — auditd không phân giải DNS, và macOS ESF ổn định không phát ra sự kiện DNS hay socket — telemetry đó được mô hình hóa như một lớp phủ agent/EDR rõ ràng và *được dán nhãn như vậy*, không bao giờ giả mạo là gốc. Các loại chỉ báo mà corpus thực sự không thể hỗ trợ được từ chối một cách thành thật thay vì âm thầm khớp với không gì cả.

---

## Kịch bản và dữ liệu mẫu — hai nguyên liệu

Mọi người hay nhầm lẫn hai thứ này. Chúng là những thứ khác nhau:

| | Kịch bản | Dữ liệu mẫu |
|---|----------|------------|
| Nó là gì | Một quy tắc — "tờ truy nã" cho một cuộc tấn công | Một bản ghi — "cảnh quay camera an ninh" về những gì đã xảy ra |
| Định dạng | Tệp YAML trong `scenarios/<tactic>/` | Tệp JSON Lines trong `sample_data/` |
| Chứa | Các bước, cửa sổ thời gian, ràng buộc vùng, tiêu chí khớp | Các sự kiện nhật ký thô: tiến trình chạy, file được tải, kết nối được thực hiện |
| Trong sản xuất | Bạn giữ và mở rộng thư viện | Bạn thay thế bằng nhật ký SIEM/EDR thực của bạn |
| Engine | Khớp *theo* những này | Tìm kiếm *qua* cái này |

Dữ liệu mẫu đi kèm với Augur là đại diện PoC cho nhật ký thực, không thay thế cho việc kết nối Augur với đầu ra EDR hoặc SIEM thực của bạn.

---

## Thêm một kịch bản

Một kịch bản là một tệp YAML. Trình tải nhận tất cả `*.yaml` trong `scenarios/` đệ quy — không cần thay đổi mã.

```bash
cp scenarios/credential_access/win_lsass_comsvcs.yaml scenarios/credential_access/my_new_attack.yaml
```

Chỉnh sửa bốn phần:

1. **Siêu dữ liệu** — `scenario_id` duy nhất (có tiền tố OS: `SCEN-WIN-NNN`, `SCEN-LNX-NNN`, `SCEN-MAC-NNN`), tên, mức độ nghiêm trọng, ánh xạ MITRE, `os_family` tùy chọn.
2. **Ràng buộc không gian** — vùng nào áp dụng, chỉ tài sản quan trọng hay không.
3. **Các bước** — có thứ tự, mỗi bước với `matching_criteria` (phải bao gồm `Node_Type`). Bước 1 không có `temporal_link`. Mỗi bước tiếp theo có một `temporal_link` trỏ đến `previous_step: <id - 1>` với một `link_scope` (`same_host`, `cross_host`, hoặc `any`) và một cửa sổ thời gian.
4. **Đầu ra săn lùng** — ít nhất một truy vấn KQL hoặc Sigma.

Xác nhận bằng:

```bash
uv run pytest tests/test_scenario_library.py
```

Tài liệu tham khảo đầy đủ cho mọi toán tử khớp (`regex`, `in`, `equals`, `exists`), mọi khóa tiêu chí, và ngữ nghĩa `temporal_link` có trong [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md).

---

## Những giới hạn thành thật

Augur là một nền tảng PoC với logic phát hiện thực, không phải một sản phẩm thương mại sẵn sàng cho sản xuất. Một vài điều cần ghi nhớ:

- **Khả năng phát hiện = 100% một phần là do cấu trúc.** Các kịch bản được viết để thân thiện với synth. Trình giả lập PoC tạo ra nhật ký thực hiện chúng hoàn hảo. Nhật ký đối thủ thực lộn xộn hơn.
- **Tỷ lệ FP = 0.0 được đo trên corpus lành tính tổng hợp.** Corpus đó sạch theo cấu trúc. Telemetry sản xuất thực sẽ có nhiều biến thể hơn; kiểm định trên dữ liệu EDR thực chưa được thực hiện.
- **Các kịch bản cloud-stub** xấp xỉ hoạt động cloud qua các sự kiện cấp endpoint. Chúng không phải là các phát hiện cloud-native đầy đủ.
- **Trình giả lập là đại diện PoC** cho nhật ký máy thực, hữu ích cho kiểm thử và trình diễn.

Những lưu ý này không phải là lỗi — chúng là phạm vi thành thật của một engine xác định luận Phase 1. Nền tảng được thiết kế để mở rộng: các bộ chuẩn hóa thực cho các nguồn nhật ký bổ sung, tích hợp telemetry thực, và lớp generative tùy chọn để mở rộng thư viện kịch bản.

Sợi chỉ xuyên suốt đằng sau mọi tính năng trong tài liệu này là một quy tắc: **nền tảng phát triển *xung quanh* một engine xác định luận không bao giờ bị thay đổi.** Gom cụm sự cố, runbook hợp nhất, báo cáo hậu sự cố, lớp phủ thông tin tình báo mối đe dọa, bộ kiểm thử độ bền — mỗi thứ đều bổ sung, chỉ-đọc, và mù về mặt cấu trúc đối với đường chấm điểm của engine. Engine kích hoạt hôm nay sẽ kích hoạt giống hệt từng byte vào ngày mai, bất kể bao nhiêu nền tảng tích tụ xung quanh nó.

---

## Tham chiếu nhanh

```bash
make install    # uv sync (cài đặt một lần)
make test       # 1164 kiểm thử
make engine     # in phát hiện, thoát
make demo       # in phát hiện + mở dashboard tại http://127.0.0.1:8000
make up         # stack Docker đầy đủ (app + Neo4j)
make down       # dừng stack Docker
```

Các lệnh trực tiếp:

```bash
uv run python -m augur.demo --no-serve
uv run python -m augur.demo --logs sample_data/acceptance/demo_multi_os.jsonl --min-proximity 0.20
uv run python -m augur.demo --logs sample_data/corpus/enterprise_day.jsonl
```

Quay lại [README dự án](README.md).
