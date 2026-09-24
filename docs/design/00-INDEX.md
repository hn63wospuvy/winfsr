# FSRING ABI 2.1 — mục lục và phạm vi chuẩn tắc

Trạng thái: **ABI 2.1 — chuẩn tắc cho toàn bộ 13 tài liệu 00–12**. Tính đến
Wave 15, kiểm chứng toàn dự án ở mức nguồn và tái tạo tất định cả hai archive đã
hoàn tất và ghi lại SHA-256; nhờ đó bộ tài liệu là **mạch lạc và tái lập được**.
Bộ tài liệu **vẫn CHƯA được tuyên bố sẵn sàng phát hành đầy đủ**: các release
gate chỉ chạy trên môi trường thật (Driver Verifier, HLK/WHCP, ma trận hiệu
năng, phần cứng Win7/Win10/Win11) và việc ký artifact còn đang chờ. Không
release gate nào được tuyên bố xanh chỉ dựa trên tài liệu.

ABI 2.1 là minor đầu tiên được phép triển khai hoặc quảng bá. ABI 2.0 là bản
nháp tiền phát hành không tương tác được: SETUP thương lượng một khoảng minor
tường minh nhưng MUST NOT chọn minor 0; peer chỉ chào 2.0 bị từ chối bằng
REVISION_MISMATCH; một khoảng chứa cả 0 và 1 luôn chọn 1. Không được giải mã
cấu trúc v1 như v2, tái sử dụng section của phiên cũ, hoặc tự động hạ cấp wire
protocol.

## 1. Danh tính ABI và phiên bản package

Danh tính bắt buộc, khớp byte-for-byte giữa Rust, C header sinh ra và C test:

| Hằng số | Giá trị |
|---|---:|
| `FSRING_ABI_MAJOR` | 2 |
| `FSRING_ABI_MINOR` | 1 |
| `FSRING_ABI_MIN_COMPAT_MINOR` | 1 |
| Package `fsring-abi` | `0.2.1` |

Minor tương thích tối thiểu bằng minor hiện hành vì minor 0 không bao giờ được
thương lượng. Wire major giữ nguyên 2 vì layout SQE/CQE cố định không đổi.

## 2. Mục tiêu và thứ tự ưu tiên

FSRING là kiến trúc filesystem Windows theo hướng Rust, gồm kernel filesystem
driver, transport shared-memory và user-mode provider. Thứ tự ưu tiên bắt buộc là:

1. đúng semantics filesystem và không làm hỏng dữ liệu;
2. an toàn kernel và cô lập security boundary;
3. khôi phục xác định sau lỗi hoặc daemon restart;
4. hiệu năng steady-state.

Tối ưu hóa không được thay đổi semantics, làm yếu validation, hoặc trở thành điều
kiện để đảm bảo correctness/security. Passthrough, memory-mapped I/O và hot restart
là năng lực production của ABI 2.1, nhưng từng mount có thể không thương lượng các
năng lực không cần dùng.

## 3. Ngôn ngữ và thuật ngữ chuẩn tắc

- **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT** và **MAY** được
  hiểu theo RFC 2119/RFC 8174 khi viết hoa. Vi phạm MUST hoặc MUST NOT là lỗi.
- **Kernel** là FSRING filesystem driver và các thành phần kernel-mode thuộc nó.
- **Daemon** hoặc **provider** là process user-mode phục vụ một volume. Daemon và
  mọi dữ liệu do daemon ghi đều không đáng tin cậy.
- **Modern profile** là build `platform-win10`; đây là profile mặc định.
- **Legacy profile** là build riêng `platform-win7`; đây không phải runtime mode
  của modern binary.
- **Wire ABI** là mọi byte layout, alignment, offset, integer registry, bit
  allocation và quy tắc encode/decode đi qua shared section hoặc authenticated
  control path.
- **Session** là một lần daemon được xác thực và gắn với một mount bằng section mới
  cùng `session_epoch` mới.
- **Protocol fault** là trạng thái daemon/shared memory mâu thuẫn hoặc sai cấu trúc
  đủ nghiêm trọng để phải quarantine session, không chỉ fail một request.
- **Generated artifact** là đầu ra được tái tạo hoàn toàn từ nguồn chuẩn tắc; nó
  không phải nơi được phép sửa tay.
- **Tài liệu chuyển tiếp** là tài liệu chưa được viết lại theo ABI 2.1: nội dung
  của nó không chuẩn tắc, nhãn `STABLE` cũ (nếu có) không còn hiệu lực, và mọi
  mâu thuẫn với Rust registry hoặc tài liệu 00–09 được giải quyết nghiêng về
  nguồn có thứ tự ưu tiên cao hơn ở mục 4. Kể từ khi hoàn tất viết lại 00–12,
  KHÔNG tài liệu nào còn ở trạng thái này; định nghĩa được giữ lại như một quy
  tắc phân giải ưu tiên phòng khi một tài liệu về sau tụt lại sau crate.

## 4. Nguồn chuẩn tắc và generated artifacts

Thứ tự ưu tiên chuẩn tắc là:

1. Rust constants, wire types, semantic validators và golden tests trong
   `fsring-abi/`;
2. C header sinh ra (`fsring-abi/include/fsring_abi.h`) và C layout tests;
3. tài liệu chuẩn tắc `00-INDEX.md` đến `03-messages.md`;
4. các tài liệu subsystem 04–12 (nay đã được viết lại đầy đủ theo ABI 2.1).

Các bảng wire trong Markdown MUST khớp `fsring-abi/`. Nếu phát hiện bất kỳ sai
khác nào, release bị chặn: không implementation nào được tùy ý chọn một phía.
Rust source trong crate là nguồn sinh header; Rust layout tests và C
compile-time assertions phải chứng minh rằng hai ngôn ngữ quan sát cùng một ABI.

Hai cổng kiểm tra cơ học bắt buộc phải xanh trước mọi tuyên bố hợp lệ tài liệu:

- `scripts/verify_spec.py` — kiểm tra đúng tập tài liệu, UTF-8 sạch, các token
  bắt buộc của ABI 2.1 và sự vắng mặt của hợp đồng transport cũ;
- `scripts/verify_v21_registry.py` — ràng buộc registry 2.1 khớp nhau qua ba
  tầng Rust/header/C và chứng minh minor 0 không bao giờ được quảng bá.

Các file ZIP chỉ là **generated outputs** để phân phối. ZIP không có quyền ghi đè
Markdown unpacked hoặc `fsring-abi/`, không được sửa trực tiếp, và chỉ được tái tạo
sau khi toàn bộ source/gate liên quan đã xanh.

## 5. Platform profiles và package targeting

Kernel crate MUST bật đúng một trong hai platform feature. Bật cả hai hoặc không
bật feature nào là compile error.

| Profile | Feature/build | Hệ điều hành và kiến trúc | Quy tắc DDI | Package |
|---|---|---|---|---|
| Modern, mặc định | `platform-win10` | Windows 10 1507+ x64; Windows 10 1709+ ARM64; Windows 11 x64/ARM64 | Chỉ được static-import DDI có ở baseline Windows 10 1507. DDI sau baseline MUST được runtime-resolve và capability-gate. | INF/catalog modern riêng |
| Legacy | `platform-win7` với default features bị tắt | Windows 7 SP1 x64 | Chỉ được static-import DDI có ở Windows 7 SP1; DDI mới hơn dùng đường tương thích bảo toàn correctness. | INF/catalog legacy riêng |

Windows ARM64 là **modern-only**. Không có legacy ARM64 hoặc x86 profile. DDI
sau baseline được tìm bằng `MmGetSystemRoutineAddress`; thiếu DDI tùy chọn chỉ được
chọn đường tương thích đã định nghĩa, không được silent semantic downgrade.

Targeting của package MUST ngăn legacy package được ưu tiên thay cho modern package
trên Windows 10/11. Mọi profile được hỗ trợ dùng **cùng wire contract ABI 2.1**;
khác biệt OS chỉ xuất hiện qua build profile, `protocol_features` và
`os_capabilities`, không tạo một biến thể layout riêng.

## 6. Thứ tự đọc bộ tài liệu

Thứ tự dưới đây là chuẩn tắc. Tài liệu phụ thuộc giả định reader đã áp dụng đầy đủ
invariant của tài liệu đứng trước. Cột trạng thái phân biệt tài liệu chuẩn tắc
với tài liệu **chuyển tiếp** (chưa viết lại theo ABI 2.1, không chuẩn tắc).

| Thứ tự | Tài liệu | Phạm vi chính | Trạng thái |
|---:|---|---|---|
| 00 | `00-INDEX.md` | phạm vi, thuật ngữ, platform và release definition | chuẩn tắc |
| 01 | `01-principles-architecture.md` | threat model, trust boundary và invariant kiến trúc | chuẩn tắc |
| 02 | `02-transport.md` | shared section, layout vật lý, ring, control IOCTL, durable store và teardown | chuẩn tắc |
| 03 | `03-messages.md` | registry opcode/feature/flag, payload byte-exact và bản đồ hợp lệ V1→V2 | chuẩn tắc |
| 04 | `04-object-model.md` | VCB/FCB/LCB/CCB, namespace và stream identity | chuẩn tắc |
| 05 | `05-irp-dispatch.md` | IRP dispatch, OPEN, cleanup/close và Windows semantics | chuẩn tắc |
| 06 | `06-locking.md` | lock order, resource matrix, cancellation và rundown | chuẩn tắc |
| 07 | `07-cache-mm.md` | Cache Manager/MM, size/VDL, truncate và mapped I/O | chuẩn tắc |
| 08 | `08-passthrough.md` | raw-data passthrough, routing rundown và coherency | chuẩn tắc |
| 09 | `09-security.md` | access boundary, token/handle donation và hostile-input validation | chuẩn tắc |
| 10 | `10-lifecycle.md` | mount, daemon death, fresh attach, replay và teardown | chuẩn tắc |
| 11 | `11-rust-implementation.md` | crate boundary, WDK/SEH, unsafe contracts, build và packaging | chuẩn tắc |
| 12 | `12-test-plan.md` | correctness, fault injection, stress, compatibility và performance gates | chuẩn tắc |

Không được đọc một bảng riêng lẻ như một ngoại lệ đối với invariant ở tài liệu khác.
Khi hai yêu cầu dường như xung đột, implementation MUST dừng, giải quyết xung đột
trong nguồn chuẩn tắc và bổ sung regression test trước khi tiếp tục. Khi một tài
liệu chuyển tiếp mâu thuẫn với Rust registry hoặc tài liệu 00–09, phía chuyển
tiếp luôn thua.

## 7. Định nghĩa hoàn thành

### 7.1 Implementation complete

Một implementation chỉ được gọi là **complete** khi đồng thời thỏa mọi điều kiện:

- mọi MUST/MUST NOT trong toàn bộ 13 tài liệu 00–12 (nay đều đã chuẩn tắc) có
  code path và test tương ứng;
- `scripts/verify_spec.py` và `scripts/verify_v21_registry.py` xác nhận đúng
  tập tài liệu, UTF-8 sạch, token ABI 2.1 đầy đủ và không còn hợp đồng
  transport cũ;
- Rust ABI assertions, generated C header và C `sizeof`/`_Alignof`/`offsetof`
  assertions khớp byte-for-byte trên các target được yêu cầu;
- mọi đường untrusted-input, cancellation, timeout, daemon death, replay, teardown,
  Cache Manager/MM và PT rundown có negative/fault-injection coverage;
- các profile được hỗ trợ build mà không dùng static import vượt baseline;
- không còn lỗi correctness, security, data-corruption hoặc invariant chưa xử lý.

Pass một smoke test, compile một profile, hoặc đạt throughput mục tiêu riêng lẻ không
đủ để tuyên bố complete.

### 7.2 Release ready

Một implementation **release ready** chỉ khi đã complete và thêm tất cả điều kiện:

- toàn bộ release matrix và exit criteria trong `12-test-plan.md` xanh, gồm stress,
  recovery, compatibility, Driver Verifier và performance gates;
- modern và legacy package được build, target và kiểm tra độc lập theo
  `11-rust-implementation.md`; ARM64 chỉ nằm trong modern package;
- mọi required feature/capability thiếu đều fail xác định, không silent downgrade;
- generated headers, package inputs và archives được tái tạo từ đúng revision nguồn,
  kiểm tra tái lập, rồi mới ký/phân phối;
- không có gate bị bỏ qua, flaky failure chưa phân loại, hoặc waiver làm yếu
  correctness/security.

Tính đến Wave 15, việc kiểm chứng ở mức nguồn/tài liệu đã hoàn tất trên một
snapshot nguồn bất biến — Rust 1.82/stable/`no_std`/clippy/Loom, layout C
MSVC-x64 và clang-cl-ARM64, `verify_spec.py`, `verify_v21_registry.py`, quét
ngữ nghĩa cấm — và cả hai archive tất định đã được tái tạo và ghi lại SHA-256;
nhờ đó bộ 13 tài liệu là chuẩn tắc, mạch lạc và tái lập được. Đây KHÔNG phải là
definition complete theo §7.1: repo hiện chỉ gồm crate ABI `fsring-abi` cùng bộ
tài liệu, chưa có implementation driver kernel, nên các điều kiện §7.1 (mọi
MUST/MUST NOT có code path và test tương ứng; negative/fault-injection coverage
cho cancellation, timeout, daemon death, replay, teardown, Cache Manager/MM và
PT rundown) CHƯA được thỏa mãn. Do đó cả §7.1 (implementation complete) lẫn §7.2
(release ready) đều CHƯA đạt: ngoài phần implementation còn thiếu, các release
gate chỉ chạy trên môi trường thật — Driver Verifier, HLK/WHCP, giải mã rào cản
ARM64, ma trận hiệu năng, và các lần chạy Win7/Win10/Win11 trên phần cứng thật —
cùng việc ký artifact vẫn đang chờ (pending), không được coi là đã đạt nếu chưa
có bằng chứng thật. Mục lục vì vậy chỉ xác nhận bộ tài liệu đã mạch lạc và tái
lập được, và KHÔNG tuyên bố release-ready. Hiệu năng là release gate sau correctness. Một tối ưu chỉ được
nhận nếu tất cả gate correctness vẫn xanh và benchmark chứng minh không có
regression ngoài ngân sách đã được `12-test-plan.md` quy định.
