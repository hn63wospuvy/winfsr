# 01 — Nguyên tắc và kiến trúc ABI 2.1

Trạng thái: **ABI 2.1 — chuẩn tắc**.

Tài liệu này xác lập invariant áp dụng cho mọi module kernel, daemon SDK, transport,
control path và passthrough path. Tài liệu sau chỉ được làm chi tiết hơn, không được
làm yếu các invariant này.

## 1. Invariant cấp cao

1. **Correctness trước performance.** Windows filesystem semantics, toàn vẹn dữ
   liệu và security boundary không phụ thuộc một optimization tùy chọn.
2. **Kernel không tin daemon.** Mọi byte, cursor, completion, mapping descriptor,
   handle, identity và status từ user mode đều là hostile input.
3. **Fast path cố định, control path có version.** SQE có đúng 128 byte và CQE có
   đúng 64 byte. Control blob mở rộng bằng prefix versioned; không tái diễn giải
   field cố định trong cùng ABI major.
4. **Một writer cho mỗi authoritative field/page.** Mapping protection và protocol
   ownership phải cùng thực thi quy tắc này.
5. **Kernel giữ quyền quyết định Windows semantics.** Provider cung cấp dữ liệu;
   kernel quyết định authorization, share/oplock và cache policy.
6. **Một cache domain cho mỗi virtual file.** Passthrough không được tạo cache
   domain thứ hai nhìn thấy bởi application.
7. **Identity có phạm vi rõ ràng.** Transport identity, namespace identity, durable
   mutation identity, boot identity và session identity không được thay thế lẫn
   nhau.
8. **Không giữ thread-owned synchronization qua daemon wait.** Wait phải có
   lifetime/rundown riêng và state được revalidate sau khi reacquire.
9. **Fail safe, không silent corruption.** Mỗi lỗi phải được phân lớp để fail đúng
   request, session, volume hoặc fail-fast khi kernel memory đã được chứng minh hỏng.

## 2. Threat model và trust boundary

### 2.1 Thành phần được tin cậy

Trust base gồm Windows kernel, I/O Manager, Cache Manager, Memory Manager và phần
FSRING kernel đã được verify theo hợp đồng này. Việc code nằm trong Rust không tự
động làm nó trusted; mọi `unsafe`/FFI boundary vẫn phải có contract và validation.

### 2.2 Thành phần không được tin cậy

Kernel MUST coi tất cả nguồn sau là không đáng tin cậy:

- daemon, kể cả daemon đã vượt qua bước attach nhưng sau đó bị compromise;
- toàn bộ shared section nhìn từ peer: CQE/SQE peer-owned, cursor, sequence,
  heartbeat, park state, slot bytes và notify data;
- mọi user/application input đến qua IRP, IOCTL, FSCTL, pathname, EA, reparse data,
  security descriptor hoặc buffer;
- pointer, handle, token, file identity, generation, offset, length, count, enum,
  flag, alignment, status và string do user mode cung cấp;
- backing filesystem/data khi được dùng cho passthrough.

Kernel MUST single-fetch dữ liệu có thể đổi đồng thời vào snapshot kernel-owned,
rồi kiểm tra size, alignment, bounds, checked arithmetic, enum/flag allowlist,
reserved-zero, ownership, generation, `session_epoch` và lifetime trước khi dùng.
Không field wire nào được hiểu là raw kernel pointer. Handle donation phải đi qua
authenticated control path, được reference/validate thành kernel-owned object trước
khi shared memory chỉ giữ opaque identifier.

Một daemon độc hại có thể từ chối phục vụ volume của chính nó; điều đó không cho
phép bugcheck, privilege escalation, truy cập volume khác, stale-memory reuse hoặc
lộ dữ liệu ngoài buffer/range đã cấp. Untrusted input không được đi tới unchecked
dereference, integer wrap, panic hoặc system bugcheck.

### 2.3 Ngẫu nhiên kernel

Mọi giá trị ngẫu nhiên kernel cần cho ABI (MountId, OpId khó đoán, khóa
`per_boot_retire_key`, boot identity) MUST được sinh ở PASSIVE_LEVEL bằng
`BCryptGenRandom` với system-preferred RNG qua kernel CNG import — có mặt ở cả
profile Windows 7. Time, counter, PID, `RtlRandom*` và byte do daemon cung cấp
không bao giờ là entropy. Không có fallback yếu hơn: thất bại làm hỏng khởi tạo
BootContext/DriverEntry hoặc trả INSUFFICIENT_RESOURCES trước khi một SETUP
MountId được công bố. Field ngẫu nhiên bắt buộc nonzero được sinh vào buffer
riêng đã zero và thử lại tối đa tám lần nếu toàn bộ số nguyên lấy mẫu bằng
không; tám lần zero liên tiếp fail closed.

## 3. Thành phần và data flow

| Thành phần | Trách nhiệm chuẩn tắc |
|---|---|
| Application + Windows I/O stack | phát sinh IRP và quan sát Windows filesystem semantics |
| FSRING kernel FSD | object model, access/share/oplock/lock semantics, cache/MM integration, request lifetime, validation và completion arbitration |
| Shared-memory transport | truyền wire artifact giữa hai phía với one-writer ownership, bounded work và explicit publication ordering |
| Authenticated control path | setup/attach, mapping và handle/token donation gắn với process, mount và session hiện tại |
| User-mode daemon/provider | thực thi provider contract, durable journal/replay khi đã thương lượng, và chỉ ghi region được cấp quyền |
| PT engine + backing filesystem | raw data path có rundown/coherency; không thay thế virtual filesystem semantics của FSRING |

Luồng ring không biến shared SQE thành nguồn sự thật. Kernel giữ canonical immutable
request descriptor ngoài vùng daemon có thể map; SQE chỉ là bản serialization. CQE
được snapshot và validate trước khi có thể chọn terminal owner của request.

## 4. Fixed fast path và versioned control

ABI 2.1 dùng hai tầng:

- SQE cố định 128 byte và CQE cố định 64 byte cho hot path;
- READ giữ fixed payload inline; WRITE và mọi control blob khác đi qua
  `ControlHeader` versioned với `CONTROL_VERSION_V1 = 1` hoặc
  `CONTROL_VERSION_V2 = 2` theo từng schema (`03-messages.md` là registry);
- control blob bắt đầu bằng `{struct_size, struct_version, required_flags}` và có
  thể thêm optional tail mà receiver cũ bỏ qua theo `struct_size`;
- unknown required flag hoặc fixed-field reinterpretation không được đoán; version
  không hợp lệ fail REVISION_MISMATCH, required flag không hỗ trợ fail
  NOT_SUPPORTED, cấu trúc hỏng fail INVALID_PARAMETER theo đúng thứ tự ưu tiên
  trong `02-transport.md`.

Kích thước, alignment, offset và registry number chỉ lấy từ `fsring-abi/`. Không
module nào được tạo một Rust/C mirror riêng rồi giả định rằng compiler sẽ giữ chúng
đồng bộ.

## 5. Thương lượng protocol và OS capability

Negotiation có hai `FeatureSet` 128-bit độc lập:

- `protocol_features` mô tả hành vi protocol mà hai phía triển khai, như PT, mmap,
  hot restart, exactly-once mutation, security, reparse và token donation;
- `os_capabilities` mô tả facility thực sự có trong kernel/OS đang chạy, như protected
  MDL mapping, coherency DDI mới hoặc ARM64.

Kernel là authority duy nhất của `os_capabilities`; daemon không được tự khẳng định
một OS facility. Required set MUST là subset của negotiated set. Thiếu required
feature/capability làm mount hoặc operation liên quan fail xác định bằng
`STATUS_NOT_SUPPORTED`.

Lựa chọn feature của ABI 2.1 là **tất định**, không có chính sách per-mount ẩn:

- `selected = offered_features & runtime_protocol_mask`, trong đó
  `runtime_protocol_mask` xuất phát từ profile mask và chỉ bị runtime probe
  **xóa bớt** bit (không bao giờ thêm): MAPPED_IO bị xóa khi thiếu MDL
  no-write/no-execute; cặp restart bị xóa khi thiếu service identity;
- SECURITY là base feature bắt buộc của kernel: daemon không chào SECURITY bị
  từ chối NOT_SUPPORTED, nên không tồn tại session với per-file security không
  xác định;
- `HOT_RESTART` và `EXACTLY_ONCE` là **cặp không tách rời** trong cả ba tập
  offered/required/selected (cùng có hoặc cùng không); bit lệch nhau là
  INVALID_PARAMETER. Yêu cầu cặp này đòi hỏi requestor process chạy dưới đúng
  một service SID dạng `S-1-5-80-a-b-c-d-e`; thiếu prerequisite đó, yêu cầu
  cặp fail ACCESS_DENIED;
- các bit registry-stable nhưng **không chọn được** trong 2.1: REPARSE (5),
  TOKEN_DONATION (6), NOTIFY_NAMES (8), CASE_SENSITIVE_NAMES (9). Require một
  bit như vậy fail NOT_SUPPORTED; mỗi bit chỉ có thể kích hoạt bằng một hợp
  đồng minor tương lai có tên;
- bit offered không biết được bỏ qua (không bao giờ phản xạ thành selected);
  bit required không biết fail NOT_SUPPORTED; `SessionResultV1` báo cáo chính
  xác selected/detected set dùng cho session.

Protocol feature và OS capability không được trộn bitset, suy ra từ nhau, hoặc dùng
để đổi physical layout. Post-baseline DDI phải runtime-resolve. Đường compatibility
có thể chậm hơn nhưng MUST giữ nguyên semantics và security; ví dụ profile Windows 7
SP1 dùng kernel-owned K2U copy cho application WRITE khi không có protected no-write
MDL mapping.

## 6. One-writer page ownership

Shared section được tách theo page-aligned ownership. Writer duy nhất và quyền nhìn
của peer là:

| Region/state | Writer duy nhất | Quyền của phía còn lại |
|---|---|---|
| Global/config header | Kernel | Daemon read-only |
| SQ payload, per-entry sequence và tail | Kernel producer | Daemon read-only |
| SQ head | Daemon consumer | Kernel đọc như hostile cursor |
| CQ payload, per-entry sequence và tail | Daemon producer | Kernel đọc/validate như hostile input |
| CQ head và kernel statistics | Kernel consumer | Daemon read-only |
| K2U slot arena | Kernel | Daemon read-only |
| U2K slot arena | Daemon trong grant hợp lệ | Kernel validate trước khi dùng |

Notification-name arena bị **vô hiệu hóa** trong ABI 2.1
(`GlobalHeader.notify_names` bằng đúng `{0, 0}`); không tồn tại vùng ghi nào
khác ngoài bảng trên. Một side MUST NOT ghi field thuộc side kia, kể cả để
"sửa" cursor hoặc clear cell. Kernel sở hữu slot allocation, generation, bounds,
direction, grant lifetime, request table và terminal completion arbitration.

One-writer không biến peer cursor thành trusted state. Mỗi quan sát cursor/sequence
phải kiểm tra regression, checked distance theo capacity, generation/session và
impossible state. Retry do concurrent publication phải hữu hạn; persistent
contradiction là `PROTOCOL_FAULT` cấp session. Kernel không được spin vô hạn trên
memory do daemon kiểm soát.

## 7. Kernel-only Windows policy

Daemon cung cấp namespace metadata, content và self-relative security descriptor,
nhưng **kernel là bên duy nhất** quyết định:

- access check, traverse/parent check, privilege handling và actual granted access;
- share access, delete-pending, byte-range lock và oplock state;
- create/open transaction visibility, cleanup/close ordering và cancellation owner;
- cache policy, Cache Manager/MM synchronization, EOF/VDL publication và coherency;
- donated handle/token có đúng type, access, process, mount và session hay không.

Daemon không được trả một "allow/deny" cuối cùng để kernel tin thẳng. Provider-returned
NTSTATUS phải nằm trong allowlist phù hợp operation hoặc được normalize thành safe
failure. Performance lease chỉ được bỏ qua công việc thừa khi generation chính xác
còn hợp lệ; lease expiry không bao giờ là correctness boundary.

## 8. Một Cache Manager domain

Mỗi virtual stream/FCB MUST có đúng một `SECTION_OBJECT_POINTERS` và một internal
stream `FILE_OBJECT` làm Cache Manager/MM domain. Chúng tồn tại cho đến khi mọi cache
map, data/image section, mapped view và dependent request đã rundown.

PT là raw-data route bên dưới virtual paging path. Backing `FILE_OBJECT` không được
trở thành user-visible cached open hoặc cache domain thứ hai. Route grant/revoke có
thể thay đổi nhưng virtual section pointers và mapping identity không đổi. Purge
không được dùng như bằng chứng giả rằng active mapping đã biến mất.

## 9. Identity và phạm vi lifetime

| Identity | Phạm vi và invariant |
|---|---|
| `FileId` | định danh ổn định của một provider stream; giữ nguyên qua rename, hard-link change và provider restart; không tái sử dụng cho stream khác còn sống |
| `LinkId` | định danh một namespace link; nhiều link có thể trỏ cùng `FileId`; rename thay đổi link state, không thay stream identity |
| `req_id` / `ReqId` | transport identity 64-bit chỉ trong session, gồm `generation:40` và `slot_index:24`; không phải durable mutation identity; không gian slot-index được phân hoạch giữa application và các system lane dành riêng (`02-transport.md`) |
| `op_id` / `OpId` | identity 128-bit được cấp ngẫu nhiên/khó đoán cho mutation; giữ nguyên qua retry, daemon restart và replay để exactly-once dedupe |
| `SlotToken` | capability 64-bit generation-stamped cho một slot được cấp (`class:2 \| index:20 \| generation:42`, generation nonzero không wrap); là nghĩa duy nhất của `BufferRef.token` loại SLOT trong 2.1 |
| `TransactionId` | chỉ mục durable 128-bit duy nhất trong MountId cho một CREATE hai pha; sống sót qua restart cùng open-prepare record |
| `kernel_open_id` | u64 đơn điệu nonzero theo mount, định danh một open xuyên suốt LIVE→CLEANED→CLOSE và replay; không bao giờ tái sử dụng |
| `BootInstanceId` | identity 128-bit của một lần boot, chỉ được xác lập qua SessionResult/RetireMountResult đã xác thực; suy đoán reboot từ thời gian/PID bị cấm |
| `session_epoch` | giá trị mới cho mỗi daemon session; mọi request/completion/session-bound object phải khớp epoch hiện hành |
| `volume_commit_sequence` | bộ đếm u64 toàn mount, tăng ngặt cho mỗi transaction đã commit (COMMIT_OPEN, WRITE, MUTATE, RESIZE, external change); zero không hợp lệ; không wrap — cạn số là retire mount |

Completion cũ, provider cookie cũ, transaction cookie cũ hoặc mapping cũ không được
hoàn tất request của session mới. Kernel cấp `req_id`, kiểm tra full generation,
slot, opcode và `session_epoch`. Notification dùng CQ `kind` riêng và acknowledgement
token riêng, không chiếm bit của request identity.

## 10. Concurrency, wait và lifetime

Quy tắc tuyệt đối là: **no thread-owned lock/resource across a daemon wait**.
ERESOURCE, mutex, push lock, spin lock hoặc callback-owned synchronization không được
giữ trong lúc chờ daemon.

Một operation cần daemon MUST thực hiện theo mẫu:

1. giữ lock để validate và snapshot canonical state/generation;
2. lấy reference/rundown cần thiết, tạo immutable request descriptor;
3. nhả toàn bộ thread-owned lock/resource;
4. publish request và chờ/cancel bằng request state machine;
5. reacquire lock theo global order, revalidate epoch/generation/state;
6. commit đúng một terminal transition hoặc retry/rollback theo operation contract.

Ring completion có thể về khác thứ tự submit. Ordering bắt buộc như per-CCB sequence,
CLEANUP barrier và CLOSE-after-CLEANUP phải được object/request state machine thực
thi; không được dựa vào scheduling may mắn của worker.

## 11. Error classes và fail-safe behavior

| Lớp lỗi | Ví dụ/nguồn | Phản ứng bắt buộc |
|---|---|---|
| Request/provider error | operation hợp lệ trả NTSTATUS nằm trong allowlist | fail đúng request; giữ session nếu state còn nhất quán |
| Resource/transient error | thiếu tài nguyên có chặn, stale generation có thể retry | bounded retry hoặc fail request; không spin/wait vô hạn |
| Protocol fault | malformed/contradictory daemon state, cursor impossible/regression, wrong epoch/generation/opcode, nonzero reserved field | quarantine session, chặn publication mới và đi vào GRACE/teardown; không tiếp tục dùng shared state |
| Daemon death/restart | process/control channel chết mà không có bằng chứng malformed wire | arbitration riêng với protocol fault; invalidate section cũ, rundown/quarantine mapping, tạo section và `session_epoch` mới; replay chỉ theo durable contract hoặc teardown |
| Volume invariant failure | size/namespace/cache state không thể reconcile an toàn | controlled volume failure hoặc reconciliation; không silent corruption |
| Proven kernel-memory corruption hoặc invariant impossibility | ownership/lifetime nội bộ được chứng minh đã hỏng | fail-fast thay vì tiếp tục làm hỏng kernel state khác |

Daemon-controlled value có thể làm fail request, session hoặc volume nhưng không được
trực tiếp gây panic/bugcheck. Protocol fault và daemon death phải hội tụ vào một
cancel-safe teardown path sau khi đã phân xử owner; không request, mapping, MDL, slot
hoặc object nào được free/reuse trước khi rundown hoàn tất.

## 12. Nguyên tắc performance

Hot path SHOULD tránh allocation, copy và global contention không cần thiết; song
mọi pool, retry và inflight work MUST có bound. Parallelism được tăng bằng nhiều ring
pair/worker phù hợp ownership thay vì thêm writer/consumer trái topology.

Một tối ưu chỉ hợp lệ khi:

- không thay authority, visibility, ordering hoặc lifetime;
- không bỏ validation của hostile input;
- có fallback giữ nguyên semantics trên OS/profile thiếu capability;
- vượt correctness, stress và performance regression gates trong
  `12-test-plan.md`.

Khi performance và correctness xung đột, implementation MUST chọn correctness và ghi
nhận điểm nghẽn để tối ưu bằng một thiết kế có thể chứng minh/test được.

## C4 source-complete architecture

The driver image implements exactly one protocol feature: `SECURITY`. The
kernel's `IMPLEMENTED_PROTOCOL_MASK` is `FeatureSet { words: [0x10, 0] }`, and
feature selection intersects the profile-filtered offer with it *before* any
request-specific policy. An optional feature the image does not implement is
omitted from the selection; a **required** one fails `NOT_SUPPORTED` before a
MountId is burned. Advertising a capability the image does not have is the one
failure this mask exists to make impossible.

C4 uses four native object roles rather than one device:

1. `\Device\FsRing` — the secure provider control endpoint, `FILE_DEVICE_UNKNOWN`,
   never registered as a filesystem;
2. `\FileSystem\FsRing` — a separate named `FILE_DEVICE_DISK_FILE_SYSTEM`
   registration control device, never exposed through the provider DOS link;
3. one named `FILE_DEVICE_VIRTUAL_DISK` VDO per active MountId, created by SETUP
   so the I/O manager supplies its VPB;
4. one unnamed `FILE_DEVICE_DISK_FILE_SYSTEM` mounted-volume device per mounted
   VDO, stored in the VPB and owning the VCB.

Every device extension begins with a closed device-kind tag, and each common
major-function thunk reads that tag before it projects an extension. A provider
path therefore cannot reinterpret a mounted volume as a control device.
