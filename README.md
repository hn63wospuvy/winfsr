# winfsr

**winfsr** is a Rust-first framework for writing Windows file systems in user
mode. It is inspired by [WinFsp](https://github.com/winfsp/winfsp) and aims to
become a replacement for it: a kernel file system driver, a shared-memory
transport, and a user-mode runtime that lets an ordinary program serve a
Windows volume.

> [!WARNING]
> **winfsr is under active development and is not usable yet.** It cannot
> mount a working drive today. The kernel driver is test-signed only, has not
> been verified on a live machine, and must never be loaded on a computer you
> care about. Crate APIs, the repository layout and build steps change often.

## Why another WinFsp?

[WinFsp](https://github.com/winfsp/winfsp) (Windows File System Proxy) lets
developers implement a Windows file system as a user-mode process, much like
FUSE on Linux. It is mature and widely used. winfsr keeps that goal and makes
different foundational choices:

- **Rust end to end.** The kernel driver is written in Rust on top of
  [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs), and
  so is the user-mode runtime. Hand-written kernel bindings are confined to
  one crate, and `unsafe` code is covered by static audits.
- **A shared-memory ring transport.** Requests and completions travel through
  submission and completion rings in a section shared by the driver and the
  user-mode provider, in the spirit of `io_uring`. The architecture and wire
  protocol are called **FSRING**, which is why the crates are named
  `fsring-*`.
- **A byte-exact, versioned ABI.** One `no_std` Rust crate, `fsring-abi`, is
  the single source of truth for every structure on the wire. A C header is
  generated from it, and both Rust and C tests pin every size, alignment and
  field offset.
- **The provider is untrusted.** Every byte that user mode writes into shared
  memory is treated as hostile input by the kernel. A misbehaving or crashing
  provider may fail its own volume, but it must not corrupt data or bring down
  the system.
- **Recovery is part of the design.** Daemon death, reattaching a fresh
  provider process, and replaying unfinished work are specified up front rather
  than added later.

The design fixes one order of priorities, and a lower one is never bought at
the cost of a higher one:

1. correct Windows file system semantics and no data corruption;
2. kernel safety and an isolated security boundary;
3. deterministic recovery after a failure or a provider restart;
4. steady-state performance.

## Architecture

```text
  Applications (Win32 / NT API)
              |
              v
     Windows I/O Manager
              |
              v
  +--------------------------+
  |  fsring-fsd              |   kernel file system driver (Rust, WDM)
  |  + fsring-core           |   WDK-free core: state machines, validation
  |  + fsring-sys            |   pinned kernel bindings
  +--------------------------+
        |  SQ ring    ^  CQ ring        one shared-memory section
        v             |                 per mounted volume
  +--------------------------+
  |  fsring-user             |   user-mode runtime: rings, dispatch, decoding
  +--------------------------+
              |
              v
  +--------------------------+
  |  provider, e.g. mirrorfs |   your file system logic
  +--------------------------+
              |
              v
      backing storage (an NTFS directory, a network service, ...)
```

In this design, a provider process opens the driver's control device and sets
up a **session**: the driver creates the shared section, maps the rings, and
binds the session to a mount. The driver turns I/O requests (IRPs) into ring
entries; the runtime decodes them, calls the provider, and writes completions
back. The kernel stays in charge of Windows semantics such as authorization,
sharing and cache policy; the provider supplies data. See
[Project status](#project-status) for how much of this path exists today.

The ABI also specifies Cache Manager and memory-mapped I/O integration,
raw-data passthrough to a backing file, and hot restart, where a crashed or
upgraded provider is replaced while the volume stays mounted.

### Supported platforms (target)

| Profile | Build feature | Windows versions |
|---|---|---|
| Modern (default) | `platform-win10` | Windows 10 1507+ x64, Windows 10 1709+ ARM64, Windows 11 x64/ARM64 |
| Legacy | `platform-win7` | Windows 7 SP1 x64 |

Both profiles speak the same ABI 2.1 wire protocol. The legacy profile is a
separate build and package, not a runtime mode of the modern driver.

## Project status

| Component | What it is | Status |
|---|---|---|
| [`fsring-abi`](fsring-abi/) | Wire ABI 2.1: ring layout, messages, validators, generated C header | ABI 2.1 defined and tested in Rust and C (x64 and ARM64 layouts) |
| [`fsring-user`](fsring-user/) | User-mode runtime: shared section, rings, provider dispatch, request decoding | Transport and dispatch in place; tested against an in-process kernel simulator |
| [`mirrorfs`](mirrorfs/) | Sample provider that mirrors an NTFS directory | Early; exercised by tests, cannot be mounted yet |
| [`driver/`](driver/) | Kernel driver: control device, session setup and teardown, mount and dismount | Session transport foundation implemented and passing its local build and audit gates; under review; **not yet verified on a live machine** |

Not built yet:

- carrying file requests over the rings end to end (open, read, write,
  directory listing, and so on);
- file objects and the file system object model in the driver;
- Cache Manager and memory-mapped I/O integration;
- passthrough, provider restart and replay;
- Driver Verifier, HLK and performance runs, and signed release packages.

The rough order of work is: verify the session transport on a real test
machine, carry requests end to end, mount `mirrorfs` as the first working file
system, then add caching, passthrough and recovery, and finally the release
gates.

## Repository layout

```text
fsring-abi/     no_std crate: the wire ABI (single source of truth)
  include/      generated C header fsring_abi.h
  tests/        Rust ABI tests and C layout tests (tests/c/)
fsring-user/    user-mode runtime (std)
  src/bin/      fsring-control-smoke: smoke harness for the driver's control device
  fuzz/         cargo-fuzz targets for decoders and the dispatch loop
mirrorfs/       sample provider backed by an NTFS directory (+ fuzz/)
driver/         separate Cargo workspace for the kernel driver
  fsring-core/  WDK-free core, testable on the host
  fsring-sys/   pinned kernel bindings (the only hand-written extern blocks)
  fsring-fsd/   the WDM file system driver
  scripts/      build matrix, static audits, smoke orchestration
  tests/        compile-fail proofs
docs/design/    architecture specification, documents 00 to 12
scripts/        ABI-registry and specification checks, archive packager
```

The repository root is one Cargo workspace (`fsring-abi`, `fsring-user`,
`mirrorfs`) on Rust 1.82. The driver lives in its own workspace under
`driver/` because it needs a different toolchain (Rust 1.85) and
`panic = "abort"` release profiles.

## Getting started

### Prerequisites

- Windows 10 or 11, x64.
- [Rust](https://rustup.rs/) with the 1.82.0 toolchain, the minimum supported
  version of the host crates:

  ```powershell
  rustup toolchain install 1.82.0
  ```

- Python 3 for the ABI registry check.

### Build and test the user-mode crates

```powershell
git clone <this repository>
cd winfsr

cargo +1.82.0 build --workspace --locked
cargo +1.82.0 test --workspace --locked

python scripts/verify_v21_registry.py
```

These steps need no driver, no administrator rights and no WDK. The runtime's
tests run against a simulated kernel, so they are the quickest way to see the
transport working. `verify_v21_registry.py` checks that the Rust ABI, the
generated C header and the C layout tests agree.

See [`fsring-abi/README.md`](fsring-abi/README.md) for regenerating the C
header and compiling the C layout tests with MSVC and clang-cl.

### Build the kernel driver (optional)

The driver needs a full Windows driver toolchain:

1. Visual Studio 2022 with **Desktop development with C++**, the **MSVC
   Spectre-mitigated libs (x64)** and the **Windows SDK 10.0.26100**.
2. The standalone **WDK 10.0.26100** installer. Its build number must match
   the SDK.
3. `cargo-wdk`:

   ```powershell
   cargo +1.85.0 install cargo-wdk --version 0.1.1 --locked
   ```

4. LLVM/libclang for bindgen (18.1.8 is known to work).

Then build from the driver workspace, which pins Rust 1.85.0 through its own
`rust-toolchain.toml`. Run the build from an x64 **Developer PowerShell for
VS 2022** (or after `VsDevCmd.bat -arch=amd64`); in a plain shell, bindgen
cannot find the WDK headers.

```powershell
$env:LIBCLANG_PATH = "$env:ProgramFiles\LLVM\bin"
cd driver
cargo wdk build
```

This produces a test-signed `fsring_fsd.sys` package. Load it only inside a
disposable virtual machine with test signing enabled. Platform profiles, the
full build and audit matrix, and the smoke procedure are described in
[`driver/README.md`](driver/README.md).

## Documentation

- [`docs/design/`](docs/design/00-INDEX.md): the architecture specification.
  Start at `00-INDEX.md`, which gives the reading order. The documents are
  currently written in Vietnamese.

  | Doc | Topic |
  |---|---|
  | 00 | Index, scope, terminology, platform profiles |
  | 01 | Principles, threat model, trust boundaries |
  | 02 | Shared-memory transport and control path |
  | 03 | Messages and registries |
  | 04 | Object model |
  | 05 | IRP dispatch |
  | 06 | Locking, cancellation and rundown |
  | 07 | Cache Manager and memory manager |
  | 08 | Passthrough |
  | 09 | Security |
  | 10 | Lifecycle: mount, daemon death, replay, teardown |
  | 11 | Rust implementation, WDK and packaging |
  | 12 | Test plan and release gates |

- [`fsring-abi/README.md`](fsring-abi/README.md): the fixed wire contract and
  its verification.
- [`driver/README.md`](driver/README.md): the driver workspace, toolchain and
  gates.

## Contributing

winfsr is early and the design still moves quickly. Bug reports, questions
and design feedback are welcome through GitHub issues. Please open an issue to
discuss a larger change before sending a pull request.

## License

winfsr is released under the [MIT License](LICENSE).

## Acknowledgements

- [WinFsp](https://github.com/winfsp/winfsp) by Bill Zissimopoulos, the
  project that showed how far user-mode file systems on Windows can go, and
  the inspiration for winfsr.
- [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs), which
  makes a Rust kernel driver practical.
