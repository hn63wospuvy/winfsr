# fsring-abi

`fsring-abi` is the single source of truth for the FSRING ABI v2 wire layout and
shared-memory transport. The crate is dependency-free and supports both host
tests and kernel `no_std` builds. The minimum supported Rust version is 1.82.

ABI v2 is intentionally incompatible with ABI v1. The default driver profile
targets Windows 10 1507 and later. Windows 7 SP1 x64 uses the separate
`platform-win7` driver feature/package; both profiles use this same ABI v2 wire
format. ARM64 is modern-profile only.

## Fixed wire contract

- ABI version: `2.0`, little-endian.
- `Sqe` is 128 bytes and 64-byte aligned; its fixed payload is 88 bytes.
- `Cqe` is 64 bytes and 64-byte aligned; its fixed output area is 24 bytes.
- `ReqId` is 64 bits: a 40-bit generation plus a 24-bit slot index.
- Feature and OS-capability sets are independent 128-bit values.
- SQ is multiple-kernel-producer/single-daemon-consumer. The kernel owns SQ
  entries, sequence values, and tail; the daemon owns SQ head.
- CQ is single-daemon-producer/single-kernel-consumer. The daemon owns CQ
  entries, sequence values, and tail; the kernel owns CQ head.
- Each side maps peer-owned authoritative pages read-only. Shared values from a
  peer are hostile input and must pass the ring validation rules.

## Rust verification

Run commands from the repository root with the exact MSRV toolchain:

```powershell
cargo +1.82.0 check --manifest-path fsring-abi/Cargo.toml --no-default-features --locked
cargo +1.82.0 test --manifest-path fsring-abi/Cargo.toml --release --locked
```

For slower CI hosts, `FSRING_TEST_DIV` scales only stress-test iteration counts:

```powershell
$env:FSRING_TEST_DIV = 50
cargo +1.82.0 test --manifest-path fsring-abi/Cargo.toml --release --locked
Remove-Item Env:FSRING_TEST_DIV
```

## Generated C header

The checked-in `include/fsring_abi.h` is generated output. Install and invoke
the pinned generator from the repository root:

```powershell
cargo install cbindgen --version 0.29.4 --locked --root target/tools/cbindgen-0.29.4
Push-Location fsring-abi
../target/tools/cbindgen-0.29.4/bin/cbindgen.exe --config cbindgen.toml --output include/fsring_abi.h .
../target/tools/cbindgen-0.29.4/bin/cbindgen.exe --quiet --verify --config cbindgen.toml --output include/fsring_abi.h .
Pop-Location
```

`tests/c/layout_v21.c` is the exhaustive ABI 2.1 layout test: it checks
`sizeof`, `_Alignof`, and every physical field offset for all 123 public wire
types plus every exported registry constant (`tests/c/layout_v2.c` remains the
minor-0 baseline). Compile them from an x64 Visual Studio/WDK developer shell
with warnings as errors:

```powershell
cl /nologo /std:c11 /W4 /WX /c fsring-abi/tests/c/layout_v21.c /Ifsring-abi/include /Fo"$env:TEMP/fsring_layout_v21_x64.obj"
```

The ARM64 compile-only gate uses `clang-cl --target=aarch64-pc-windows-msvc`:

```powershell
clang-cl --target=aarch64-pc-windows-msvc /nologo /std:c11 /W4 /WX /c fsring-abi/tests/c/layout_v21.c /Ifsring-abi/include /Fo"$env:TEMP/fsring_layout_v21_arm64.obj"
```

Both gates validate declarations and layouts but do not replace a native
Windows 11 ARM64 build/run/HLK gate. Run the C compilers from PowerShell/cmd,
never a POSIX shell that rewrites the MSVC `/`-prefixed flags.

## Generated archives

The unpacked crate and Markdown specification are authoritative. Root-level
`fsring-abi.zip` and `fsring-spec.zip` are deterministic generated artifacts;
never edit either archive as an independent source. Regenerate them only with
the repository packaging command documented by the project release workflow.
