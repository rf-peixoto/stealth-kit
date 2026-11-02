# envcheck + cobfuscate

Two small, independent software-protection tools for your **own** C binaries:

1. **`envcheck`** — an inspect-only C library that reports whether your program
   is running inside a VM, sandbox, debugger, or on a dedicated
   reverse-engineering machine. It *only reports*; it never kills the process,
   alters your logic, hides itself, or phones home.
2. **`cobfuscate`** — a Python source-to-source tool that replaces the string
   literals in a `.c` file with obfuscated blobs plus a runtime deobfuscator, so
   `strings mybinary` no longer reveals them.

They are useful on their own. The build script also wires them together: it can
run the obfuscator over every source and then compile the result.

> **Both are speed bumps, not walls.** They raise the cost of casual analysis
> and defeat many automated sandboxes. A skilled analyst on bare metal — or one
> who patches the checks out, or opens the binary in a debugger — gets through.
> Several envcheck signals also fire on legitimate hosts (cloud dev boxes, WSL,
> containers, CI runners, low-spec laptops), so weigh the **aggregate scores**;
> never act on a single flag.

## Repository layout

```
envcheck-lib/
├── README.md                      # this file
├── build.sh                       # Linux/macOS build; --obfuscate runs cobfuscate first
├── build.bat                      # Windows/MSVC build; "obfuscate" arg does the same
├── .gitignore
├── include/
│   └── envcheck.h                 # public API + env_report_t struct
├── src/
│   └── envcheck.c                 # library implementation (no main) — the one the builds use
├── examples/
│   ├── example.c                  # minimal driver: prints the report as JSON
│   ├── report.c                   # full per-signal breakdown + scores + percentage
│   ├── guard.c                    # DESTRUCTIVE enforcement example (self-deletes)
│   └── precompiled/               # prebuilt, obfuscated+stripped guard, for inspection
│       ├── guard.obf.stripped     #   Linux x86-64 ELF
│       └── guard.obf.stripped.exe #   Windows x64 PE32+
├── tools/
│   └── cobfuscate.py              # the string obfuscator
└── demo/
    └── demo.c                     # small sample program the obfuscator transforms
```

Build output goes to `build/` (and obfuscated sources to `build/obf/`); both are
git-ignored.

### What each piece is

| Path | What it is |
|------|------------|
| `include/envcheck.h` | Public API: the `env_report_t` struct, `env_options_t`, and the four functions (`env_default_options`, `env_inspect`, `env_layout_matches`, `env_report_to_json`). Include this in your project. |
| `src/envcheck.c` | The inspect-only library implementation. No `main()` — you link it into your own program (or into the example drivers below). |
| `examples/example.c` | Smallest possible driver: runs `env_inspect()` and prints the report as JSON. |
| `examples/report.c` | Human-readable harness: per-signal breakdown with weights, VM/analysis subtotals, and a heuristic VM-likelihood percentage. Takes `--json`, `--no-ptrace`, `--no-backdoor`, `--sleep-skew`. |
| `examples/guard.c` | **Destructive** enforcement example: if the combined score ≥ `GUARD_THRESHOLD`, it deletes its own executable and exits. Test with `GUARD_DRY_RUN=1` first. |
| `examples/precompiled/guard.obf.stripped` | A prebuilt `guard` for **Linux x86-64** (ELF), with both its own and envcheck's strings obfuscated, then stripped. For `strings`/reverse-engineering inspection — see "Inspecting the precompiled binaries". |
| `examples/precompiled/guard.obf.stripped.exe` | The same, cross-compiled for **Windows x64** (PE32+, MinGW-w64). |
| `tools/cobfuscate.py` | The string obfuscator (Part 2). Pure Python 3, no dependencies. |
| `demo/demo.c` | A tiny self-contained program used to showcase the obfuscator's before/after (6 clear-text strings → 0). |
| `build.sh` / `build.bat` | One-command builds for Linux/macOS and Windows respectively (Part 3). |

---

## Quick start

```sh
./build.sh                 # compile the examples            -> build/report, build/guard, build/example, build/demo
./build.sh --obfuscate     # obfuscate every source, then compile  -> build/*.obf
./build.sh --obfuscate --seed 1234   # reproducible obfuscation
./build.sh clean           # remove build/
```

Override the toolchain with environment variables:
`CC=clang CFLAGS="-O3" PYTHON=python3.12 ./build.sh`.

On **Windows**, use `build.bat` from a *x64 Native Tools Command Prompt for VS*
(so `cl.exe` and `python` are on PATH):

```bat
build.bat                 :: compile the examples          -> build\*.exe
build.bat obfuscate       :: obfuscate every source, then compile -> build\*.obf.exe
build.bat obfuscate 1234  :: reproducible obfuscation
build.bat clean
```

A `cl.exe` build keeps debug info in a separate `.pdb`, so function names are not
embedded in the `.exe` — there is no separate `strip` step on Windows.

---

## Part 1 — the `envcheck` library

### Building into your own project

```sh
cc -O2 -Iinclude -c src/envcheck.c          # Linux: just the object file
cl /O2 /Iinclude /c src\envcheck.c          # Windows (MSVC recommended)
```

Supported: Linux and Windows on x86/x86-64. MSVC is recommended on Windows — the
SEH debugger traps compile only under MSVC, and the VMware backdoor probe needs
MSVC x86 (see caveats).

### Minimal usage

```c
#include "envcheck.h"

env_report_t r = env_inspect(NULL);          /* NULL => default options */
env_layout_matches(&r, "pt", 0x0416);        /* optional market check (pt / pt-BR) */

if (r.analysis_score >= 6 || r.vm_score >= 8) {
    /* your policy — refuse to run, reduce functionality, log, call a license
       server, whatever. The library does none of this for you, by design. */
}
```

Pass an `env_options_t*` instead of `NULL` to change the slow / stateful probes:

| Option | Default | Notes |
|--------|:------:|-------|
| `run_ptrace_self` | 1 | Linux `PTRACE_TRACEME` probe. Changes process state (see caveats). |
| `run_io_backdoor` | 1 | VMware backdoor port probe. Raises+catches a CPU fault. |
| `run_sleep_skew`  | 0 | Sleeps ~200 ms and measures; adds latency, so off by default. |

### Example programs

**`examples/example.c`** — the smallest possible driver. Prints the report as
JSON and exits.

```sh
./build/example
# {"vm":{"hypervisor_bit":1,...},"scores":{"vm_score":12,"analysis_score":0}}
```

**`examples/report.c`** — a human-readable harness: every signal, the points it
contributes, the VM/analysis subtotals, and a heuristic VM-likelihood
percentage with interpretation bands.

```sh
./build/report                 # full breakdown + score + percentage
./build/report --json          # raw JSON instead
./build/report --sleep-skew    # also run the time-acceleration probe
./build/report --no-backdoor   # skip the VMware I/O backdoor probe
./build/report --no-ptrace     # skip the PTRACE_TRACEME self-probe
```

**`examples/guard.c`** — a **destructive** enforcement example. It runs the
checks and, if the combined score reaches `GUARD_THRESHOLD` (default 7),
**deletes its own executable** and halts. It only ever unlinks its *own* image.

```sh
GUARD_DRY_RUN=1 ./build/guard   # report what it WOULD do, delete nothing  <-- test first!
./build/guard                   # live: self-deletes + exits if tripped
```

Retune the threshold at build time:

```sh
CFLAGS="-O2 -DGUARD_THRESHOLD=14" ./build.sh
```

> The default threshold of 7 is **low**: a plain KVM guest scores ~11–13 with no
> debugger present, so with this threshold the binary self-deletes on many
> legitimate VMs. Measure against your real target fleet, and prefer gating on
> `analysis_score` (active debugging) over `vm_score` (merely virtualized).

### envcheck caveats (read these)

1. **`run_ptrace_self` and `run_io_backdoor` are mutually exclusive per
   process.** `PTRACE_TRACEME` has persistent, process-wide side effects: once
   it has run, the next synchronous `SIGSEGV`/`SIGILL` is delivered as a
   trace-stop, which would make the fault-based backdoor probe self-stop the
   process. `env_inspect()` enforces this for you — on Linux with both enabled
   (the default), the backdoor runs on the **first** call and is disabled
   thereafter for the life of the process.
2. **The backdoor probe makes an *interactive* debugger break on SIGSEGV.** If
   you ever debug your own release build, set `run_io_backdoor = 0` first — or
   in gdb: `handle SIGSEGV nostop pass`.
3. **SEH traps are MSVC-only.** `seh_int3` and `closehandle` compile to no-ops
   under MinGW/Clang on Windows; `false` there means "not tested", not "no
   debugger".
4. **The VMware backdoor needs inline asm.** It runs on Linux (GCC/Clang
   x86/x64) and Windows MSVC **x86**. On MSVC x64 it is a no-op.
5. **Keyboard layout on Linux is a locale approximation** (`LANG`/`LC_*`). For
   the real active X11/Wayland layout you'd add `libxkbcommon`.

### JSON fields and scoring weights

`env_report_to_json()` emits a nested object. Each flag that feeds a score is
shown below with the points it contributes; `vm_score` and `analysis_score` are
simple weighted sums. Pick your own thresholds.

<details>
<summary><b>vm</b> — virtualization / controlled host</summary>

| Field | Weight | Meaning |
|-------|:------:|---------|
| `hypervisor_bit` | 1 | CPUID.1 ECX[31] set. True on most cloud/dev hosts too. |
| `hypervisor_vendor` | 2 | CPUID 0x40000000 vendor (`KVMKVMKVM`, `VMwareVMware`…). |
| `cpu_brand_virtual` | 2 | CPU brand string contains QEMU/Virtual/KVM. |
| `mac_prefix` | 2 | NIC MAC OUI belongs to a VM vendor. |
| `dmi_string` | 3 | DMI/registry manufacturer/product looks virtual. |
| `artifact_present` | 3 | Guest-tool device/driver/module/service present. |
| `vmware_backdoor` | 3 | VMware I/O port `0x5658` responded with its magic. |
| `cpuinfo_hypervisor` | 1 | Linux `/proc/cpuinfo` hypervisor flag. |
| `wine` | 2 | Running under Wine. |
| `wsl` | 1 | Running under WSL. |
| `container` / `container_type` | 2 | docker / lxc / k8s. |
| `firmware_table` / `firmware_hit` | 3 | ACPI/SMBIOS firmware tables name a VM. Hard to scrub. |
| `pci_device` / `pci_id` | 3 | PCI vendor ID is a VM vendor (VMware 15ad, VBox 80ee, virtio 1af4, QEMU 1234, Xen 5853, Parallels 1ab8). |
| `disk_model` | 2 | Disk model string / virtio `vd*` device looks virtual. |
| `gpu_model` / `gpu_name` | 2 | Display adapter / DRM driver is virtual (vmwgfx, virtio, vboxvideo, qxl…). |
| `no_thermal_sensor` | 1 | No thermal sensors (Linux). Weak — servers lack them too. |
| `named_pipe` | 2 | Windows VM/sandbox named pipe present. |
| `no_battery` | **0** | Reported but **not scored** — too noisy to weight. |

</details>

<details>
<summary><b>sandbox_env</b>, <b>debugger</b>, <b>analysis</b>, <b>resources</b></summary>

**sandbox_env** — `seccomp_active` (2), `unusual_namespace` (1), `yama_ptrace_scope` (reported).

**debugger** — `present` (3, rolls up the rest), `kernel_debugger` (3),
`hw_breakpoints` (2), `peb_ntglobalflag` (1), `ld_preload_set` (1),
`ld_audit_set` (1), `ptrace_self_blocked` (2), `seh_int3` (3, MSVC),
`closehandle` (3, MSVC). `tracer_pid` / `peb_being_debugged` / `debug_port_set`
reported and folded into `present`.

**analysis** — `tool_running` (3, IDA/Ghidra/x64dbg/radare2/gdb/Wireshark…),
`tool_installed` (2), `hook_dll_loaded` (3, Sandboxie/Cuckoo…),
`instrumentation` (3, Frida/Pin/DynamoRIO/Qiling), `parent_suspicious` (3).

**resources** — `low_cpu` (1, <2 cores), `low_ram` (1, <2 GB), `small_disk`
(1, <60 GB), `short_uptime` (1, <5 min), `suspicious_identity`
(2, host/user like `sandbox`/`cuckoo`/`malware`), `small_screen` (1, Windows),
`no_user_input` (1, Windows), `sleep_skew_suspicious` (2, time acceleration).

**timing** — `cpuid_cycles` / `suspicious` (1): serialising CPUID far slower
than bare metal → VM-exit overhead.

**keyboard** — `primary_langid` / `layout_name` / `matches_target`: coarse
market signal from `env_layout_matches()`. Not scored.

Current theoretical maxima are **49** (VM) and **33** (analysis), **82**
combined — but several signals are platform-specific or mutually exclusive, so
no single run reaches the max. `report` prints the live maxima and percentage.

</details>

---

## Part 2 — the `cobfuscate` string obfuscator

`tools/cobfuscate.py` reads a `.c` file, finds string literals that sit in safe
(callable) positions inside function bodies, and rewrites each one as a call to
one of *N* runtime deobfuscation functions fed an obfuscated byte blob. No clear
text is left in the source **or** the compiled binary for those strings.

### Usage

```sh
python3 tools/cobfuscate.py input.c -o output.c [options]
```

| Option | Default | Meaning |
|--------|:------:|---------|
| `-o, --output PATH` | `<input>.obf.c` | Output file. |
| `--n-deob N` | 5 | Number of distinct deob functions (each with its own transform pipeline). |
| `--seed S` | random | RNG seed, for reproducible builds. |
| `--alloc {static,malloc}` | static | Buffer strategy (see "Memory model"). |
| `--prefix P` | `__cbf_` | Identifier prefix for injected symbols. |
| `--verify` | off | Run `cc -fsyntax-only` on the output and report. |
| `--stats` | off | Print how many literals were obfuscated / skipped. |

### Example

```sh
# Transform the sample program and prove the strings are gone:
python3 tools/cobfuscate.py demo/demo.c -o /tmp/demo.obf.c --seed 1234 --verify --stats
cc -O2 -Wno-format-security /tmp/demo.obf.c -o /tmp/demo.obf

strings ./build/demo   | grep OBFUSCATE     # plain binary: 6 hits (after ./build.sh)
strings /tmp/demo.obf  | grep OBFUSCATE     # obfuscated:   0 hits
/tmp/demo.obf                                # runs identically
```

### How it works

* **Real C lexer.** A single-pass scanner tracks comments, char vs string
  literals, preprocessor directives, brace/paren context and declaration
  qualifiers, so it rewrites only where a function-call expression is a legal
  substitute for a string literal.
* **Low-entropy, no XOR.** Every transform is a histogram-preserving operation —
  a constant byte-shift, a bit-rotation, an affine byte map (`a·x+b`, `a` odd so
  it inverts), or a pure byte reorder (reverse / pair-swap / rotate). The blob is
  therefore just a relabelled, reordered copy of the plaintext, so its Shannon
  entropy is **unchanged** and it does not look like a packed/encrypted section
  to AV heuristics. No key table is stored (parameters are tiny constants baked
  into the deob functions).
* **Multi-layer, N functions.** Each of the `--n-deob` functions chains 3–5
  transforms, so every decode runs several passes, and different strings route
  through different functions.
* **Blobs, not strings.** Obfuscated data is emitted as `unsigned char` arrays
  with an explicit length (embedded NULs survive), so `strings` sees nothing —
  not even the blob.

### Memory model

* **`static` (default)** — each obfuscated string gets its own persistent output
  buffer in `.bss`. The deobfuscator decodes into that buffer and returns it, so
  every string has a **stable address safe to stash** in a lookup table, there is
  **no shared pool to clobber**, nothing to `free()`, and it is a true drop-in
  replacement. The decoded plaintext lives in process memory while the program
  runs (a memory dump would show it — true of any scheme once decoded), but it is
  never in the file, so `strings` sees nothing. Re-decoding is idempotent; if two
  threads decode the *same* string literal at the same instant a reader could
  briefly see a half-decoded buffer — use `malloc` or a `/*noobf*/` opt-out for
  the rare string where that matters.
* **`malloc`** — each call returns a fresh `malloc`'d buffer that **the caller
  must `free()`**. Not a drop-in replacement; use it only when you specifically
  do not want decoded plaintext lingering in static memory.

### Limitations (by design — these keep it compiling)

* **Strings in non-callable positions stay in clear text.** The tool deliberately
  skips string literals at file scope, in `#define` macros, in `static` /
  `extern` declarations, in `char x[] = "..."` array initializers, as `sizeof`
  operands, and inside `_Static_assert` / `asm` / `__attribute__`. A
  function-call can't legally stand in those places. Move a sensitive string
  into a function body (e.g. `const char *p = "...";` assigned at runtime) to get
  it covered, or tag a line you want left alone with a trailing `/*noobf*/`.
* **Automatic aggregate initializers ARE covered.** Lookup tables written as
  *non-`static`* locals inside a function — `const char *t[] = {"a","b",...}`,
  and struct-array initializers — are obfuscated element by element, because C
  allows non-constant initializers for automatic storage. Only the `static` /
  file-scope versions of such tables are skipped (they need a constant
  initializer). Because each string owns a persistent buffer (`static` alloc),
  even a 50-entry table whose entries are all live at once is safe.
* **Function/variable names are symbols, not strings.** The obfuscator does not
  touch identifiers, so names like `check_sandbox_env` remain in the symbol
  table. Strip them with `strip yourbinary` (or link with `-s`) — that is a
  separate, standard step.
* **Wide / unicode strings** (`L"..."`, `u8"..."`, …) are skipped — the
  deobfuscator returns `char*`.
* **`printf`-family format strings.** An obfuscated literal used *directly* as a
  format becomes a non-literal: GCC emits a harmless `-Wformat-security` warning
  and you lose compile-time format checking. The build passes
  `-Wno-format-security` for obfuscated builds.
* **Threat model:** this defeats `strings` and casual inspection, not a debugger.
  Raise `--n-deob` to multiply the manual-reversing effort.

### A note on obfuscating `envcheck.c` itself

The `--obfuscate` build runs the obfuscator over `src/envcheck.c` too, and the
result compiles and behaves identically. envcheck's signature tables (`cuckoo`,
`ghidra`, `VMwareVMware`, firmware keywords, PCI IDs…) were deliberately written
as **automatic (non-`static`) local tables** so the obfuscator reaches them — so
they *are* obfuscated now. Concretely, on a stripped build:

```
./build.sh --obfuscate --seed 1234
strip build/guard.obf
strings build/guard.obf | grep -icE 'vmware|ghidra|frida|cuckoo|qemu|vbox'   # -> 0
```

Before this rework those tables were `static`/file-scope and survived
obfuscation; the entries are now built at runtime instead (rebuilt per call,
which is negligible for checks that run once). The only clear text that then
remains is the file-scope JSON template field names (they are not signatures)
and dynamic-linker import names (`ptrace`, `unlink`, …), which you cannot remove
without static linking. `demo/demo.c` is still the simplest before/after
showcase (6 → 0).

---

## Part 3 — the integrated build

`./build.sh --obfuscate` chains everything:

1. Runs `tools/cobfuscate.py` over `src/envcheck.c`, the three `examples/*.c`,
   and `demo/demo.c`, writing obfuscated sources to `build/obf/`.
2. Compiles each obfuscated example against the obfuscated library into
   `build/report.obf`, `build/guard.obf`, `build/example.obf`, and the
   standalone `build/demo.obf`.

```sh
./build.sh --obfuscate --seed 1234

# the obfuscated programs behave exactly like the plain ones:
diff <(./build/report --no-backdoor --no-ptrace) \
     <(./build/report.obf --no-backdoor --no-ptrace)   # (no output = identical)
```

Add `--seed N` for reproducible builds; omit it for a different obfuscation each
run. On Windows the same thing is `build.bat obfuscate 1234`.

---

## Inspecting the precompiled binaries

`examples/precompiled/` holds a prebuilt `guard` — the enforcement example — with
**both its own strings and all of envcheck's signature strings obfuscated**, then
stripped. Two targets:

| File | Platform | Built with |
|------|----------|------------|
| `guard.obf.stripped`     | Linux x86-64 (ELF)   | `gcc` + `cobfuscate.py`, then `strip` |
| `guard.obf.stripped.exe` | Windows x64 (PE32+)  | `x86_64-w64-mingw32-gcc` + `cobfuscate.py`, then `-s` |

They are there so you can confirm the obfuscation holds up under a `strings`
scan. For example:

```sh
# Linux
strings examples/precompiled/guard.obf.stripped \
  | grep -iE 'vmware|ghidra|frida|cuckoo|qemu|vbox'          # -> (nothing)

# Windows signatures (names, driver files, pipes) — e.g. with Sysinternals strings
strings examples\precompiled\guard.obf.stripped.exe \
  | findstr /I "VBoxMiniRdrDN vmmouse ghidra frida cuckoo"   # -> (nothing)
```

Against an equivalent *plain* build the same scans return dozens to hundreds of
hits (the Windows code path alone carries ~500 signature strings: registry
service paths, driver filenames, VM/sandbox named pipes). After obfuscation the
only clear text left is the file-scope JSON template field names (not signatures)
and dynamic-linker import names (`ptrace`, `unlink`, …), which can't be removed
without static linking.

**Caveats for your analysis.** This defeats static inspection (`strings`, reading
`.rodata` in a disassembler), *not* a running debugger: the strings are
reconstructed in memory at runtime, so a live debugger or a memory dump recovers
them. Also, the `.exe` here was cross-compiled with MinGW; the MSVC-only probes
(SEH `int 3`, the x86 VMware backdoor) are no-ops in it — rebuild with
`build.bat obfuscate` on a real MSVC toolchain to exercise those.

---

## License / intent

This is defensive software-protection code for guarding *your own* binaries.
The envcheck library is written to be auditable — nothing in it is hidden, and
every probe is named and commented. The obfuscator is a separate, opt-in step
for raising the cost of casual string extraction from *your* programs.
