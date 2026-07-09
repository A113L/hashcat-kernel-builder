# KernelBuilder

> Python port of the original C# tool. Auto-generates Hashcat OpenCL kernels and modules from PHP-like hash expressions like (md5(sha1($plain).sha256($salt))).

KernelBuilder takes a simple expression like `md5($plain.$salt)` or `sha1(md5($plain))` and automatically generates a complete Hashcat plugin: **pure** OpenCL kernels for attack modes `-a 0`, `-a 1`, and `-a 3`, plus the C module for hash parsing and encoding.

This version intentionally generates **pure kernels only**. An earlier iteration also generated `-optimized.cl` kernels for use with Hashcat's `-O` flag, but those triggered build/runtime errors on some algorithm combinations (particularly big-endian chained hashes on `-a 0`/`-a 1`), so optimized-kernel generation was dropped in favor of a simpler, reliably-working pure-kernel-only build. `-a 3` optimized kernels did work correctly, but for consistency this script keeps all three attack modes on pure kernels.

---

## Features

- **Auto-generate Hashcat plugins** from intuitive PHP-like syntax
- **Supported algorithms**: MD5, SHA1, SHA224, SHA256
- **Nested hashing**: `md5(sha1($plain))`, `sha256(md5($salt.$plain))`, etc.
- **Salt support**: `$salt` and `$plain` concatenation in any order
- **CUT support**: Truncate intermediate hashes to a specific byte length
- **Attack modes**: Generates pure kernels for `-a 0` (rules), `-a 1` (combinator), and `-a 3` (mask/vector)
- **Single & Multi hash**: Both `mXXXXX_sxx` and `mXXXXX_mxx` kernels
- **Endianness aware**: Automatically handles little-endian (MD5) and big-endian (SHA-family) conversions

> **Not included in this version:** optimized (`-O`) kernel generation. Run cracking sessions without `-O` (or with `-w` in benchmark mode) — the generated plugin only ships `-pure.cl` kernels.

---

## Requirements

- Python 3.7+
- Hashcat source code (for compiling the generated plugin)

---

## Usage

```
python3 kernel_builder.py <algorithm> <ID> [--overwrite] [--hashcat] [--list] [--hashcat-path PATH]
```

| Argument | Description |
|---|---|
| `algorithm` | Hash expression, e.g. `'md5($plain)'`, `'sha1($plain.$salt)'` |
| `ID` | Kernel ID / Hashcat `-m` number (1-5 digits, e.g. `98000`) |
| `--overwrite` | Overwrite a previously generated plugin folder |
| `--hashcat-path PATH` | Path to the Hashcat directory to write into (used with --hashcat). If omitted, you will be prompted for it interactively.|
| `--hashcat` | Write directly into a Hashcat source tree's `OpenCL/` and `src/modules/` folders instead of `plugins/<ID>/` |
| `-l`, `--list` | List supported algorithms and exit |

### Examples

```bash
python3 kernel_builder.py 'md5($plain)' 98000
python3 kernel_builder.py 'sha1($plain.$salt)' 98001
python3 kernel_builder.py 'sha224($salt.$plain)' 98002
python3 kernel_builder.py 'sha256($salt.$plain)' 98003
python3 kernel_builder.py 'md5(sha1($plain))' 98004 --hashcat
python3 kernel_builder.py 'sha256($salt.CUT16_md5($plain))' 92000 --overwrite
```

### Output layout (without `--hashcat`)

```
plugins/<ID>/
├── OpenCL/
│   ├── m<ID>_a0-pure.cl
│   ├── m<ID>_a1-pure.cl
│   └── m<ID>_a3-pure.cl
└── src/modules/
    └── module_<ID>.c
```

Copy the two subfolders into your Hashcat source tree and rebuild:

```bash
cp -r plugins/<ID>/* /path/to/hashcat/
```

Then compile Hashcat: https://github.com/hashcat/hashcat/blob/master/BUILD.md

### Testing

```bash
./hashcat -b -m <ID>                                    # benchmark (pure kernel)
./hashcat -a0 -m <ID> hashes.txt wordlist.txt -r rules/best64.rule
```

Do **not** pass `-O` — no optimized kernels are shipped, so Hashcat would fail to find the tiered symbol names (`s04`/`m04` etc.) it looks up under `-O`.

---

**Credits**

Python port based on the original [KernelBuilder](https://github.com/PenguinKeeper7/KernelBuilder) by Penguinkeeper.
