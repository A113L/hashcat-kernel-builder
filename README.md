# KernelBuilder

> Python port of the C# tool. Auto-generate Hashcat OpenCL kernels and modules from PHP-like hash expressions.

KernelBuilder takes a simple expression like `md5($plain.$salt)` or `sha1(md5($plain))` and automatically generates the complete Hashcat plugin: OpenCL kernels (pure) for attack modes `-a 0`, `-a 1`, and `-a 3`, plus the C module for hash parsing and encoding.

---

## Features

- **Auto-generate Hashcat plugins** from intuitive PHP-like syntax
- **Supported algorithms**: MD5, SHA1, SHA224, SHA256
- **Nested hashing**: `md5(sha1($plain))`, `sha256(md5($salt.$plain))`, etc.
- **Salt support**: `$salt` and `$plain` concatenation in any order
- **CUT support**: Truncate intermediate hashes to a specific byte length
- **Attack modes**: Generates kernels for `-a 0` (rules), `-a 1` (combinator), and `-a 3` (mask/vector)
- **Single & Multi hash**: Both `mXXXXX_sxx` and `mXXXXX_mxx` kernels
- **Endianness aware**: Automatically handles little-endian (MD5) and big-endian (SHA-family) conversions

---

## Requirements

- Python 3.7+
- Hashcat source code (for compiling the generated plugin)

**Author**

Python port based on the original [KernelBuilder](https://github.com/PenguinKeeper7/KernelBuilder) by Penguinkeeper.
