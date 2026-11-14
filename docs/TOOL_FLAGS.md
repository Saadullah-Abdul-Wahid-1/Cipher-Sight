# External tool integration status

Rule: a tool is marked **tested** only after its wrapper has been executed on a real
installation. Until then it stays **unverified**. Flags below come from documentation
and have not been run in this build.

| Tool | Platform | Probe used by check-tools | Probe tested | Wrapper tested |
|---|---|---|---|---|
| exiftool | Win, Linux, macOS | `-ver` | no | no |
| binwalk | Linux, WSL (v3 is Rust) | `--version` | no | no |
| foremost | Linux, WSL | `-V` | no | no |
| steghide | Linux, Win builds | `--version` | no | no |
| stegseek | Linux or WSL only | `--version` | no | no |
| zsteg | Ruby gem | `--version` | no | no |
| outguess | Linux, WSL | `-h` | no | no |
| stegoveritas | Python tool | `--help` | no | no |

Known corrections to the original blueprint:
- Binwalk v2 reached end of life on 2025-12-12. v3 is a Rust rewrite, not a Python package.
- StegSeek does not build natively on Windows. It needs WSL.
- Sources disagree on the `zsteg -o` option. Do not use it until checked.
- Foremost needs an empty or non-existent output directory.
- `forsmost` on crates.io is a separate Rust project, not Foremost.

No external tool is installed in the build sandbox, so none of these have been executed.
