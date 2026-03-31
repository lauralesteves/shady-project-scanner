# Shady Project Scanner

A collection of shell-based malware and vulnerability scanners for auditing code repositories. Detects suspicious patterns across multiple ecosystems: **Node.js/npm**, **PHP**, **Python/PyPI**, **Go**, and general cross-language threats.

No dependencies required -- just bash and standard Unix tools (`grep`, `find`, `awk`).

## Quick Start

```bash
# Scan a project with ALL scanners
make scan TARGET=/path/to/project

# Scan current directory
make scan
```

## Scanners

### General Repository Scanner (`scan-repo`)

Cross-language security checks applicable to any codebase.

| Check | What it detects |
|-------|-----------------|
| Git hooks | Malicious hooks that download/execute code, exfiltrate data |
| Crypto miners | xmrig, coinhive, mining pool addresses, wallet strings |
| Secrets & credentials | AWS keys, GitHub tokens, Slack tokens, private keys, .env files, JWTs, DB connection strings |
| CI/CD tampering | GitHub Actions with unsafe pinning, `pull_request_target` exploits, curl-pipe-bash in workflows |
| Docker abuse | Privileged containers, host mounts, remote script execution |
| Unicode attacks | Trojan Source (CVE-2021-42574) bidirectional overrides, zero-width obfuscation, Cyrillic homoglyphs |
| Suspicious binaries | .exe, .dll, .so, .bat, .ps1, .vbs files in repos |
| Build scripts | Makefiles/shell scripts that download and execute, base64 decode + exec, reverse shells |
| Encoded blobs | Very long lines (>2000 chars) in source files indicating obfuscation |
| IDE config | VS Code tasks/settings with shell execution commands |
| Git config abuse | Custom filter drivers in .gitattributes, local .gitconfig overrides |

### Node.js / npm Scanner (`scan-node`)

Detects malicious patterns in JavaScript/TypeScript projects.

| Check | What it detects |
|-------|-----------------|
| Install scripts | Suspicious `preinstall`/`postinstall` hooks in package.json (curl, wget, eval, base64) |
| eval / Function | Dynamic `eval()` with variables, `new Function()`, `eval(atob(...))`, eval+child_process |
| child_process | Shell execution with suspicious commands, obfuscated `require('child_process')`, string-building to hide module name |
| Data exfiltration | process.env reading + HTTP requests, reading sensitive files (.ssh, .aws, .npmrc), webhook/exfil URLs (Discord, Slack, ngrok) |
| Obfuscated payloads | Long base64/hex/unicode strings, javascript-obfuscator `_0x` patterns, JSFuck-style obfuscation, Buffer.from+eval chains |
| npm/yarn config | Custom registries, auth tokens in .npmrc/.yarnrc |
| Lockfile integrity | package-lock.json resolved URLs pointing outside official registries |
| Native addons | binding.gyp files, .node binaries outside node_modules |

### PHP Malware / Webshell Scanner (`scan-php`)

Detects webshells, backdoors, and obfuscated malware in PHP projects.

| Check | What it detects |
|-------|-----------------|
| Webshell signatures | c99shell, r57shell, b374k, WSO, FilesMan, Ani-Shell, ALFA Shell, Weevely, p0wny, phpspy |
| User input to danger functions | `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` passed directly into eval, system, exec, shell_exec, passthru, popen |
| Obfuscation chains | `eval(base64_decode(...))`, `eval(gzinflate(...))`, nested decode chains, `assert()` as eval, `preg_replace` with `/e` modifier, `create_function()` |
| Shell execution | `system()`/`passthru()`/`shell_exec()` with variables, backtick operator with variable interpolation, `proc_open` with user input |
| File write abuse | `file_put_contents` with user-controlled path, `fwrite` with decoded content, `move_uploaded_file` without MIME validation |
| Hidden PHP | PHP code in .jpg/.png/.gif/.ico/.css/.txt files, double extensions (.php.jpg), alternative extensions (.phtml, .pht, .phar) |
| Encoded payloads | Long base64/hex strings, chr() obfuscation chains, variable variables, string concatenation building function names |
| .htaccess abuse | auto_prepend_file/auto_append_file injection, AddHandler making images executable as PHP |
| PHP config | php.ini/.user.ini with auto_prepend_file, disable_functions weakening |
| Composer | Suspicious install scripts, VCS/inline package sources bypassing Packagist |

### Python / PyPI Scanner (`scan-python`)

Detects malicious patterns in Python projects and packages.

| Check | What it detects |
|-------|-----------------|
| Malicious setup.py | Imports of subprocess/os/network modules, exec/eval/compile during install, base64 decoding, custom install command classes, URL fetching during setup |
| pyproject.toml | Custom cmdclass, unusual build backends |
| exec / eval abuse | exec/eval with encoded payloads, `exec(compile(...))`, multi-layer decode chains (base64 -> zlib -> marshal -> exec) |
| Obfuscated payloads | Long base64 strings, `marshal.loads()` (bytecode deserialization), dynamic `__import__`, `bytes.fromhex`, chr() building, lambda wrapping exec |
| Data exfiltration | Reading sensitive files (.ssh, .aws, .env) + network calls, webhook URLs, os.environ + HTTP POST, DNS exfiltration via socket |
| Subprocess abuse | `subprocess` with `shell=True`, `os.system()` with variables, `os.popen()`, reverse shell patterns |
| Deserialization | `pickle.load(s)` with untrusted sources, `yaml.load()` without SafeLoader, `__reduce__` exploit patterns |
| Requirements | Dependencies from git URLs, non-PyPI URLs, custom `--index-url`/`--extra-index-url` (dependency confusion) |
| .pth files | Auto-executing import statements on Python startup |

### Go Module Scanner (`scan-go`)

Detects supply chain attacks and suspicious patterns in Go projects.

| Check | What it detects |
|-------|-----------------|
| go.mod replace | Local path overrides (dependency hijacking), non-standard source replacements, retract directives, dependencies from unusual domains |
| Suspicious init() | init() functions in files with network calls, exec, env variable reading + HTTP, access to sensitive file paths |
| os/exec abuse | exec.Command with shell interpreters + suspicious commands, fmt.Sprintf arguments (obfuscation), env vars as commands |
| Data exfiltration | Webhook/exfil URLs, system info gathering + HTTP requests, reading .ssh/.aws/.env files, raw TCP/UDP + exec (C2 patterns) |
| CGo abuse | C code calling system()/popen()/exec(), importing dangerous C headers |
| go:generate | Generate directives with curl/wget/bash, remote URL fetching |
| Build tricks | go:embed including executables/hidden files, `//go:build ignore` with exec/network code, shared libraries in Go projects |

### PolinRider Scanner (`scan-polinrider`)

The original scanner -- detects the PolinRider malware which appends obfuscated JS payloads to config files and force-pushes via `temp_auto_push.bat`.

| Check | What it detects |
|-------|-----------------|
| Primary signature | PolinRider obfuscated payload in postcss/tailwind/eslint/next/babel config files |
| Propagation | `temp_auto_push.bat` and `config.bat` presence |
| .gitignore injection | `config.bat` entry injected into .gitignore |
| Git reflog | Amended commits consistent with PolinRider behavior |

## Usage

### Run all scanners

```bash
make scan TARGET=/path/to/project
```

### Run individual scanners

```bash
make scan-node TARGET=/path/to/project
make scan-php TARGET=/path/to/project
make scan-python TARGET=/path/to/project
make scan-go TARGET=/path/to/project
make scan-repo TARGET=/path/to/project
make scan-polinrider TARGET=/path/to/project
```

### Run scripts directly

```bash
./scanners/scan-node.sh /path/to/project
./scanners/scan-php.sh /path/to/project
./scanners/scan-python.sh /path/to/project
./scanners/scan-go.sh /path/to/project
./scanners/scan-repo.sh /path/to/project
./scanners/scan-polinrider.sh /path/to/project
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings detected (review output) |
| 2 | Error (invalid path, etc.) |

## Finding Severity

- **`[!]` Red** -- High confidence indicator of malicious or dangerous code. Requires investigation.
- **`[~]` Yellow** -- Suspicious pattern that could be legitimate but warrants manual review.
- **`[i]` Cyan** -- Informational note for context.

## Limitations

- These are pattern-based scanners, not static analysis tools. They can produce false positives (especially on scanner code itself) and may miss sophisticated obfuscation.
- Scans are limited to the file system -- they don't analyze runtime behavior, network traffic, or installed packages outside the project directory.
- `node_modules/`, `vendor/`, `.venv/`, `.git/`, and build output directories are excluded by default.
- For comprehensive security auditing, combine these scanners with tools like `npm audit`, `pip-audit`, `govulncheck`, Snyk, Socket, or Semgrep.

## Adding New Scanners

1. Create a new script in `scanners/` following the existing pattern (banner, warn/info/note functions, exit codes).
2. Add a new Makefile target.
3. Add the scanner to the `scan` target's loop.

## License

MIT
