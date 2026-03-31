#!/bin/bash
#
# Python / PyPI Malware Scanner
#
# Detects suspicious patterns in Python codebases:
#   - Malicious setup.py / setup.cfg with code execution during install
#   - exec() / eval() / compile() abuse
#   - Obfuscated payloads (base64, marshal, zlib, codecs)
#   - Data exfiltration (requests, urllib, socket, subprocess)
#   - Typosquatting indicators in requirements
#   - Suspicious __import__ and importlib patterns
#   - Hidden code in __init__.py files
#
# Usage:
#   ./scan-python.sh /path/to/project
#   ./scan-python.sh                    # scans current directory

set -u

SCAN_DIR="${1:-.}"
SCAN_DIR="$(cd "$SCAN_DIR" 2>/dev/null && pwd)" || { echo "Error: invalid directory"; exit 2; }

RED="" GREEN="" YELLOW="" CYAN="" BOLD="" RESET=""
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
fi

FINDINGS_FILE=$(mktemp)
echo 0 > "$FINDINGS_FILE"
trap 'rm -f "$FINDINGS_FILE"' EXIT

banner() {
    printf "\n${BOLD}=== Python / PyPI Malware Scanner ===${RESET}\n"
    printf "Target: ${BOLD}%s${RESET}\n\n" "$SCAN_DIR"
}

_inc_findings() {
    local c; c=$(cat "$FINDINGS_FILE"); echo $((c + 1)) > "$FINDINGS_FILE"
}

warn() {
    printf "  ${RED}[!]${RESET} ${BOLD}%s${RESET}: %s\n" "$1" "$2"
    _inc_findings
}

info() {
    printf "  ${YELLOW}[~]${RESET} ${BOLD}%s${RESET}: %s\n" "$1" "$2"
    _inc_findings
}

note() {
    printf "  ${CYAN}[i]${RESET} %s\n" "$1"
}

banner

# ---------------------------------------------------------------------------
# 1. Malicious setup.py / setup.cfg / pyproject.toml
# ---------------------------------------------------------------------------
printf "${BOLD}[1/8] Checking setup.py / build configuration...${RESET}\n"

find "$SCAN_DIR" -name "setup.py" -not -path "*/site-packages/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | while read -r setup; do
    rel="${setup#${SCAN_DIR}/}"

    # Code execution in setup.py (imports that shouldn't be there)
    if grep -nqE '(subprocess|os\.system|os\.popen|urllib|requests|http\.client|socket)\b' "$setup" 2>/dev/null; then
        warn "$rel" "setup.py imports suspicious modules (subprocess/os/network)"
    fi

    # exec/eval in setup.py
    if grep -nqE '\b(exec|eval|compile)\s*\(' "$setup" 2>/dev/null; then
        warn "$rel" "setup.py contains exec/eval/compile (code execution during install)"
    fi

    # base64 in setup.py
    if grep -nqE '(base64\.b64decode|base64\.decodebytes|codecs\.decode)' "$setup" 2>/dev/null; then
        warn "$rel" "setup.py decodes encoded data (possible hidden payload)"
    fi

    # Custom install command classes
    if grep -nqE '(cmdclass|install.*Command|develop.*Command|egg_info.*Command)' "$setup" 2>/dev/null; then
        if grep -nqE '(subprocess|os\.system|os\.popen|exec\s*\(|eval\s*\()' "$setup" 2>/dev/null; then
            warn "$rel" "Custom install command with code execution"
        else
            info "$rel" "Custom install command class (review for suspicious behavior)"
        fi
    fi

    # URL fetching during setup
    if grep -nqE '(urlopen|urlretrieve|requests\.get|requests\.post|urllib\.request)' "$setup" 2>/dev/null; then
        warn "$rel" "setup.py fetches remote URLs during install"
    fi
done

# Check pyproject.toml for build-system scripts
find "$SCAN_DIR" -name "pyproject.toml" -not -path "*/.git/*" -not -path "*/.venv/*" \
    -not -path "*/venv/*" 2>/dev/null | while read -r toml; do
    rel="${toml#${SCAN_DIR}/}"

    if grep -qE '\[tool\.setuptools\.cmdclass\]' "$toml" 2>/dev/null; then
        info "$rel" "Custom build commands in pyproject.toml"
    fi

    # Build backend pointing to unusual sources
    if grep -qE 'build-backend\s*=' "$toml" 2>/dev/null; then
        if grep -qE 'build-backend' "$toml" | grep -qvE '(setuptools|flit|poetry|hatchling|pdm|maturin|scikit-build)'; then
            warn "$rel" "Unusual build backend specified"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 2. exec / eval / compile abuse
# ---------------------------------------------------------------------------
printf "${BOLD}[2/8] Scanning for exec() / eval() / compile() abuse...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.py" -not -path "*/site-packages/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" \
    -not -path "*/__pycache__/*" 2>/dev/null | while read -r pyfile; do
    rel="${pyfile#${SCAN_DIR}/}"

    # exec() with decoded/encoded content
    if grep -nqE 'exec\s*\(\s*(base64|codecs|zlib|marshal|bytes\.fromhex|bytearray)' "$pyfile" 2>/dev/null; then
        warn "$rel" "exec() with encoded/decoded payload"
    fi

    # exec(compile(...))
    if grep -nqE 'exec\s*\(\s*compile\s*\(' "$pyfile" 2>/dev/null; then
        warn "$rel" "exec(compile(...)) pattern"
    fi

    # CRITICAL: fetch-then-exec -- exec(requests.get(...).text) or eval(urllib response)
    if grep -qlE '(requests\.|urllib|http\.client|urlopen)' "$pyfile" 2>/dev/null; then
        if grep -qlE '(exec|eval|compile)\s*\(' "$pyfile" 2>/dev/null; then
            warn "$rel" "CRITICAL: Remote content fetch + code execution (RCE backdoor pattern)"
        fi
    fi

    # eval with decode
    if grep -nqE 'eval\s*\(\s*(base64|codecs|zlib|marshal|bytes\.fromhex)' "$pyfile" 2>/dev/null; then
        warn "$rel" "eval() with encoded payload"
    fi

    # Multi-layer decode: base64 -> zlib -> exec
    if grep -qlE 'base64' "$pyfile" 2>/dev/null; then
        if grep -qlE '(zlib|marshal|codecs)' "$pyfile" 2>/dev/null; then
            if grep -qlE '(exec|eval)' "$pyfile" 2>/dev/null; then
                warn "$rel" "Multi-layer decode chain + code execution"
            fi
        fi
    fi
done

# ---------------------------------------------------------------------------
# 3. Obfuscated payloads
# ---------------------------------------------------------------------------
printf "${BOLD}[3/8] Scanning for obfuscated payloads...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.py" -not -path "*/site-packages/*" -not -path "*/.git/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" -not -path "*/__pycache__/*" 2>/dev/null | while read -r pyfile; do
    rel="${pyfile#${SCAN_DIR}/}"

    # Very long base64 strings
    if grep -nqE '[A-Za-z0-9+/]{200,}={0,2}' "$pyfile" 2>/dev/null; then
        info "$rel" "Contains very long Base64-like string (>200 chars)"
    fi

    # marshal.loads (deserialize Python bytecode)
    if grep -nqE 'marshal\.loads\s*\(' "$pyfile" 2>/dev/null; then
        warn "$rel" "marshal.loads() (Python bytecode deserialization)"
    fi

    # __import__ obfuscation
    if grep -nqE '__import__\s*\(\s*[^"'\''a-zA-Z]' "$pyfile" 2>/dev/null; then
        warn "$rel" "Dynamic __import__ with non-literal argument"
    fi

    # importlib with constructed string
    if grep -nqE 'importlib\.import_module\s*\(' "$pyfile" 2>/dev/null; then
        if grep -nqE 'importlib\.import_module\s*\(\s*[^"'\'']' "$pyfile" 2>/dev/null; then
            info "$rel" "importlib.import_module with dynamic argument"
        fi
    fi

    # bytes.fromhex for code
    if grep -nqE 'bytes\.fromhex\s*\(' "$pyfile" 2>/dev/null; then
        if grep -qlE '(exec|eval|compile)' "$pyfile" 2>/dev/null; then
            warn "$rel" "bytes.fromhex + code execution"
        fi
    fi

    # Excessive string concatenation/chr() building
    if grep -nqE '(chr\s*\(\s*[0-9]+\s*\)\s*\+?\s*){10,}' "$pyfile" 2>/dev/null; then
        warn "$rel" "chr() string building (10+ chars, possible obfuscation)"
    fi

    # Lambda obfuscation: (lambda: exec(...))()
    if grep -nqE 'lambda.*exec\s*\(' "$pyfile" 2>/dev/null; then
        warn "$rel" "Lambda wrapping exec() call"
    fi

    # getattr(__builtins__) - dynamic access to built-in functions
    if grep -nqE 'getattr\s*\(\s*__builtins__' "$pyfile" 2>/dev/null; then
        warn "$rel" "getattr(__builtins__) - dynamic access to built-in functions"
    fi

    # Encrypted/encoded payloads (Fernet, AES, etc.)
    if grep -nqE '(Fernet|AES\.new|DES\.new|RC4|Blowfish)' "$pyfile" 2>/dev/null; then
        if grep -qlE '(exec|eval|compile|subprocess|os\.system)' "$pyfile" 2>/dev/null; then
            warn "$rel" "Encryption library + code execution (encrypted payload)"
        fi
    fi

    # Browser credential theft indicators
    if grep -nqE '(Chrome|Firefox|\.mozilla|Cookies|Login Data|keychain|Web Data|Local State)' "$pyfile" 2>/dev/null; then
        if grep -qlE '(sqlite3|requests\.|urllib|socket|CryptUnprotectData|decrypt)' "$pyfile" 2>/dev/null; then
            warn "$rel" "Browser credential/cookie theft pattern"
        fi
    fi

    # Hardcoded IP:port (C2 endpoint)
    if grep -nqE '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b' "$pyfile" 2>/dev/null; then
        info "$rel" "Contains IP:port literal (possible C2 endpoint)"
    fi
done

# ---------------------------------------------------------------------------
# 4. Data exfiltration patterns
# ---------------------------------------------------------------------------
printf "${BOLD}[4/8] Scanning for data exfiltration patterns...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.py" -not -path "*/site-packages/*" -not -path "*/.git/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" -not -path "*/__pycache__/*" 2>/dev/null | while read -r pyfile; do
    rel="${pyfile#${SCAN_DIR}/}"

    # Reading sensitive files + network
    if grep -qlE '(\.ssh|\.aws|\.env|\.npmrc|\.pypirc|/etc/passwd|/etc/shadow|\.gitconfig|\.netrc)' "$pyfile" 2>/dev/null; then
        if grep -qlE '(requests\.|urllib|http\.client|socket\.|smtplib)' "$pyfile" 2>/dev/null; then
            warn "$rel" "Reads sensitive files AND makes network calls"
        fi
    fi

    # Webhook/exfil endpoints
    if grep -nqE '(discord\.com/api/webhooks|hooks\.slack\.com|webhook\.site|pipedream\.net|requestbin|ngrok\.io|burpcollaborator|interact\.sh|oast\.)' "$pyfile" 2>/dev/null; then
        warn "$rel" "Contains webhook/exfiltration service URL"
    fi

    # Collecting env vars + sending
    if grep -qlE 'os\.environ' "$pyfile" 2>/dev/null; then
        if grep -qlE '(requests\.(post|get|put)|urllib\.request\.urlopen|http\.client)' "$pyfile" 2>/dev/null; then
            info "$rel" "Accesses os.environ AND makes HTTP requests"
        fi
    fi

    # DNS exfiltration via socket
    if grep -nqE 'socket\.getaddrinfo|socket\.gethostbyname' "$pyfile" 2>/dev/null; then
        if grep -qlE '(os\.environ|platform\.|getpass|subprocess)' "$pyfile" 2>/dev/null; then
            info "$rel" "DNS resolution + system info gathering (possible DNS exfil)"
        fi
    fi

    # Stealing tokens / credentials
    if grep -nqE '(token|password|secret|api_key|apikey|auth)' "$pyfile" 2>/dev/null; then
        if grep -nqE '(requests\.post|urllib\.request\.urlopen)' "$pyfile" 2>/dev/null; then
            if grep -nqE '(os\.environ|open\s*\()' "$pyfile" 2>/dev/null; then
                info "$rel" "Reads credentials/tokens + sends HTTP POST"
            fi
        fi
    fi
done

# ---------------------------------------------------------------------------
# 5. Subprocess / OS command execution
# ---------------------------------------------------------------------------
printf "${BOLD}[5/8] Scanning for suspicious subprocess usage...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.py" -not -path "*/site-packages/*" -not -path "*/.git/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" -not -path "*/__pycache__/*" 2>/dev/null | while read -r pyfile; do
    rel="${pyfile#${SCAN_DIR}/}"

    # subprocess with shell=True and variable input
    if grep -nqE 'subprocess\.(call|run|Popen|check_output)\s*\(.*shell\s*=\s*True' "$pyfile" 2>/dev/null; then
        info "$rel" "subprocess with shell=True"
    fi

    # os.system with variable
    if grep -nqE 'os\.system\s*\(\s*[^"'\'']' "$pyfile" 2>/dev/null; then
        info "$rel" "os.system() with variable argument"
    fi

    # os.popen
    if grep -nqE 'os\.popen\s*\(' "$pyfile" 2>/dev/null; then
        info "$rel" "os.popen() usage"
    fi

    # Reverse shell patterns
    if grep -nqE '(socket.*connect.*exec|/bin/sh.*socket|pty\.spawn)' "$pyfile" 2>/dev/null; then
        warn "$rel" "Possible reverse shell pattern"
    fi
done

# ---------------------------------------------------------------------------
# 6. Pickle / deserialization attacks
# ---------------------------------------------------------------------------
printf "${BOLD}[6/8] Scanning for deserialization risks...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.py" -not -path "*/site-packages/*" -not -path "*/.git/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" -not -path "*/__pycache__/*" 2>/dev/null | while read -r pyfile; do
    rel="${pyfile#${SCAN_DIR}/}"

    # pickle.loads with untrusted data
    if grep -nqE 'pickle\.(loads|load)\s*\(' "$pyfile" 2>/dev/null; then
        if grep -qlE '(requests\.|urllib|open\s*\(|sys\.stdin|input\()' "$pyfile" 2>/dev/null; then
            warn "$rel" "pickle.load(s) with potentially untrusted data source"
        else
            info "$rel" "pickle.load(s) usage (ensure trusted data source)"
        fi
    fi

    # yaml.load without SafeLoader
    if grep -nqE 'yaml\.load\s*\(' "$pyfile" 2>/dev/null; then
        if ! grep -qE 'Loader\s*=\s*(yaml\.)?SafeLoader' "$pyfile" 2>/dev/null; then
            info "$rel" "yaml.load() without SafeLoader (code execution risk)"
        fi
    fi

    # Custom __reduce__ method (pickle exploit)
    if grep -nqE 'def\s+__reduce__\s*\(' "$pyfile" 2>/dev/null; then
        if grep -qlE '(os\.|subprocess|exec|eval|system)' "$pyfile" 2>/dev/null; then
            warn "$rel" "__reduce__ method with command execution (pickle exploit pattern)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 7. Requirements file checks
# ---------------------------------------------------------------------------
printf "${BOLD}[7/8] Checking requirements files...${RESET}\n"

find "$SCAN_DIR" \( -name "requirements*.txt" -o -name "constraints.txt" \) \
    -not -path "*/.git/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | while read -r req; do
    rel="${req#${SCAN_DIR}/}"

    # Dependencies from git URLs
    if grep -qE '(git\+https?://|git\+ssh://|git://)' "$req" 2>/dev/null; then
        info "$rel" "Dependencies installed from git URLs (verify sources)"
        grep -n 'git+' "$req" 2>/dev/null | head -3 | while read -r line; do
            note "    $line"
        done
    fi

    # Dependencies from direct URLs
    if grep -qE 'https?://' "$req" 2>/dev/null | grep -qvE '(git\+|pypi\.org|pythonhosted\.org)'; then
        warn "$rel" "Dependencies from non-PyPI URLs"
    fi

    # --index-url or --extra-index-url pointing to unknown registries
    if grep -qE '--index-url|--extra-index-url' "$req" 2>/dev/null; then
        if grep -qE '(--index-url|--extra-index-url)' "$req" | grep -qvE '(pypi\.org|pythonhosted\.org|artifactory|nexus|devpi)'; then
            warn "$rel" "Custom package index URL (possible dependency confusion)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 8. Suspicious .pth files (auto-execute on Python startup)
# ---------------------------------------------------------------------------
printf "${BOLD}[8/8] Checking for suspicious .pth files...${RESET}\n"

find "$SCAN_DIR" -name "*.pth" -not -path "*/.git/*" 2>/dev/null | while read -r pth; do
    rel="${pth#${SCAN_DIR}/}"

    # .pth files with import statements (auto-executed)
    if grep -qE '^import\s' "$pth" 2>/dev/null; then
        warn "$rel" ".pth file with import statement (auto-executes on Python startup)"
    fi
done

# Check for .egg-link or .egg-info with suspicious content
find "$SCAN_DIR" -name "*.egg-info" -type d -not -path "*/site-packages/*" \
    -not -path "*/.git/*" 2>/dev/null | while read -r egg; do
    rel="${egg#${SCAN_DIR}/}"
    if [ -f "${egg}/entry_points.txt" ]; then
        if grep -qE '(console_scripts|gui_scripts)' "${egg}/entry_points.txt" 2>/dev/null; then
            info "$rel" "Has entry_points (review for unexpected scripts)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
FINDINGS=$(cat "$FINDINGS_FILE")
printf "\n${BOLD}========================================${RESET}\n"
if [ "$FINDINGS" -gt 0 ]; then
    printf "  ${RED}${BOLD}Python scan: %d finding(s)${RESET}\n" "$FINDINGS"
else
    printf "  ${GREEN}${BOLD}Python scan: Clean${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n\n"

[ "$FINDINGS" -gt 0 ] && exit 1 || exit 0
