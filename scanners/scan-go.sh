#!/bin/bash
#
# Go Module Malware Scanner
#
# Detects suspicious patterns in Go codebases:
#   - Malicious go.mod replace directives (dependency hijacking)
#   - Suspicious init() functions (network calls, exec, env stealing)
#   - os/exec usage with encoded/obfuscated commands
#   - Data exfiltration (HTTP calls with system info)
#   - CGo abuse (hidden C code execution)
#   - Build constraint tricks (//go:build ignore hiding malicious code)
#   - Suspicious go:generate directives
#
# Usage:
#   ./scan-go.sh /path/to/project
#   ./scan-go.sh                    # scans current directory

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
    printf "\n${BOLD}=== Go Module Malware Scanner ===${RESET}\n"
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
# 1. go.mod replace directives (dependency hijacking)
# ---------------------------------------------------------------------------
printf "${BOLD}[1/7] Checking go.mod replace directives...${RESET}\n"

find "$SCAN_DIR" -name "go.mod" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gomod; do
    rel="${gomod#${SCAN_DIR}/}"

    # Replace directives pointing to local paths
    if grep -nqE '^\s*replace\s+.*=>\s*\.\.?/' "$gomod" 2>/dev/null; then
        warn "$rel" "replace directive pointing to local path (dependency override)"
        grep -nE '^\s*replace\s+.*=>\s*\.\.?/' "$gomod" 2>/dev/null | head -3 | while read -r line; do
            note "    $line"
        done
    fi

    # Replace directives pointing to non-standard repos
    if grep -nqE '^\s*replace\s+' "$gomod" 2>/dev/null; then
        suspicious=$(grep -nE '^\s*replace\s+' "$gomod" 2>/dev/null | grep -vE '(github\.com|golang\.org|google\.golang\.org|gopkg\.in|go\.uber\.org|\.\./)' | head -5)
        if [ -n "$suspicious" ]; then
            info "$rel" "replace directive pointing to non-standard source"
            echo "$suspicious" | head -3 | while read -r line; do
                note "    $line"
            done
        fi
    fi

    # Retract directives (unusual, can indicate compromised version)
    if grep -nqE '^\s*retract\s+' "$gomod" 2>/dev/null; then
        info "$rel" "Has retract directive (verify this is intentional)"
    fi

    # Dependencies from unusual domains
    if grep -nqE '^\s*require\s' "$gomod" 2>/dev/null || grep -nqE '^\t' "$gomod" 2>/dev/null; then
        suspicious_deps=$(grep -E '^\t[a-z]' "$gomod" 2>/dev/null | grep -vE '(github\.com|golang\.org|google\.golang\.org|gopkg\.in|go\.uber\.org|k8s\.io|sigs\.k8s\.io|cloud\.google\.com|gocloud\.dev|modernc\.org)' | head -5)
        if [ -n "$suspicious_deps" ]; then
            info "$rel" "Dependencies from less common domains (verify legitimacy)"
            echo "$suspicious_deps" | head -3 | while read -r dep; do
                note "    $dep"
            done
        fi
    fi
done

# ---------------------------------------------------------------------------
# 2. Suspicious init() functions
# ---------------------------------------------------------------------------
printf "${BOLD}[2/7] Scanning for suspicious init() functions...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gofile; do
    rel="${gofile#${SCAN_DIR}/}"

    # Check if file has init() function
    if grep -nqE '^\s*func\s+init\s*\(\s*\)' "$gofile" 2>/dev/null; then

        # init() with network calls
        if grep -qlE '(net/http|net\.Dial|http\.Get|http\.Post|http\.NewRequest)' "$gofile" 2>/dev/null; then
            warn "$rel" "init() function in file with network calls"
        fi

        # init() with exec
        if grep -qlE '(os/exec|exec\.Command|exec\.CommandContext)' "$gofile" 2>/dev/null; then
            warn "$rel" "init() function in file with os/exec"
        fi

        # init() with environment variable access
        if grep -qlE '(os\.Getenv|os\.Environ)' "$gofile" 2>/dev/null; then
            if grep -qlE '(net/http|net\.Dial|http\.)' "$gofile" 2>/dev/null; then
                warn "$rel" "init() reads env vars AND makes network calls"
            fi
        fi

        # init() with file operations on sensitive paths
        if grep -qlE '(\.ssh|\.aws|\.env|\.npmrc|/etc/passwd|\.gitconfig|\.netrc|\.docker/config)' "$gofile" 2>/dev/null; then
            warn "$rel" "init() in file accessing sensitive paths"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 3. os/exec with suspicious commands
# ---------------------------------------------------------------------------
printf "${BOLD}[3/7] Scanning for suspicious os/exec usage...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gofile; do
    rel="${gofile#${SCAN_DIR}/}"

    # exec.Command with shell interpreters
    if grep -nqE 'exec\.Command\s*\(\s*"(bash|sh|/bin/bash|/bin/sh|cmd|powershell|cmd\.exe)"' "$gofile" 2>/dev/null; then
        if grep -nqE '(curl|wget|nc |ncat|base64|/dev/tcp|whoami|id\b|cat /etc)' "$gofile" 2>/dev/null; then
            warn "$rel" "Shell execution with suspicious command"
        else
            info "$rel" "exec.Command with shell interpreter"
        fi
    fi

    # exec with string concatenation / fmt.Sprintf (possible obfuscation)
    if grep -nqE 'exec\.Command\s*\(\s*fmt\.' "$gofile" 2>/dev/null; then
        info "$rel" "exec.Command with formatted string argument"
    fi

    # exec with environment variable as command
    if grep -nqE 'exec\.Command\s*\(\s*os\.Getenv' "$gofile" 2>/dev/null; then
        warn "$rel" "exec.Command using environment variable as command"
    fi
done

# ---------------------------------------------------------------------------
# 4. Data exfiltration patterns
# ---------------------------------------------------------------------------
printf "${BOLD}[4/7] Scanning for data exfiltration patterns...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gofile; do
    rel="${gofile#${SCAN_DIR}/}"

    # Webhook/exfil endpoints
    if grep -nqE '(discord\.com/api/webhooks|hooks\.slack\.com|webhook\.site|pipedream\.net|requestbin|ngrok\.io|burpcollaborator|interact\.sh|oast\.)' "$gofile" 2>/dev/null; then
        warn "$rel" "Contains webhook/exfiltration service URL"
    fi

    # Collecting system info + HTTP POST
    if grep -qlE '(os\.Hostname|user\.Current|os\.Getenv|runtime\.GOOS|runtime\.GOARCH)' "$gofile" 2>/dev/null; then
        if grep -qlE '(http\.Post|http\.NewRequest|net\.Dial)' "$gofile" 2>/dev/null; then
            info "$rel" "Collects system info AND sends HTTP requests"
        fi
    fi

    # Reading sensitive files
    if grep -nqE 'os\.(Open|ReadFile)\s*\(\s*"[^"]*\.(ssh|aws|env|npmrc|gitconfig|netrc|docker)' "$gofile" 2>/dev/null; then
        warn "$rel" "Reads sensitive configuration files"
    fi

    # Raw TCP/UDP connections (possible C2)
    if grep -nqE 'net\.Dial\s*\(\s*"(tcp|udp)"' "$gofile" 2>/dev/null; then
        if grep -qlE '(os/exec|exec\.Command|os\.Getenv)' "$gofile" 2>/dev/null; then
            warn "$rel" "Raw TCP/UDP connection + exec capabilities (possible C2)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 5. CGo abuse
# ---------------------------------------------------------------------------
printf "${BOLD}[5/7] Scanning for suspicious CGo usage...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gofile; do
    rel="${gofile#${SCAN_DIR}/}"

    # import "C" with suspicious C code in comments
    if grep -qE '^import "C"' "$gofile" 2>/dev/null; then
        if grep -qE '(system\(|popen\(|exec[lv]p?\(|fork\(|dlopen\()' "$gofile" 2>/dev/null; then
            warn "$rel" "CGo with dangerous C function calls (system/exec/popen)"
        fi

        if grep -qE '(#include.*<stdlib|#include.*<unistd|#include.*<dlfcn)' "$gofile" 2>/dev/null; then
            info "$rel" "CGo importing system C headers"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 6. go:generate directives
# ---------------------------------------------------------------------------
printf "${BOLD}[6/7] Checking go:generate directives...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gofile; do
    rel="${gofile#${SCAN_DIR}/}"

    if grep -nqE '//go:generate' "$gofile" 2>/dev/null; then
        # Dangerous generate commands
        if grep -nE '//go:generate' "$gofile" 2>/dev/null | grep -qiE '(curl|wget|bash|sh |powershell|rm |del |nc |python|ruby|perl)'; then
            warn "$rel" "go:generate with suspicious command"
        fi

        # Generate calling remote scripts
        if grep -nE '//go:generate' "$gofile" 2>/dev/null | grep -qiE '(https?://|ftp://)'; then
            warn "$rel" "go:generate fetches remote URL"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 7. Build constraints and embed tricks
# ---------------------------------------------------------------------------
printf "${BOLD}[7/7] Checking build constraints and embed directives...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r gofile; do
    rel="${gofile#${SCAN_DIR}/}"

    # go:embed with suspicious file patterns
    if grep -nqE '//go:embed' "$gofile" 2>/dev/null; then
        if grep -nE '//go:embed' "$gofile" 2>/dev/null | grep -qiE '(\.(sh|bat|exe|dll|so|py|rb|pl|ps1)|/\.)'; then
            info "$rel" "go:embed including executable/hidden files"
        fi
    fi

    # Build constraint that skips file in normal builds but includes in specific OS
    # This is normal, but combined with malicious code it's suspicious
    if grep -nqE '//go:build\s+ignore' "$gofile" 2>/dev/null; then
        if grep -qlE '(exec\.Command|net/http|os\.Getenv|net\.Dial)' "$gofile" 2>/dev/null; then
            info "$rel" "File with //go:build ignore contains exec/network code"
        fi
    fi

    # go:linkname - bypasses Go export rules, can access unexported internals
    if grep -nqE '//go:linkname' "$gofile" 2>/dev/null; then
        info "$rel" "go:linkname directive (bypasses export rules, review intent)"
    fi

    # syscall.Exec / syscall.ForkExec (low-level exec, harder to detect)
    if grep -nqE 'syscall\.(Exec|ForkExec|StartProcess)\s*\(' "$gofile" 2>/dev/null; then
        warn "$rel" "syscall.Exec/ForkExec (low-level process execution)"
    fi

    # Hardcoded IP:port (C2 endpoint)
    if grep -nqE '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b' "$gofile" 2>/dev/null; then
        info "$rel" "Contains IP:port literal (possible C2 endpoint)"
    fi
done

# Check for suspicious binary files in the Go project
find "$SCAN_DIR" -type f \( -name "*.so" -o -name "*.dylib" -o -name "*.dll" \) \
    -not -path "*/.git/*" -not -path "*/vendor/*" 2>/dev/null | while read -r bin; do
    rel="${bin#${SCAN_DIR}/}"
    warn "$rel" "Compiled shared library in Go project"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
FINDINGS=$(cat "$FINDINGS_FILE")
printf "\n${BOLD}========================================${RESET}\n"
if [ "$FINDINGS" -gt 0 ]; then
    printf "  ${RED}${BOLD}Go scan: %d finding(s)${RESET}\n" "$FINDINGS"
else
    printf "  ${GREEN}${BOLD}Go scan: Clean${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n\n"

[ "$FINDINGS" -gt 0 ] && exit 1 || exit 0
