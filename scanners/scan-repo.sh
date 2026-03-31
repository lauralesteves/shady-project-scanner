#!/bin/bash
#
# General Repository Security Scanner
#
# Cross-language scanner for common malware indicators:
#   - Malicious git hooks
#   - Cryptocurrency miner signatures
#   - Secrets and credentials committed to repo
#   - Suspicious CI/CD pipeline modifications
#   - Suspicious Docker/container files
#   - Hidden Unicode/homoglyph attacks in source code
#   - Suspicious binaries and compiled artifacts
#   - Encoded payloads in any file type
#   - Environment variable exfiltration
#   - Suspicious Makefile / build script commands
#
# Usage:
#   ./scan-repo.sh /path/to/project
#   ./scan-repo.sh                    # scans current directory

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
    printf "\n${BOLD}=== General Repository Security Scanner ===${RESET}\n"
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
# 1. Malicious git hooks
# ---------------------------------------------------------------------------
printf "${BOLD}[1/14] Checking git hooks...${RESET}\n"

HOOKS_DIR="${SCAN_DIR}/.git/hooks"
if [ -d "$HOOKS_DIR" ]; then
    find "$HOOKS_DIR" -type f -executable 2>/dev/null | while read -r hook; do
        hookname="$(basename "$hook")"
        # Skip sample hooks
        case "$hookname" in *.sample) continue ;; esac

        rel=".git/hooks/$hookname"

        # Suspicious commands in hooks
        if grep -qiE '(curl|wget|nc |ncat|python|ruby|perl|bash -c|/dev/tcp|base64|eval|exec)' "$hook" 2>/dev/null; then
            warn "$rel" "Git hook contains suspicious commands"
        fi

        # Hooks that download and execute
        if grep -qiE '(curl.*\|\s*bash|wget.*\|\s*sh|curl.*-o.*&&.*chmod|bash\s*<\(curl)' "$hook" 2>/dev/null; then
            warn "$rel" "Git hook downloads and executes remote code"
        fi

        # Hooks that modify source files
        if grep -qiE '(sed\s+-i|perl\s+-pi|git\s+add\s|git\s+commit)' "$hook" 2>/dev/null; then
            info "$rel" "Git hook modifies files or commits (verify intended)"
        fi

        # Hooks that exfiltrate data
        if grep -qiE '(discord\.com|hooks\.slack|webhook\.site|pipedream|ngrok|requestbin)' "$hook" 2>/dev/null; then
            warn "$rel" "Git hook contains exfiltration URL"
        fi
    done
fi

# Also check for custom hooks directory configured via core.hooksPath
if [ -d "${SCAN_DIR}/.git" ]; then
    custom_hooks=$(git -C "$SCAN_DIR" config core.hooksPath 2>/dev/null)
    if [ -n "$custom_hooks" ] && [ "$custom_hooks" != ".git/hooks" ]; then
        info ".git/config" "Custom hooksPath configured: $custom_hooks"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Cryptocurrency miner signatures
# ---------------------------------------------------------------------------
printf "${BOLD}[2/14] Scanning for cryptocurrency miner signatures...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.py" -o -name "*.sh" -o -name "*.go" \
    -o -name "*.rb" -o -name "*.php" -o -name "*.rs" -o -name "*.java" -o -name "*.ts" \
    -o -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.json" \
    -o -name "Dockerfile*" -o -name "Makefile" -o -name "*.bat" -o -name "*.ps1" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" -not -path "*/site-packages/*" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    # Known mining software
    if grep -qlE '(xmrig|cryptonight|stratum\+tcp://|stratum\+ssl://|coinhive|coin-hive|monero\.hashvault|minergate|nanopool|supportxmr|nicehash)' "$file" 2>/dev/null; then
        warn "$rel" "Cryptocurrency miner reference detected"
    fi

    # Mining pool addresses
    if grep -nqE '(pool\.(minexmr|supportxmr|hashvault|nanopool|f2pool|antpool)\.com|mining\.subscribe)' "$file" 2>/dev/null; then
        warn "$rel" "Mining pool address found"
    fi

    # Monero/Bitcoin wallet address patterns
    if grep -nqE '4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}' "$file" 2>/dev/null; then
        info "$rel" "Possible Monero wallet address"
    fi
done

# ---------------------------------------------------------------------------
# 3. Secrets and credentials
# ---------------------------------------------------------------------------
printf "${BOLD}[3/14] Scanning for committed secrets...${RESET}\n"

find "$SCAN_DIR" -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) \
    -not -name ".env.example" -not -name ".env.sample" -not -name ".env.template" \
    -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null | while read -r envfile; do
    rel="${envfile#${SCAN_DIR}/}"
    warn "$rel" "Environment file with potential secrets committed to repo"
done

# Look for secrets in source code
find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.rb" \
    -o -name "*.php" -o -name "*.java" -o -name "*.ts" -o -name "*.yml" -o -name "*.yaml" \
    -o -name "*.json" -o -name "*.toml" -o -name "*.xml" -o -name "*.conf" -o -name "*.cfg" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" -not -path "*/site-packages/*" \
    -not -name "*.lock" -not -name "package-lock.json" -not -name "yarn.lock" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    # AWS keys
    if grep -nqE '(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16})' "$file" 2>/dev/null; then
        warn "$rel" "AWS Access Key ID detected"
    fi

    # Private keys
    if grep -nqE '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY' "$file" 2>/dev/null; then
        warn "$rel" "Private key detected"
    fi

    # GitHub tokens
    if grep -nqE '(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})' "$file" 2>/dev/null; then
        warn "$rel" "GitHub token detected"
    fi

    # Slack tokens
    if grep -nqE '(xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}|xoxp-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}|xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+)' "$file" 2>/dev/null; then
        warn "$rel" "Slack token detected"
    fi

    # Generic API key patterns
    if grep -nqE '(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\''"][a-zA-Z0-9]{20,}['\''"]' "$file" 2>/dev/null; then
        info "$rel" "Possible API key/secret in code"
    fi

    # JWT tokens (hardcoded)
    if grep -nqE 'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.' "$file" 2>/dev/null; then
        info "$rel" "Hardcoded JWT token"
    fi

    # Database connection strings with passwords
    if grep -nqE '(mysql|postgres|mongodb|redis|amqp)://[^:]+:[^@]+@' "$file" 2>/dev/null; then
        warn "$rel" "Database connection string with embedded credentials"
    fi
done

# Check for credential files
find "$SCAN_DIR" \( -name "credentials" -o -name "credentials.json" -o -name "service-account*.json" \
    -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "id_rsa" \
    -o -name "id_ed25519" -o -name "id_ecdsa" -o -name ".npmrc" -o -name ".pypirc" \
    -o -name ".docker/config.json" -o -name "htpasswd" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null | while read -r cred; do
    rel="${cred#${SCAN_DIR}/}"
    warn "$rel" "Credential/key file in repository"
done

# ---------------------------------------------------------------------------
# 4. CI/CD pipeline tampering
# ---------------------------------------------------------------------------
printf "${BOLD}[4/14] Checking CI/CD pipeline files...${RESET}\n"

# GitHub Actions
find "$SCAN_DIR" -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" 2>/dev/null | while read -r wf; do
    rel="${wf#${SCAN_DIR}/}"

    # Untrusted actions (not from well-known orgs, pinned to branch not SHA)
    if grep -nqE 'uses:\s+[^@]+@(main|master|latest|v[0-9]+)' "$wf" 2>/dev/null; then
        info "$rel" "GitHub Actions pinned to branch/tag instead of SHA"
    fi

    # Actions that download and execute scripts
    if grep -qiE '(curl.*\|\s*bash|curl.*\|\s*sh|wget.*\|\s*bash|bash\s*<\(curl)' "$wf" 2>/dev/null; then
        warn "$rel" "CI workflow downloads and pipes to shell"
    fi

    # Self-hosted runners (can be a security risk)
    if grep -qE 'runs-on:.*self-hosted' "$wf" 2>/dev/null; then
        info "$rel" "Uses self-hosted runners"
    fi

    # pull_request_target (can expose secrets to PR from forks)
    if grep -qE 'pull_request_target' "$wf" 2>/dev/null; then
        if grep -qE '(secrets\.|GITHUB_TOKEN)' "$wf" 2>/dev/null; then
            warn "$rel" "pull_request_target with secrets access (fork PR attack vector)"
        fi
    fi

    # Workflow with write permissions
    if grep -qE 'permissions:.*write' "$wf" 2>/dev/null; then
        info "$rel" "Workflow requests write permissions"
    fi
done

# GitLab CI
find "$SCAN_DIR" -name ".gitlab-ci.yml" -not -path "*/.git/*" 2>/dev/null | while read -r ci; do
    rel="${ci#${SCAN_DIR}/}"

    if grep -qiE '(curl.*\|\s*bash|wget.*\|\s*sh)' "$ci" 2>/dev/null; then
        warn "$rel" "GitLab CI downloads and pipes to shell"
    fi

    # include from external URLs
    if grep -qE 'include:' "$ci" 2>/dev/null; then
        if grep -qE '(remote:|https?://)' "$ci" 2>/dev/null; then
            info "$rel" "GitLab CI includes remote configuration"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 5. Suspicious Docker / container files
# ---------------------------------------------------------------------------
printf "${BOLD}[5/14] Checking Docker / container files...${RESET}\n"

find "$SCAN_DIR" \( -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) \
    -not -path "*/.git/*" 2>/dev/null | while read -r docker; do
    rel="${docker#${SCAN_DIR}/}"

    # Downloading and running scripts
    if grep -qiE '(curl.*\|\s*(bash|sh)|wget.*\|\s*(bash|sh)|curl.*&&.*chmod.*\+x)' "$docker" 2>/dev/null; then
        warn "$rel" "Docker file downloads and executes remote scripts"
    fi

    # Running as root without switching user
    if grep -qE '^FROM' "$docker" 2>/dev/null; then
        if ! grep -qE '^USER\s' "$docker" 2>/dev/null; then
            info "$rel" "Dockerfile runs as root (no USER directive)"
        fi
    fi

    # Privileged mode or host network
    if grep -qE '(privileged:\s*true|network_mode:\s*host|pid:\s*host)' "$docker" 2>/dev/null; then
        warn "$rel" "Container with privileged/host access"
    fi

    # Mounting sensitive host paths
    if grep -qE '(/var/run/docker\.sock|/etc/shadow|/etc/passwd|/root/|~/.ssh|~/.aws)' "$docker" 2>/dev/null; then
        warn "$rel" "Container mounts sensitive host paths"
    fi

    # Suspicious base images
    if grep -qiE '^FROM\s+(.*latest|.*@sha256)' "$docker" 2>/dev/null; then
        : # common, not flagging
    fi
done

# ---------------------------------------------------------------------------
# 6. Hidden Unicode / homoglyph attacks
# ---------------------------------------------------------------------------
printf "${BOLD}[6/14] Scanning for Unicode/homoglyph attacks...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.rb" \
    -o -name "*.php" -o -name "*.java" -o -name "*.ts" -o -name "*.c" -o -name "*.cpp" \
    -o -name "*.rs" -o -name "*.swift" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" \
    -not -path "*/.venv/*" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    # Bidirectional text override characters (Trojan Source attack - CVE-2021-42574)
    if grep -Pq '[\x{202A}\x{202B}\x{202C}\x{202D}\x{202E}\x{2066}\x{2067}\x{2068}\x{2069}]' "$file" 2>/dev/null; then
        warn "$rel" "Bidirectional Unicode override characters (Trojan Source attack)"
    fi

    # Zero-width characters used for obfuscation
    if grep -Pq '[\x{200B}\x{200C}\x{200D}\x{FEFF}]' "$file" 2>/dev/null; then
        info "$rel" "Zero-width Unicode characters (possible identifier obfuscation)"
    fi

    # Homoglyphs in identifiers (Cyrillic chars that look like Latin)
    if grep -Pq '[а-яА-Я]' "$file" 2>/dev/null; then
        if echo "$rel" | grep -qvE '\.(ru|uk|bg)\b'; then
            info "$rel" "Contains Cyrillic characters (possible homoglyph attack)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 7. Suspicious binaries and compiled artifacts
# ---------------------------------------------------------------------------
printf "${BOLD}[7/14] Checking for suspicious binary files...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.so" -o -name "*.dylib" \
    -o -name "*.bin" -o -name "*.elf" -o -name "*.com" -o -name "*.scr" -o -name "*.bat" \
    -o -name "*.cmd" -o -name "*.vbs" -o -name "*.vbe" -o -name "*.wsf" -o -name "*.wsh" \
    -o -name "*.ps1" -o -name "*.msi" -o -name "*.msp" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | while read -r bin; do
    rel="${bin#${SCAN_DIR}/}"

    case "$bin" in
        *.bat|*.cmd|*.ps1|*.vbs|*.vbe|*.wsf)
            # Check script content
            if grep -qiE '(Invoke-WebRequest|DownloadString|DownloadFile|Start-Process|New-Object.*Net\.WebClient|IEX|Invoke-Expression|cmd.*\/c|powershell.*-enc|-EncodedCommand|-WindowStyle\s+Hidden)' "$bin" 2>/dev/null; then
                warn "$rel" "Script with suspicious download/execute pattern"
            else
                info "$rel" "Script file in repository"
            fi
            ;;
        *.exe|*.dll|*.so|*.dylib|*.elf|*.msi)
            warn "$rel" "Binary executable in repository"
            ;;
        *)
            info "$rel" "Binary file in repository"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# 8. Suspicious Makefile / build scripts
# ---------------------------------------------------------------------------
printf "${BOLD}[8/14] Checking build scripts...${RESET}\n"

find "$SCAN_DIR" \( -name "Makefile" -o -name "GNUmakefile" -o -name "makefile" \
    -o -name "*.mk" -o -name "Rakefile" -o -name "Gruntfile*" -o -name "gulpfile*" \
    -o -name "build.sh" -o -name "install.sh" -o -name "deploy.sh" -o -name "postinstall.sh" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | while read -r build; do
    rel="${build#${SCAN_DIR}/}"

    # Download and execute
    if grep -qiE '(curl.*\|\s*(bash|sh)|wget.*\|\s*(bash|sh)|curl.*-o.*&&.*(chmod|bash|sh)|bash\s*<\(curl)' "$build" 2>/dev/null; then
        warn "$rel" "Build script downloads and executes remote code"
    fi

    # Base64 decode and execute
    if grep -qiE '(base64.*\|\s*(bash|sh)|echo.*\|\s*base64.*-d)' "$build" 2>/dev/null; then
        warn "$rel" "Build script decodes and executes base64 payload"
    fi

    # Reverse shells
    if grep -qiE '(/dev/tcp/|mkfifo|nc\s+-[elp]|ncat.*-[elp]|bash\s+-i\s+>&)' "$build" 2>/dev/null; then
        warn "$rel" "Build script contains reverse shell pattern"
    fi

    # Modifying system files
    if grep -qiE '(echo.*>>\s*/etc/|chmod\s+[0-7]*\s+/|chown.*/)' "$build" 2>/dev/null; then
        info "$rel" "Build script modifies system files"
    fi
done

# ---------------------------------------------------------------------------
# 9. Large encoded blobs in any file
# ---------------------------------------------------------------------------
printf "${BOLD}[9/14] Scanning for large encoded blobs...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.rb" \
    -o -name "*.php" -o -name "*.java" -o -name "*.ts" -o -name "*.sh" -o -name "*.yml" \
    -o -name "*.yaml" -o -name "*.json" -o -name "*.xml" -o -name "*.conf" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" \
    -not -path "*/.venv/*" -not -name "*.lock" -not -name "package-lock.json" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    # Very long single lines (>2000 chars) - likely obfuscated/minified
    if awk 'length > 2000 { found=1; exit } END { exit !found }' "$file" 2>/dev/null; then
        # Skip known minified files
        case "$rel" in
            *.min.js|*.min.css|*bundle*|*chunk*|*-lock*) continue ;;
        esac
        info "$rel" "Contains very long lines (>2000 chars, possible obfuscation)"
    fi
done

# ---------------------------------------------------------------------------
# 10. Suspicious cron jobs / scheduled tasks in repo
# ---------------------------------------------------------------------------
printf "${BOLD}[10/14] Checking for embedded cron/scheduled tasks...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "crontab" -o -name "*.cron" -o -name "cron.d" \) \
    -not -path "*/.git/*" 2>/dev/null | while read -r cron; do
    rel="${cron#${SCAN_DIR}/}"

    if grep -qiE '(curl|wget|python|ruby|perl|bash|nc\s)' "$cron" 2>/dev/null; then
        info "$rel" "Cron file with network/script commands"
    fi
done

# ---------------------------------------------------------------------------
# 11. Suspicious VS Code / IDE extensions
# ---------------------------------------------------------------------------
printf "${BOLD}[11/14] Checking IDE configuration...${RESET}\n"

if [ -f "${SCAN_DIR}/.vscode/extensions.json" ]; then
    info ".vscode/extensions.json" "VS Code extensions recommendations (verify all are legitimate)"
fi

if [ -f "${SCAN_DIR}/.vscode/settings.json" ]; then
    if grep -qE '(terminal\.integrated\.(shell|shellArgs)|task|launch)' "${SCAN_DIR}/.vscode/settings.json" 2>/dev/null; then
        info ".vscode/settings.json" "VS Code settings configure terminal/tasks (review for safety)"
    fi
fi

# Check for .vscode/tasks.json with suspicious tasks
if [ -f "${SCAN_DIR}/.vscode/tasks.json" ]; then
    if grep -qiE '(curl|wget|bash|sh -c|powershell|cmd\.exe|eval|python -c)' "${SCAN_DIR}/.vscode/tasks.json" 2>/dev/null; then
        warn ".vscode/tasks.json" "VS Code task with suspicious command"
    fi
fi

# ---------------------------------------------------------------------------
# 12. GitHub/GitLab config abuse
# ---------------------------------------------------------------------------
printf "${BOLD}[12/14] Checking repository config...${RESET}\n"

# .gitattributes with filter drivers (can execute arbitrary code)
if [ -f "${SCAN_DIR}/.gitattributes" ]; then
    if grep -qE 'filter\s*=' "${SCAN_DIR}/.gitattributes" 2>/dev/null; then
        info ".gitattributes" "Custom git filter drivers defined (can execute code on checkout)"
    fi
fi

# .gitconfig in repo
if [ -f "${SCAN_DIR}/.gitconfig" ]; then
    warn ".gitconfig" "Local .gitconfig in repository (can override git behavior)"
fi

# FUNDING.yml abuse (redirecting to attacker's wallets)
if [ -f "${SCAN_DIR}/.github/FUNDING.yml" ]; then
    if grep -qE '(custom|ko_fi|open_collective|community_bridge|patreon)' "${SCAN_DIR}/.github/FUNDING.yml" 2>/dev/null; then
        info ".github/FUNDING.yml" "Funding file present (verify URLs are legitimate)"
    fi
fi

# ---------------------------------------------------------------------------
# 13. Reverse shell patterns (cross-language)
# ---------------------------------------------------------------------------
printf "${BOLD}[13/14] Scanning for reverse shell patterns...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.rb" \
    -o -name "*.php" -o -name "*.sh" -o -name "*.pl" -o -name "*.java" -o -name "*.ts" \
    -o -name "*.rs" -o -name "*.c" -o -name "*.cpp" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" \
    -not -path "*/.venv/*" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    # Bash reverse shell
    if grep -nqE '(bash\s+-i\s+>&\s*/dev/tcp|/dev/tcp/[0-9]+\.[0-9]+|mkfifo.*/tmp/.*nc\s|nc\s+-[elp])' "$file" 2>/dev/null; then
        warn "$rel" "Bash/netcat reverse shell pattern"
    fi

    # Python reverse shell
    if grep -nqE 'socket.*connect.*subprocess|pty\.spawn.*(/bin/sh|/bin/bash)' "$file" 2>/dev/null; then
        warn "$rel" "Python reverse shell pattern"
    fi

    # PHP reverse shell
    if grep -nqE 'fsockopen.*\$_(GET|POST)|socket_create.*socket_connect.*shell_exec' "$file" 2>/dev/null; then
        warn "$rel" "PHP reverse shell pattern"
    fi

    # Perl reverse shell
    if grep -nqE 'IO::Socket::INET.*exec.*(/bin/sh|/bin/bash|cmd\.exe)' "$file" 2>/dev/null; then
        warn "$rel" "Perl reverse shell pattern"
    fi
done

# ---------------------------------------------------------------------------
# 14. Hardcoded IP:port endpoints (cross-language)
# ---------------------------------------------------------------------------
printf "${BOLD}[14/14] Scanning for hardcoded IP:port endpoints...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.sh" -o -name "*.yml" -o -name "*.yaml" \
    -o -name "Makefile" -o -name "*.bat" -o -name "*.ps1" \) \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    # IP:port in build/config scripts (excluding common localhost patterns)
    if grep -nE '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}\b' "$file" 2>/dev/null | grep -qvE '(127\.0\.0\.1|0\.0\.0\.0|localhost|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)'; then
        info "$rel" "Contains non-private IP:port literal (possible C2 or exfil endpoint)"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
FINDINGS=$(cat "$FINDINGS_FILE")
printf "\n${BOLD}========================================${RESET}\n"
if [ "$FINDINGS" -gt 0 ]; then
    printf "  ${RED}${BOLD}Repo scan: %d finding(s)${RESET}\n" "$FINDINGS"
else
    printf "  ${GREEN}${BOLD}Repo scan: Clean${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n\n"

[ "$FINDINGS" -gt 0 ] && exit 1 || exit 0
