#!/bin/bash
#
# Node.js / npm Malware Scanner
#
# Detects suspicious patterns in Node.js projects:
#   - Malicious pre/post install scripts in package.json
#   - eval() / Function() abuse and obfuscated code
#   - child_process spawning and shell execution
#   - Data exfiltration (HTTP calls, DNS lookups, env stealing)
#   - Suspicious dependencies (typosquatting indicators)
#   - Encoded payloads (base64, hex blobs)
#   - Minified/obfuscated one-liners in config files
#
# Usage:
#   ./scan-node.sh /path/to/project
#   ./scan-node.sh                    # scans current directory

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
    printf "\n${BOLD}=== Node.js / npm Malware Scanner ===${RESET}\n"
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
# 1. Suspicious install scripts in package.json
# ---------------------------------------------------------------------------
printf "${BOLD}[1/8] Checking package.json install scripts...${RESET}\n"

find "$SCAN_DIR" -name "package.json" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | while read -r pjson; do
    rel="${pjson#${SCAN_DIR}/}"

    # Check for preinstall / postinstall / install scripts
    for hook in preinstall install postinstall preuninstall postuninstall; do
        script_val=$(grep -oP "\"$hook\"\s*:\s*\"[^\"]*\"" "$pjson" 2>/dev/null | head -1)
        if [ -n "$script_val" ]; then
            # Flag dangerous commands inside install hooks
            if echo "$script_val" | grep -qiE '(curl|wget|nc |ncat|bash|sh -c|node -e|eval|exec|powershell|cmd\.exe|/dev/tcp|base64)'; then
                warn "$rel" "Suspicious '$hook' script: $script_val"
            elif echo "$script_val" | grep -qiE '(http://|https://|ftp://)'; then
                warn "$rel" "'$hook' script fetches remote URL: $script_val"
            else
                info "$rel" "Has '$hook' script (review manually): $script_val"
            fi
        fi
    done

    # Check for suspicious dependency names (common typosquatting patterns)
    if grep -qE '"(lod[a@]sh|chal[kc]|col[ou]rs-js|event-stream|flatmap-stream|ua-parser-jss|rc[^"]*exploit)"' "$pjson" 2>/dev/null; then
        warn "$rel" "Potentially typosquatted dependency name detected"
    fi

    # Check for bundledDependencies with suspicious entries
    if grep -q '"bundledDependencies"' "$pjson" 2>/dev/null || grep -q '"bundleDependencies"' "$pjson" 2>/dev/null; then
        info "$rel" "Has bundledDependencies (can hide malicious packages)"
    fi
done

# ---------------------------------------------------------------------------
# 2. eval / Function constructor abuse
# ---------------------------------------------------------------------------
printf "${BOLD}[2/8] Scanning for eval() / Function() abuse...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/dist/*" \
    -not -path "*/.next/*" -not -path "*/build/*" -not -path "*/vendor/*" 2>/dev/null | while read -r jsfile; do
    rel="${jsfile#${SCAN_DIR}/}"

    # eval with variable/encoded content (not simple string literals)
    if grep -nE 'eval\s*\(' "$jsfile" 2>/dev/null | grep -qvE 'eval\s*\(\s*['\''"]'; then
        warn "$rel" "eval() with dynamic argument"
    fi

    # new Function() constructor
    if grep -nqE 'new\s+Function\s*\(' "$jsfile" 2>/dev/null; then
        info "$rel" "new Function() constructor (dynamic code execution)"
    fi

    # eval(atob(...)) or eval(Buffer.from(...))
    if grep -nqE 'eval\s*\(\s*(atob|Buffer\.from)\s*\(' "$jsfile" 2>/dev/null; then
        warn "$rel" "eval() with encoded payload (atob/Buffer.from)"
    fi

    # eval(require('child_process'))
    if grep -nqE "eval.*require\s*\(\s*['\"]child_process['\"]" "$jsfile" 2>/dev/null; then
        warn "$rel" "eval with child_process require"
    fi

    # CRITICAL: eval(response.data) / eval(res.body) -- fetch-then-eval RCE backdoor
    if grep -nqE 'eval\s*\(\s*(response|res)\s*\.\s*(data|body|text|result)' "$jsfile" 2>/dev/null; then
        warn "$rel" "CRITICAL: eval() on HTTP response data (remote code execution backdoor)"
    fi

    # Broader fetch-then-eval: .then(r => eval(r...))
    if grep -nqE '\.then\s*\(.*eval\s*\(' "$jsfile" 2>/dev/null; then
        warn "$rel" "CRITICAL: HTTP response piped to eval() in .then() chain (RCE backdoor)"
    fi

    # fetch/axios + eval in same file (weaker signal but worth flagging)
    if grep -qlE '(axios|fetch|https?\.request|got\(|node-fetch)' "$jsfile" 2>/dev/null; then
        if grep -qlE 'eval\s*\(' "$jsfile" 2>/dev/null; then
            warn "$rel" "File contains both HTTP client and eval() (review for fetch-then-eval pattern)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 3. child_process and shell execution
# ---------------------------------------------------------------------------
printf "${BOLD}[3/8] Scanning for child_process / shell execution...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/dist/*" \
    -not -path "*/.next/*" -not -path "*/build/*" 2>/dev/null | while read -r jsfile; do
    rel="${jsfile#${SCAN_DIR}/}"

    # execSync / exec with suspicious commands
    if grep -nE "(execSync|spawnSync|exec)\s*\(" "$jsfile" 2>/dev/null | grep -qiE '(curl|wget|bash|sh\s|powershell|cmd|nc\s|/bin/sh|/bin/bash|whoami|id\s|cat /etc|/dev/tcp)'; then
        warn "$rel" "Shell execution with suspicious command"
    fi

    # Dynamic require of child_process (obfuscation)
    if grep -nqE "require\s*\(\s*['\"]child_process['\"]\.exec(Sync)?\s*\(\s*['\"]" "$jsfile" 2>/dev/null; then
        : # normal usage, skip
    elif grep -nqE "require\s*\([^)]*child.process" "$jsfile" 2>/dev/null | grep -qE '(\+|concat|join|split|reverse|replace)'; then
        warn "$rel" "Obfuscated child_process require"
    fi

    # String concatenation to build 'child_process'
    if grep -nqE "['\"]child['\"].*['\"]process['\"]|['\"]ch['\"].*['\"]ild_pro['\"]" "$jsfile" 2>/dev/null; then
        warn "$rel" "Suspicious string building (possible child_process obfuscation)"
    fi
done

# ---------------------------------------------------------------------------
# 4. Data exfiltration patterns
# ---------------------------------------------------------------------------
printf "${BOLD}[4/8] Scanning for data exfiltration patterns...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/dist/*" \
    -not -path "*/.next/*" -not -path "*/build/*" 2>/dev/null | while read -r jsfile; do
    rel="${jsfile#${SCAN_DIR}/}"

    # Reading environment variables + HTTP request in same file
    if grep -qlE 'process\.env' "$jsfile" 2>/dev/null; then
        if grep -qlE '(https?\.request|fetch\s*\(|axios|got\(|node-fetch|request\()' "$jsfile" 2>/dev/null; then
            info "$rel" "Reads process.env AND makes HTTP requests (potential exfiltration)"
        fi
    fi

    # Reading sensitive files
    if grep -nqE "readFileSync\s*\(\s*['\"](/etc/passwd|/etc/shadow|~/.ssh|~/.aws|~/.npmrc|\.env)" "$jsfile" 2>/dev/null; then
        warn "$rel" "Reads sensitive system files"
    fi

    # DNS exfiltration
    if grep -nqE "(dns\.resolve|dns\.lookup|dgram.*send)" "$jsfile" 2>/dev/null; then
        if grep -qlE '(process\.env|readFile|hostname|os\.platform)' "$jsfile" 2>/dev/null; then
            info "$rel" "DNS functions + system info gathering (possible DNS exfiltration)"
        fi
    fi

    # Webhook/exfil URLs
    if grep -nqE '(discord\.com/api/webhooks|hooks\.slack\.com|webhook\.site|pipedream\.net|requestbin|ngrok\.io|burpcollaborator|interact\.sh|oast\.)' "$jsfile" 2>/dev/null; then
        warn "$rel" "Contains webhook/exfiltration service URL"
    fi

    # Sending hostname, username, IP to external service
    if grep -nqE '(os\.hostname|os\.userInfo|os\.networkInterfaces|os\.homedir)' "$jsfile" 2>/dev/null; then
        if grep -qlE '(fetch|https?\.request|axios|XMLHttpRequest)' "$jsfile" 2>/dev/null; then
            info "$rel" "Gathers OS info AND makes network requests"
        fi
    fi

    # CI/CD token harvesting
    if grep -nqE '(GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|CIRCLE_TOKEN|JENKINS_URL|GITLAB_TOKEN|TRAVIS_TOKEN)' "$jsfile" 2>/dev/null; then
        if grep -qlE '(fetch|https?\.request|axios|got\(|http\.request)' "$jsfile" 2>/dev/null; then
            warn "$rel" "Accesses CI/CD tokens AND makes HTTP requests (credential theft)"
        fi
    fi

    # Hardcoded IP:port (possible C2 server)
    if grep -nqE '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b' "$jsfile" 2>/dev/null; then
        info "$rel" "Contains IP:port literal (possible C2 endpoint)"
    fi

    # String.fromCharCode obfuscation
    if grep -nqE '(String\.fromCharCode\s*\(\s*[0-9]+\s*(,\s*[0-9]+\s*){5,})' "$jsfile" 2>/dev/null; then
        warn "$rel" "String.fromCharCode with many char codes (obfuscation)"
    fi

    # decodeURIComponent / unescape with long encoded strings
    if grep -nqE '(decodeURIComponent|unescape)\s*\(\s*['\''"](%[0-9a-fA-F]{2}){10,}' "$jsfile" 2>/dev/null; then
        warn "$rel" "decodeURIComponent/unescape with long encoded payload"
    fi
done

# ---------------------------------------------------------------------------
# 5. Obfuscated / encoded payloads
# ---------------------------------------------------------------------------
printf "${BOLD}[5/8] Scanning for obfuscated / encoded payloads...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/dist/*" \
    -not -path "*/.next/*" -not -path "*/build/*" 2>/dev/null | while read -r jsfile; do
    rel="${jsfile#${SCAN_DIR}/}"

    # Long base64 strings (>100 chars)
    if grep -nqE '[A-Za-z0-9+/]{100,}={0,2}' "$jsfile" 2>/dev/null; then
        info "$rel" "Contains long Base64-like string (>100 chars)"
    fi

    # Hex-encoded strings (\x pattern repeated)
    if grep -nqE '(\\x[0-9a-fA-F]{2}){20,}' "$jsfile" 2>/dev/null; then
        warn "$rel" "Contains long hex-encoded string"
    fi

    # Unicode escape sequences used for obfuscation
    if grep -nqE '(\\u[0-9a-fA-F]{4}){10,}' "$jsfile" 2>/dev/null; then
        info "$rel" "Contains long Unicode escape sequence (possible obfuscation)"
    fi

    # Buffer.from + base64 decoding
    if grep -nqE "Buffer\.from\s*\([^)]+,\s*['\"]base64['\"]" "$jsfile" 2>/dev/null; then
        if grep -qlE '(eval|exec|spawn|Function)' "$jsfile" 2>/dev/null; then
            warn "$rel" "Base64 decoding + code execution"
        fi
    fi

    # Obfuscator.io / javascript-obfuscator patterns
    if grep -nqE '_0x[a-f0-9]{4,}\[' "$jsfile" 2>/dev/null; then
        warn "$rel" "javascript-obfuscator pattern detected (_0x... variable names)"
    fi

    # Self-rewriting string-array function (obfuscator.io string-array stage)
    # Pattern: function X(){var Y=['...',...]; X=function(){return Y;};return X();}
    # Works regardless of variable name (this variant uses 1-char names like 'a','br')
    if awk '
        /function[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*\([[:space:]]*\)[[:space:]]*\{[[:space:]]*var[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=[[:space:]]*\[/ {seen=1}
        seen && /=[[:space:]]*function[[:space:]]*\([[:space:]]*\)[[:space:]]*\{[[:space:]]*return[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*;?[[:space:]]*\}[[:space:]]*;[[:space:]]*return[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*\([[:space:]]*\)/ {found=1; exit}
        END {exit !found}
    ' "$jsfile" 2>/dev/null; then
        warn "$rel" "Self-rewriting string-array function (obfuscator.io string-array)"
    fi

    # Array rotation self-defending IIFE: f['push'](f['shift']())
    # The rotation loop keeps cycling until a checksum matches; tampering breaks decoding
    if grep -nqE "\[['\"]push['\"]\]\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\[['\"]shift['\"]\]\s*\(" "$jsfile" 2>/dev/null; then
        warn "$rel" "Array rotation self-defending pattern (push/shift IIFE)"
    fi

    # Custom Base64 alphabet (lowercase-first - non-standard)
    # Standard Base64 puts uppercase first; this swapped variant is the obfuscator's decoder
    if grep -qF "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" "$jsfile" 2>/dev/null; then
        warn "$rel" "Lowercase-first Base64 alphabet (obfuscator string-decoder signature)"
    fi

    # Decoder cache markers: random 6-char property keys assigned {} / !![] on a function
    # e.g. c['CFeNoz']={}, c['nrungE']=!![], b['ngSqpq']={}, b['NdfJqz']=!![]
    if grep -nqE "[A-Za-z_$][A-Za-z0-9_$]*\[['\"][A-Za-z]{6}['\"]\]\s*=\s*(\{\s*\}|!\!?\[\])" "$jsfile" 2>/dev/null; then
        info "$rel" "Random-key cache properties on a function (obfuscator decoder memoization)"
    fi

    # Multi-term hex arithmetic for plain integer constants
    # e.g. (-0x60c + -0x1f2*-0xf + -0x1564) -- 3+ hex literals combined just to produce a number
    if grep -nqE '\(-?0x[0-9a-fA-F]+\s*[+*\-]\s*-?0x[0-9a-fA-F]+\s*[+*\-]\s*-?0x[0-9a-fA-F]+\s*\)' "$jsfile" 2>/dev/null; then
        info "$rel" "Hex-arithmetic constant obfuscation (>=3 hex literals combined inline)"
    fi

    # Silent global error handlers - malware hides crashes from victim
    if grep -nqE "process\.on\s*\(\s*['\"]uncaughtException['\"]\s*,\s*function\s*\([^)]*\)\s*\{\s*\}\s*\)" "$jsfile" 2>/dev/null; then
        warn "$rel" "Silent process.on('uncaughtException') handler (hides crashes)"
    fi
    if grep -nqE "process\.on\s*\(\s*['\"]unhandledRejection['\"]\s*,\s*function\s*\([^)]*\)\s*\{\s*\}\s*\)" "$jsfile" 2>/dev/null; then
        warn "$rel" "Silent process.on('unhandledRejection') handler (hides promise errors)"
    fi

    # IPv4-from-octets concat chain: ''.concat(N,'.').concat(N,'.').concat(N,'.').concat(N)
    # 3 consecutive ",'.')" arguments is a strong signal of building an IP literal at runtime
    # to bypass static-string scanning and domain-reputation blocklists
    if grep -nqE "(,\s*['\"]\.['\"]\s*\)){3,}" "$jsfile" 2>/dev/null; then
        warn "$rel" "IPv4-from-octets concat chain (likely hardcoded C2 endpoint)"
    fi

    # Dropper sequence: writeFileSync with w+ flag near a spawn/exec call
    if grep -nqE "writeFileSync\s*\([^)]+flag\s*:\s*['\"]w\+['\"]" "$jsfile" 2>/dev/null; then
        if grep -qlE "(spawn|spawnSync|exec|execSync)\s*\(" "$jsfile" 2>/dev/null; then
            warn "$rel" "writeFileSync(flag:'w+') + child_process call (dropper pattern)"
        fi
    fi

    # JSFuck-style obfuscation
    if grep -nqE '^\s*[!\[\]\(\)+]{50,}' "$jsfile" 2>/dev/null; then
        warn "$rel" "JSFuck-style obfuscation detected"
    fi
done

# ---------------------------------------------------------------------------
# 6. Suspicious .npmrc / .yarnrc files
# ---------------------------------------------------------------------------
printf "${BOLD}[6/8] Checking for suspicious npm/yarn config...${RESET}\n"

find "$SCAN_DIR" \( -name ".npmrc" -o -name ".yarnrc" -o -name ".yarnrc.yml" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | while read -r rcfile; do
    rel="${rcfile#${SCAN_DIR}/}"

    # Custom registry pointing to non-standard location
    if grep -qiE 'registry\s*=\s*https?://' "$rcfile" 2>/dev/null; then
        if grep -qiE 'registry\s*=\s*https?://' "$rcfile" | grep -qvE '(npmjs\.org|yarnpkg\.com|registry\.npmmirror\.com|artifactory|nexus|verdaccio)'; then
            warn "$rel" "Custom npm registry pointing to unusual URL"
        fi
    fi

    # Auth tokens in config
    if grep -qiE '(_authToken|_auth|//.*:_password)' "$rcfile" 2>/dev/null; then
        warn "$rel" "Contains authentication tokens (possible credential leak)"
    fi
done

# ---------------------------------------------------------------------------
# 7. Suspicious lockfile manipulation
# ---------------------------------------------------------------------------
printf "${BOLD}[7/8] Checking for lockfile integrity issues...${RESET}\n"

find "$SCAN_DIR" -name "package-lock.json" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | while read -r lockfile; do
    rel="${lockfile#${SCAN_DIR}/}"

    # Check for resolved URLs pointing to non-registry locations
    if grep -qE '"resolved"\s*:\s*"https?://' "$lockfile" 2>/dev/null; then
        suspicious_urls=$(grep -oE '"resolved"\s*:\s*"https?://[^"]*"' "$lockfile" 2>/dev/null | grep -vE '(registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com)' | head -5)
        if [ -n "$suspicious_urls" ]; then
            warn "$rel" "Resolved URLs pointing outside official registries"
            echo "$suspicious_urls" | head -3 | while read -r url; do
                note "    $url"
            done
        fi
    fi

    # Tarball URLs pointing to non-standard locations
    if grep -qE '"tarball"\s*:\s*"https?://' "$lockfile" 2>/dev/null; then
        suspicious_tarballs=$(grep -oE '"tarball"\s*:\s*"https?://[^"]*"' "$lockfile" 2>/dev/null | grep -vE '(registry\.npmjs\.org|registry\.yarnpkg\.com)' | head -5)
        if [ -n "$suspicious_tarballs" ]; then
            warn "$rel" "Tarball URLs pointing outside official registries"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 8. Binding.gyp / native addons (can hide native malware)
# ---------------------------------------------------------------------------
printf "${BOLD}[8/8] Checking for suspicious native addons...${RESET}\n"

find "$SCAN_DIR" -name "binding.gyp" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | while read -r gyp; do
    rel="${gyp#${SCAN_DIR}/}"
    info "$rel" "Native addon build file (review for suspicious native code)"
done

# Check for .node binary files outside node_modules
find "$SCAN_DIR" -name "*.node" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | while read -r nodefile; do
    rel="${nodefile#${SCAN_DIR}/}"
    warn "$rel" "Native .node binary outside node_modules"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
FINDINGS=$(cat "$FINDINGS_FILE")
printf "\n${BOLD}========================================${RESET}\n"
if [ "$FINDINGS" -gt 0 ]; then
    printf "  ${RED}${BOLD}Node.js scan: %d finding(s)${RESET}\n" "$FINDINGS"
else
    printf "  ${GREEN}${BOLD}Node.js scan: Clean${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n\n"

[ "$FINDINGS" -gt 0 ] && exit 1 || exit 0
