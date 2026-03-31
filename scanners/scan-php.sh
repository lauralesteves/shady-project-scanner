#!/bin/bash
#
# PHP Malware / Webshell Scanner
#
# Detects suspicious patterns in PHP codebases:
#   - Webshell signatures and backdoor patterns
#   - Obfuscation chains (eval + base64_decode + gzinflate + str_rot13)
#   - Dangerous function usage (system, exec, passthru, shell_exec, popen)
#   - File upload/write abuse
#   - Hidden PHP files and suspicious file names
#   - Encoded payloads and variable function calls
#   - Composer dependency issues
#
# Usage:
#   ./scan-php.sh /path/to/project
#   ./scan-php.sh                    # scans current directory

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
    printf "\n${BOLD}=== PHP Malware / Webshell Scanner ===${RESET}\n"
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
# 1. Classic webshell / backdoor signatures
# ---------------------------------------------------------------------------
printf "${BOLD}[1/9] Scanning for known webshell signatures...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.php" -not -path "*/vendor/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" 2>/dev/null | while read -r phpfile; do
    rel="${phpfile#${SCAN_DIR}/}"

    # Known webshell strings
    if grep -qlE '(c99shell|r57shell|b374k|wso\s+shell|FilesMan|Ani-Shell|ALFA\s*Shell|Weevely|p0wny|phpspy|Locus7Shell|RedGlobal)' "$phpfile" 2>/dev/null; then
        warn "$rel" "Known webshell signature detected"
    fi

    # $_GET/$_POST/$_REQUEST/$_COOKIE passed into dangerous functions
    if grep -nqE '(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)' "$phpfile" 2>/dev/null; then
        warn "$rel" "User input directly passed to dangerous function"
    fi

    # Variable function calls with user input: $func = $_GET['x']; $func();
    if grep -nqE '\$[a-zA-Z_]+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)' "$phpfile" 2>/dev/null; then
        if grep -nqE '\$[a-zA-Z_]+\s*\(' "$phpfile" 2>/dev/null; then
            info "$rel" "Variable assigned from user input + variable function call (possible backdoor)"
        fi
    fi

    # Callback functions with user input (call_user_func, array_map, usort, etc.)
    if grep -nqE '(call_user_func|call_user_func_array|array_map|array_filter|usort|uasort|uksort|array_walk)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)' "$phpfile" 2>/dev/null; then
        warn "$rel" "Callback function with user input (code execution via callback)"
    fi

    # include/require with user input (LFI/RFI)
    if grep -nqE '(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)' "$phpfile" 2>/dev/null; then
        warn "$rel" "include/require with user input (LFI/RFI vulnerability)"
    fi

    # Error-suppressed execution (@eval, @system, @exec)
    if grep -nqE '@\s*(eval|system|exec|passthru|shell_exec)\s*\(' "$phpfile" 2>/dev/null; then
        warn "$rel" "Error-suppressed dangerous function call (@eval/@system)"
    fi

    # CRITICAL: fetch-then-eval -- eval(file_get_contents(url)) or eval(curl response)
    if grep -qlE '(file_get_contents|curl_exec|fopen)\s*\(' "$phpfile" 2>/dev/null; then
        if grep -qlE '(eval|assert|system|exec|passthru)\s*\(' "$phpfile" 2>/dev/null; then
            if grep -qvlE '\$_(GET|POST|REQUEST)' "$phpfile" 2>/dev/null; then
                warn "$rel" "CRITICAL: Remote content fetch + code execution (RCE backdoor pattern)"
            fi
        fi
    fi

    # file_get_contents('php://input') - raw POST body (often used in webshells)
    if grep -nqE "file_get_contents\s*\(\s*['\"]php://input['\"]" "$phpfile" 2>/dev/null; then
        if grep -qlE '(eval|exec|system|passthru|assert)' "$phpfile" 2>/dev/null; then
            warn "$rel" "Reads php://input + code execution (webshell pattern)"
        fi
    fi

    # fsockopen for exfiltration/reverse shell
    if grep -nqE 'fsockopen\s*\(' "$phpfile" 2>/dev/null; then
        if grep -qlE '(fwrite|fputs|exec|system|shell_exec|\$_(GET|POST))' "$phpfile" 2>/dev/null; then
            warn "$rel" "fsockopen with write/exec (possible reverse shell or exfiltration)"
        fi
    fi

    # Webshell password pattern
    if grep -nqE '\$(auth_pass|password|passwd|pass)\s*=\s*['\''"][a-f0-9]{32}['\''"]' "$phpfile" 2>/dev/null; then
        warn "$rel" "Hardcoded MD5 password hash (common webshell authentication)"
    fi

    # @ini_set + set_time_limit combo (webshell initialization)
    if grep -qlE '@ini_set\s*\(' "$phpfile" 2>/dev/null; then
        if grep -qlE '@set_time_limit\s*\(\s*0\s*\)' "$phpfile" 2>/dev/null; then
            info "$rel" "@ini_set + @set_time_limit(0) combo (webshell init pattern)"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 2. Obfuscation chains: eval(base64_decode()), eval(gzinflate()), etc.
# ---------------------------------------------------------------------------
printf "${BOLD}[2/9] Scanning for obfuscation chains...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.php" -not -path "*/vendor/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" 2>/dev/null | while read -r phpfile; do
    rel="${phpfile#${SCAN_DIR}/}"

    # eval + decode/decompress chains
    if grep -nqE 'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|urldecode|hex2bin)\s*\(' "$phpfile" 2>/dev/null; then
        warn "$rel" "eval() with decode/decompress chain (classic obfuscation)"
    fi

    # Nested decode chains without eval
    if grep -nqE '(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(' "$phpfile" 2>/dev/null; then
        warn "$rel" "Nested decode/decompress chain"
    fi

    # assert() used as eval alternative
    if grep -nqE 'assert\s*\(\s*(base64_decode|gzinflate|\$_)' "$phpfile" 2>/dev/null; then
        warn "$rel" "assert() used as eval alternative with encoded/user input"
    fi

    # preg_replace with /e modifier (code execution - deprecated but still works in older PHP)
    if grep -nqE "preg_replace\s*\(\s*['\"][^'\"]*\/[a-z]*e[a-z]*['\"]" "$phpfile" 2>/dev/null; then
        warn "$rel" "preg_replace() with /e modifier (code execution)"
    fi

    # create_function (deprecated, often used in malware)
    if grep -nqE 'create_function\s*\(' "$phpfile" 2>/dev/null; then
        info "$rel" "create_function() usage (deprecated, used in obfuscation)"
    fi
done

# ---------------------------------------------------------------------------
# 3. Dangerous function usage
# ---------------------------------------------------------------------------
printf "${BOLD}[3/9] Scanning for dangerous function usage...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.php" -not -path "*/vendor/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" 2>/dev/null | while read -r phpfile; do
    rel="${phpfile#${SCAN_DIR}/}"

    # system / exec / passthru / shell_exec with concatenation or variables
    if grep -nqE '(system|passthru|shell_exec)\s*\(\s*\$' "$phpfile" 2>/dev/null; then
        warn "$rel" "Shell execution with variable argument"
    fi

    # backtick operator with variable
    if grep -nqE '`.*\$[a-zA-Z_].*`' "$phpfile" 2>/dev/null; then
        info "$rel" "Backtick execution with variable interpolation"
    fi

    # proc_open
    if grep -nqE 'proc_open\s*\(' "$phpfile" 2>/dev/null; then
        if grep -qlE '\$_(GET|POST|REQUEST|COOKIE)' "$phpfile" 2>/dev/null; then
            warn "$rel" "proc_open() in file that reads user input"
        fi
    fi

    # dl() - dynamic extension loading
    if grep -nqE '\bdl\s*\(\s*['\''"]' "$phpfile" 2>/dev/null; then
        warn "$rel" "dl() - dynamic PHP extension loading"
    fi
done

# ---------------------------------------------------------------------------
# 4. File write / upload abuse
# ---------------------------------------------------------------------------
printf "${BOLD}[4/9] Scanning for file write / upload abuse...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.php" -not -path "*/vendor/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" 2>/dev/null | while read -r phpfile; do
    rel="${phpfile#${SCAN_DIR}/}"

    # file_put_contents with user input
    if grep -nqE 'file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)' "$phpfile" 2>/dev/null; then
        warn "$rel" "file_put_contents() with user-controlled path"
    fi

    # fwrite with decoded/user content
    if grep -nqE 'fwrite\s*\(' "$phpfile" 2>/dev/null; then
        if grep -qlE '(base64_decode|\$_(GET|POST|REQUEST))' "$phpfile" 2>/dev/null; then
            info "$rel" "fwrite() in file that decodes/reads user input"
        fi
    fi

    # move_uploaded_file without proper validation context
    if grep -nqE 'move_uploaded_file\s*\(' "$phpfile" 2>/dev/null; then
        if ! grep -qlE '(pathinfo|getimagesize|mime_content_type|finfo_|FILEINFO_MIME)' "$phpfile" 2>/dev/null; then
            info "$rel" "move_uploaded_file() without apparent MIME/extension validation"
        fi
    fi
done

# ---------------------------------------------------------------------------
# 5. Hidden PHP in non-PHP files
# ---------------------------------------------------------------------------
printf "${BOLD}[5/9] Scanning for hidden PHP in non-PHP files...${RESET}\n"

find "$SCAN_DIR" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" -o -name "*.ico" \
    -o -name "*.css" -o -name "*.txt" -o -name "*.log" -o -name "*.html" \) \
    -not -path "*/vendor/*" -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"

    if grep -qlE '<\?php' "$file" 2>/dev/null; then
        warn "$rel" "PHP code found in non-PHP file (possible hidden webshell)"
    fi
done

# Check for double extensions
find "$SCAN_DIR" -type f \( -name "*.php.jpg" -o -name "*.php.png" -o -name "*.php.gif" \
    -o -name "*.php.ico" -o -name "*.php.txt" -o -name "*.phtml" -o -name "*.php5" \
    -o -name "*.php7" -o -name "*.pht" -o -name "*.phps" -o -name "*.phar" \) \
    -not -path "*/vendor/*" -not -path "*/.git/*" 2>/dev/null | while read -r file; do
    rel="${file#${SCAN_DIR}/}"
    warn "$rel" "Suspicious file extension (possible webshell disguise)"
done

# ---------------------------------------------------------------------------
# 6. Encoded payloads & variable function calls
# ---------------------------------------------------------------------------
printf "${BOLD}[6/9] Scanning for encoded payloads...${RESET}\n"

find "$SCAN_DIR" -type f -name "*.php" -not -path "*/vendor/*" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" 2>/dev/null | while read -r phpfile; do
    rel="${phpfile#${SCAN_DIR}/}"

    # Very long base64 strings (likely encoded payload)
    if grep -nqE '[A-Za-z0-9+/]{200,}={0,2}' "$phpfile" 2>/dev/null; then
        info "$rel" "Contains very long Base64-like string (>200 chars)"
    fi

    # Long hex string
    if grep -nqE '\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){30,}' "$phpfile" 2>/dev/null; then
        warn "$rel" "Contains long hex-encoded string"
    fi

    # chr() obfuscation: chr(xx).chr(xx).chr(xx)
    if grep -nqE '(chr\s*\(\s*[0-9]+\s*\)\s*\.?\s*){10,}' "$phpfile" 2>/dev/null; then
        warn "$rel" "chr() string obfuscation (10+ char codes chained)"
    fi

    # Variable variable / dynamic function: $$var or ${'func'}()
    if grep -nqE '\$\{[^}]*\$' "$phpfile" 2>/dev/null; then
        info "$rel" "Variable variables / dynamic access pattern"
    fi

    # Array-based obfuscation: $a='base'.'64_'.'deco'.'de';
    if grep -nqE "\\\$[a-zA-Z_]+\s*=\s*['\"][a-z]{2,5}['\"]\.['\"]\s*[a-z_]{2,}['\"]" "$phpfile" 2>/dev/null; then
        info "$rel" "String concatenation building function name (possible obfuscation)"
    fi
done

# ---------------------------------------------------------------------------
# 7. Suspicious .htaccess
# ---------------------------------------------------------------------------
printf "${BOLD}[7/9] Checking .htaccess files...${RESET}\n"

find "$SCAN_DIR" -name ".htaccess" -not -path "*/.git/*" 2>/dev/null | while read -r htaccess; do
    rel="${htaccess#${SCAN_DIR}/}"

    # auto_prepend_file / auto_append_file (inject PHP into every request)
    if grep -qiE '(auto_prepend_file|auto_append_file)' "$htaccess" 2>/dev/null; then
        warn "$rel" "auto_prepend/append_file directive (injects PHP into all requests)"
    fi

    # AddHandler/AddType making non-PHP files executable
    if grep -qiE '(AddHandler|AddType).*php' "$htaccess" 2>/dev/null; then
        if grep -qiE '\.(jpg|png|gif|ico|txt|html|css)' "$htaccess" 2>/dev/null; then
            warn "$rel" "AddHandler/AddType making non-PHP extensions executable as PHP"
        fi
    fi

    # SetHandler for arbitrary extensions
    if grep -qiE 'SetHandler.*php' "$htaccess" 2>/dev/null; then
        info "$rel" "SetHandler PHP directive (review context)"
    fi
done

# ---------------------------------------------------------------------------
# 8. Suspicious PHP config/ini
# ---------------------------------------------------------------------------
printf "${BOLD}[8/9] Checking php.ini / .user.ini files...${RESET}\n"

find "$SCAN_DIR" \( -name "php.ini" -o -name ".user.ini" \) -not -path "*/.git/*" 2>/dev/null | while read -r ini; do
    rel="${ini#${SCAN_DIR}/}"

    if grep -qiE '(auto_prepend_file|auto_append_file)' "$ini" 2>/dev/null; then
        warn "$rel" "auto_prepend/append_file in PHP config"
    fi

    if grep -qiE 'disable_functions\s*=' "$ini" 2>/dev/null; then
        info "$rel" "disable_functions directive (may be weakening security)"
    fi
done

# ---------------------------------------------------------------------------
# 9. Composer dependency checks
# ---------------------------------------------------------------------------
printf "${BOLD}[9/9] Checking Composer dependencies...${RESET}\n"

find "$SCAN_DIR" -name "composer.json" -not -path "*/vendor/*" -not -path "*/.git/*" 2>/dev/null | while read -r composer; do
    rel="${composer#${SCAN_DIR}/}"

    # Scripts that run shell commands
    for hook in post-install-cmd post-update-cmd pre-install-cmd pre-update-cmd post-autoload-dump; do
        script_val=$(grep -A2 "\"$hook\"" "$composer" 2>/dev/null | grep -oE '"[^"]*"' | tail -1)
        if [ -n "$script_val" ]; then
            if echo "$script_val" | grep -qiE '(curl|wget|bash|sh -c|eval|exec|base64|php -r)'; then
                warn "$rel" "Suspicious '$hook' Composer script: $script_val"
            fi
        fi
    done

    # VCS repositories pointing to unusual URLs
    if grep -qE '"type"\s*:\s*"vcs"' "$composer" 2>/dev/null; then
        info "$rel" "Has VCS repository sources (verify they're legitimate)"
    fi

    # Packages from custom repositories
    if grep -qE '"type"\s*:\s*"package"' "$composer" 2>/dev/null; then
        info "$rel" "Has inline package definitions (can bypass Packagist)"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
FINDINGS=$(cat "$FINDINGS_FILE")
printf "\n${BOLD}========================================${RESET}\n"
if [ "$FINDINGS" -gt 0 ]; then
    printf "  ${RED}${BOLD}PHP scan: %d finding(s)${RESET}\n" "$FINDINGS"
else
    printf "  ${GREEN}${BOLD}PHP scan: Clean${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n\n"

[ "$FINDINGS" -gt 0 ] && exit 1 || exit 0
