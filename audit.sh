#!/bin/bash

DEFAULT_LOG_FILE="access.log"
DEFAULT_REPORT_FILE="report.txt"
DEFAULT_SUMMARY_FILE="summary.txt"
DEFAULT_BLACKLIST_FILE="blacklist.txt"
DEFAULT_TOP_N_DATE=10
DEFAULT_TOP_N_IP=10
DEFAULT_TOP_N_URL=10
DEFAULT_TOP_N_REFERER=10

LOG_FILE="$DEFAULT_LOG_FILE"
REPORT_FILE="$DEFAULT_REPORT_FILE"
SUMMARY_FILE="$DEFAULT_SUMMARY_FILE"
BLACKLIST_FILE="$DEFAULT_BLACKLIST_FILE"
TOP_N_DATE="$DEFAULT_TOP_N_DATE"
TOP_N_IP="$DEFAULT_TOP_N_IP"
TOP_N_URL="$DEFAULT_TOP_N_URL"
TOP_N_REFERER="$DEFAULT_TOP_N_REFERER"

usage() {
    echo "Usage: $0 [OPTIONS...]"
    echo "Options:"
    echo "  --file LOG_FILE, -f LOG_FILE         Path to the log file to analyze (default: $DEFAULT_LOG_FILE)"
    echo "  --report-file REPORT_FILE            Detailed report file name (default: $DEFAULT_REPORT_FILE)"
    echo "  --summary-file SUMMARY_FILE          Summary report file name (default: $DEFAULT_SUMMARY_FILE)"
    echo "  --blacklist-file BLACKLIST_FILE      IP blacklist file name (default: $DEFAULT_BLACKLIST_FILE)"
    echo "  --top-date TOP_N_DATE                Number of daily detection entries to display (default: $DEFAULT_TOP_N_DATE)"
    echo "  --top-ip TOP_N_IP                  Number of IP address detection entries to display (default: $DEFAULT_TOP_N_IP)"
    echo "  --top-url TOP_N_URL                Number of URL detection entries to display (default: $DEFAULT_TOP_N_URL)"
    echo "  --top-referer TOP_N_REFERER        Number of Referer detection entries to display (default: $DEFAULT_TOP_N_REFERER)"
    echo "  --help, -h                           Display this help message."
    exit 1
}

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file|-f)
            if [[ -n "$2" && "$2" != -* ]]; then LOG_FILE="$2"; shift 2; else echo "Error: --file or -f option requires a file path argument." >&2; usage; fi ;;
        --report-file)
            if [[ -n "$2" && "$2" != -* ]]; then REPORT_FILE="$2"; shift 2; else echo "Error: --report-file option requires a file name argument." >&2; usage; fi ;;
        --summary-file)
            if [[ -n "$2" && "$2" != -* ]]; then SUMMARY_FILE="$2"; shift 2; else echo "Error: --summary-file option requires a file name argument." >&2; usage; fi ;;
        --blacklist-file)
            if [[ -n "$2" && "$2" != -* ]]; then BLACKLIST_FILE="$2"; shift 2; else echo "Error: --blacklist-file option requires a file name argument." >&2; usage; fi ;;
        --top-date)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_DATE="$2"; shift 2; else echo "Error: --top-date option requires a numeric argument." >&2; usage; fi ;;
        --top-ip)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_IP="$2"; shift 2; else echo "Error: --top-ip option requires a numeric argument." >&2; usage; fi ;;
        --top-url)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_URL="$2"; shift 2; else echo "Error: --top-url option requires a numeric argument." >&2; usage; fi ;;
        --top-referer)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_REFERER="$2"; shift 2; else echo "Error: --top-referer option requires a numeric argument." >&2; usage; fi ;;
        --help|-h)
            usage ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ${#ARGS[@]} -ne 0 ]; then
    echo "Unknown argument or incorrect option usage: ${ARGS[*]}"
    usage
fi


PATTERNS=(
    "SQL_INJECTION:.*' OR '1'='1"
    "SQL_INJECTION:.*(\b(UNION|SELECT)\b.{1,100}?\b(FROM|SLEEP|BENCHMARK|PG_SLEEP|WAITFOR)\b)"
    "SQL_INJECTION:.*(information_schema|pg_catalog|mysql\.user|sys\.tables|sysobjects)"
    "SQL_INJECTION:.*(SLEEP\(|BENCHMARK\(|pg_sleep\(|WAITFOR DELAY)"
    "SQL_INJECTION:.*(--|#|/\*|\*/|;).*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\b"
    "SQL_INJECTION:.*(xp_cmdshell|sp_configure|OPENROWSET|OPENDATASOURCE)"
    "SQL_INJECTION_NOSQL:.*([$]ne|[$]gt|[$]lt|[$]regex|[$]where)"
    "XSS:.*<script\b[^>]*>.*?</script\b[^>]*>"
    "XSS:.*<img\b[^>]*\b(src|onerror|onload)\s*=\s*[^>]*javascript:[^>]+>"
    "XSS:.*<[a-zA-Z]+\b[^>]*\b(on\w+)\s*=\s*[^>]*[^'\"\s>]+"
    "XSS:.*<iframe\b[^>]*\b(src|srcdoc)\s*=\s*[^>]*javascript:[^>]+>"
    "XSS:.*(alert\(|confirm\(|prompt\(|document\.cookie|document\.write\(|window\.location)"
    "XSS:.*(expression\(|eval\(|setTimeout\(|setInterval\()"
    "XSS_ENCODED:.*(%3Cscript|%3Cimg|%3Csvg|%253Cscript|<script|<script)"
    "XSS_DOM:.*(#|location\.hash\s*=).*(<script>|javascript:)"
    "PATH_TRAVERSAL_LFI:.*(\.\.[/\\]|\.%2e%2e[%2f%5c]|\.%252e%252e[%252f%255c])"
    "PATH_TRAVERSAL_LFI:.*(etc/passwd|boot\.ini|win\.ini|system32/drivers/etc/hosts)"
    "PATH_TRAVERSAL_LFI:.*(WEB-INF/web\.xml|META-INF/MANIFEST\.MF)"
    "PATH_TRAVERSAL_LFI:.*(\%00|\0)"
    "RFI:.*(include|require|include_once|require_once)\s*[_A-Z0-9\[\]\"']*\s*=\s*(ht|f)tps?://[^&?\s]+"
    "RFI:.*(include|require|include_once|require_once)\s*[_A-Z0-9\[\]\"']*\s*=\s*(php|data|expect)://[^&?\s]+"
    "CMD_INJECTION:.*(;|%3B|\n|%0A|\r|%0D|[\`]|[$]\(|\&\&|\|\|)"
    "CMD_INJECTION:.*(cmd=|exec=|command=|system=|passthru=|shell_exec=|popen=|pcntl_exec|eval\(|assert\()"
    "CMD_INJECTION:.*(cat\s+/etc/passwd|whoami|uname\s+-a|id|ls\s+-la|netstat|ifconfig|ipconfig|ping\s+-c\s+\d)"
    "CMD_INJECTION:.*(nc\s+-l\s+-p|ncat|powershell|bash\s+-c|perl\s+-e|python\s+-c|ruby\s+-e)"
    "SENSITIVE_FILE_ACCESS:.*wp-config\.php"
    "SENSITIVE_FILE_ACCESS:.*(\.env|\.htpasswd|\.htaccess|\.git/config|config\.php|settings\.php|localsettings\.php|credentials|database\.yml|secrets\.yml)"
    "SENSITIVE_FILE_ACCESS:.*(\.pem|\.key|\.p12|\.crt|\.csr|\.jks)"
    "SENSITIVE_FILE_ACCESS:.*(phpinfo\.php|test\.php|info\.php|status\?full|server-status|manager/html)"
    "SENSITIVE_FILE_ACCESS:.*(web\.config|appsettings\.json)"
    "SENSITIVE_FILE_BACKUP:.*(\.(bak|backup|old|orig|sql|config|conf|zip|tar\.gz|tgz|swp|~|save|copy|dev|prod|staging|bkp|bk))([\?&]|$)"
    "DIRECTORY_LISTING:.*(Index of /|parent directory)"
    "SSRF:.*(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)"
    "SSRF:.*(169\.254\.169\.254|metadata\.google\.internal|instance-data/latest/)"
    "SSRF:.*(url=|uri=|target=|dest=|file=|path=|host=|data=|feed=|image_url=).*(file:///|dict://|sftp://|ldap://|gopher://|jar://)"
    "SSRF:.*(url=|uri=|target=|dest=).*(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
    "XXE_INJECTION:.*(<!ENTITY\s+[^>]*\s+(SYSTEM|PUBLIC)\s+[\"'][^\"']*[\"']>)"
    "XXE_INJECTION:.*(<!ENTITY\s+%\s+[^>]*\s+SYSTEM)"
    "XXE_INJECTION:.*(xxe_payload|ENTITY\s+xxe)"
    "LOG4J_JNDI_LOOKUP:.*\\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds):"
    "SPRING4SHELL_RCE:.*class\.module\.classLoader"
    "DESERIALIZATION_PHP_OBJECT:.*O:[0-9]+:\""
    "DESERIALIZATION_JAVA_OBJECT:.*( rO0ABXNy|aced0005|ysoserial| Javassist\.CtClass|weblogic\.jms\.common\.StreamMessageImpl)"
    "FILE_UPLOAD_VULN:.*POST .*/(upload|files|uploads|tmp|temp|images)/.*\.(php[3457s]?|phtml|phar|aspx?|jspx?|sh|exe|dll|cgi|pl|py|rb|war|jar)(\.[^./]+)*"
    "FILE_UPLOAD_VULN:.*Content-Disposition:.*\bfilename\s*=\s*[\"'].*\.(php|jsp|asp|sh)[\"']"
    "AUTH_BYPASS:.*(admin_bypass|is_admin=(true|1)|role=(admin|root)|user_level=0|debug_mode=1)"
    "AUTH_BYPASS:.*(X-Forwarded-For:\s*127\.0\.0\.1|X-Original-URL:|X-Rewrite-URL:|Authorization:\s*Basic\s*YWRtaW46YWRtaW4=)"
    "VULN_COMPONENT_ACCESS:.*(/phpmyadmin/|/pma/|/wp-admin/|/admin/|/manager/html|/jmx-console/|/web-console/|struts/dojo/)"
    "OPEN_REDIRECT:.*(redirect=|url=|next=|location=|goto=|target=|return=|return_to=|checkout_url=)(https?%3A%2F%2F|%2F%2F|\\\\|%5C%5C)[^/\\s?&][^\"'<>]+"
    "INFO_DISCLOSURE_DEBUG:.*(debug=(true|1)|TRACE\s+/|TRACK\s+/|X-Debug-Token:|phpinfo\(\))"
    "VERBOSE_ERROR_MESSAGES:.*(Stack Trace|Traceback \(most recent call last\)|PHP Fatal error:|Syntax error near|ORA-\d{5}:|java\.lang\.|Warning: Division by zero|Undefined index:)"
    "LOG_INJECTION:.*(%0d|%0a|\\r|\\n|\r\n)"
    "SSTI:.*(\{\{.*\}\}|\{\%.*\%\}|<%=.*%>|[$]\{[^\}]+\}|#\{[^\}]+\})"
    "SSTI:.*(config.SECRET_KEY|settings.SECRET_KEY|getattribute|lipsum|self.__init__|class.__bases__|mro\(\))"
    "PROTOTYPE_POLLUTION:.*(__proto__|constructor\.prototype|Object\.prototype).*\s*=\s*\{"
    "HTTP_DESYNC:.*(Content-Length:\s*\d+\r\nTransfer-Encoding:\s*chunked|Transfer-Encoding:\s*chunked\r\nContent-Length:\s*\d+)"
)

IP_REGEX='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
DATE_REGEX='\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4})'

url_decode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

get_threat_description() {
    local type_code="$1"
    local description="" 
    case "$type_code" in
        "SQL_INJECTION") description="SQL Injection: Attempt to manipulate database queries. Recommend input validation and use of Prepared Statements." ;;
        "SQL_INJECTION_NOSQL") description="NoSQL Injection: Attempt to manipulate NoSQL database queries (e.g., MongoDB). Recommend input validation and careful use of operators." ;;
        "XSS") description="Cross-Site Scripting (XSS): Attempt to inject malicious scripts. Recommend output encoding and Content Security Policy (CSP)." ;;
        "XSS_ENCODED") description="Encoded XSS Attempt: Attempt to inject encoded malicious scripts. Requires decoding then validation, and output encoding." ;;
        "XSS_DOM") description="DOM-based XSS Attempt: Attempt to manipulate DOM via client-side scripts. Use safe DOM APIs and validate input." ;;
        "PATH_TRAVERSAL_LFI") description="Path Traversal/LFI: Attempt to access unauthorized files. Recommend validating user-supplied paths and minimizing access rights." ;;
        "RFI") description="Remote File Inclusion (RFI): Attempt to execute external malicious files. Use whitelist-based validation for file inclusion." ;;
        "CMD_INJECTION") description="Command Injection: Attempt to execute server commands. Avoid direct use of user input in system calls; use APIs instead." ;;
        "SENSITIVE_FILE_ACCESS") description="Sensitive File Access: Attempt to access sensitive files (config, keys, etc.). Strengthen access controls and prevent exposure." ;;
        "SENSITIVE_FILE_BACKUP") description="Sensitive Backup File Access: Attempt to access backup/temporary files. Store backups outside web root and control access." ;;
        "DIRECTORY_LISTING") description="Directory Listing: Exposure of directory contents. Recommend disabling in web server configuration." ;;
        "SSRF") description="Server-Side Request Forgery (SSRF): Attempt to make the server access internal/external resources. Validate URLs and restrict internal IP access." ;;
        "XXE_INJECTION") description="XML External Entity (XXE) Injection: Exploitation of XML external entity processing. Disable external entity features in XML parsers." ;;
        "LOG4J_JNDI_LOOKUP") description="Log4Shell (CVE-2021-44228): Exploitation of Log4j JNDI injection. Update Log4j or remove JndiLookup class." ;;
        "SPRING4SHELL_RCE") description="Spring4Shell (CVE-2022-22965): Exploitation of Spring Framework RCE. Update Spring Framework/JDK." ;;
        "DESERIALIZATION_PHP_OBJECT") description="Insecure Deserialization (PHP): Attempt of insecure PHP object deserialization. Avoid deserializing untrusted data." ;;
        "DESERIALIZATION_JAVA_OBJECT") description="Insecure Deserialization (Java): Attempt of insecure Java object deserialization. Avoid untrusted data and update libraries." ;;
        "FILE_UPLOAD_VULN") description="Malicious File Upload: Attempt to upload malicious files (e.g., web shells). Validate file extensions/types, store outside web root, remove execute permissions." ;;
        "AUTH_BYPASS") description="Authentication Bypass Attempt: Attempt to bypass authentication. Implement strong authentication and verify access controls." ;;
        "VULN_COMPONENT_ACCESS") description="Sensitive Component Access: Attempt to access admin tools or vulnerable components. Remove unnecessary components and strengthen access controls." ;;
        "OPEN_REDIRECT") description="Open Redirect: Attempt to redirect to untrusted external sites. Validate redirection URLs against a whitelist." ;;
        "INFO_DISCLOSURE_DEBUG") description="Debug Mode Enabled: Information disclosure due to active debug mode. Disable debug mode in production." ;;
        "VERBOSE_ERROR_MESSAGES") description="Verbose Error Messages: Internal information disclosure via detailed error messages. Use generic error messages." ;;
        "LOG_INJECTION") description="Log Injection / CRLF Injection: Attempt to manipulate log files or split HTTP responses. Filter input and remove CRLF characters." ;;
        "SSTI") description="Server-Side Template Injection (SSTI): Attempt to execute code via server-side templates. Avoid user input in templates or use secure sandboxing." ;;
        "PROTOTYPE_POLLUTION") description="Prototype Pollution: Attempt to manipulate JavaScript prototypes for attribute modification or code execution. Be cautious with object merging and update libraries." ;;
        "HTTP_DESYNC") description="HTTP Request Smuggling/Desync: Attack exploiting inconsistencies in HTTP request parsing. Review and update proxy and web server configurations." ;;
        *) description="$type_code: (No description available)" ;;
    esac
    echo "$description"
}

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file '$LOG_FILE' not found."
    usage
fi
if ! [[ "$TOP_N_DATE" =~ ^[0-9]+$ ]]; then
    echo "Error: Top N value for daily (--top-date) must be a number. Input: $TOP_N_DATE"
    usage
fi
if ! [[ "$TOP_N_IP" =~ ^[0-9]+$ ]]; then
    echo "Error: Top N value for IP (--top-ip) must be a number. Input: $TOP_N_IP"
    usage
fi
if ! [[ "$TOP_N_URL" =~ ^[0-9]+$ ]]; then
    echo "Error: Top N value for URL (--top-url) must be a number. Input: $TOP_N_URL"
    usage
fi
if ! [[ "$TOP_N_REFERER" =~ ^[0-9]+$ ]]; then
    echo "Error: Top N value for Referer (--top-referer) must be a number. Input: $TOP_N_REFERER"
    usage
fi

if [ -f "$REPORT_FILE" ]; then rm "$REPORT_FILE"; fi
if [ -f "$SUMMARY_FILE" ]; then rm "$SUMMARY_FILE"; fi
if [ -f "$BLACKLIST_FILE" ]; then rm "$BLACKLIST_FILE"; fi


echo "Security Audit Report (Detailed Logs) - $(date)" > "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Log File Analyzed: $LOG_FILE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Security Audit Summary - $(date)" > "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Log File Analyzed: $LOG_FILE" >> "$SUMMARY_FILE"
echo "Number of Daily Detections to Display: $TOP_N_DATE" >> "$SUMMARY_FILE"
echo "Number of IP Address Detections to Display: $TOP_N_IP" >> "$SUMMARY_FILE"
echo "Number of URL Detections to Display: $TOP_N_URL" >> "$SUMMARY_FILE"
echo "Number of Referer Detections to Display: $TOP_N_REFERER" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

found_any_threat=false
total_log_lines_matched_overall=0
threat_type_summary_data=""
ip_summary_data=""
daily_summary_data=""
referer_summary_data_raw=""
top_ips_for_summary=""
top_urls_for_summary_raw=""
top_dates_for_summary=""
top_referers_for_summary_raw=""


unique_threat_types_in_order=()
temp_seen_types_str=""
for pattern_item in "${PATTERNS[@]}"; do
    IFS=":" read -r threat_type _ <<< "$pattern_item"
    if [ -z "$threat_type" ]; then continue; fi
    if ! echo "$temp_seen_types_str" | grep -q -w "$threat_type"; then
        unique_threat_types_in_order+=("$threat_type")
        temp_seen_types_str="$temp_seen_types_str$threat_type "
    fi
done
unset temp_seen_types_str

TEMP_MATCHED_LOGS=$(mktemp)

for current_threat_type in "${unique_threat_types_in_order[@]}"; do
    type_specific_total_count=0
    for pattern_item in "${PATTERNS[@]}"; do
        IFS=":" read -r threat_type_from_pattern pattern <<< "$pattern_item"
        if [[ "$threat_type_from_pattern" == "$current_threat_type" ]]; then
            current_pattern_detection_count=$(grep -E -i -c "$pattern" "$LOG_FILE")
            type_specific_total_count=$((type_specific_total_count + current_pattern_detection_count))
        fi
    done
    if [ "$type_specific_total_count" -gt 0 ]; then
        threat_type_summary_data="${threat_type_summary_data}${current_threat_type}=${type_specific_total_count};"
        found_any_threat=true
    fi
done

if [ "$found_any_threat" = true ]; then
    for pattern_item in "${PATTERNS[@]}"; do
        IFS=":" read -r _ pattern <<< "$pattern_item"
         if [ -z "$pattern" ]; then continue; fi
        grep -E -i "$pattern" "$LOG_FILE" >> "$TEMP_MATCHED_LOGS"
    done
fi

for pattern_item in "${PATTERNS[@]}"; do
    IFS=":" read -r _ pattern <<< "$pattern_item"
    if [ -z "$pattern" ]; then continue; fi
    count_for_this_pattern=$(grep -E -i -c "$pattern" "$LOG_FILE")
    total_log_lines_matched_overall=$((total_log_lines_matched_overall + count_for_this_pattern))
done

if [ -f "$TEMP_MATCHED_LOGS" ] && [ -s "$TEMP_MATCHED_LOGS" ]; then
    extracted_ips_raw_for_summary=$(grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_ips_raw_for_summary; do ip_summary_data="${ip_summary_data}${item};"; done
    if [ -n "$ip_summary_data" ]; then
        top_ips_for_summary=$(echo "$ip_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n "$TOP_N_IP" | awk '{print $2 "=" $1}')
    fi

    extracted_dates_raw_for_summary=$(grep -o -E "$DATE_REGEX" "$TEMP_MATCHED_LOGS" | sed -E 's/^\[//' | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_dates_raw_for_summary; do daily_summary_data="${daily_summary_data}${item};"; done
    if [ -n "$daily_summary_data" ]; then
         top_dates_for_summary=$(echo "$daily_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n "$TOP_N_DATE" | awk '{print $2 "=" $1}')
    fi

    extracted_urls_raw_counts=$(awk -F'"' '{
        if (NF >= 2 && $2 ~ /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) /) {
            split($2, request_parts, " ");
            if (request_parts[2] != "") {
                print request_parts[2];
            }
        }
    }' "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{$1=$1; printf "%s\t%s\n", $2, $1}')

    current_url_summary_for_sorting=""
    while IFS=$'\t' read -r url_path count; do
        if [ -n "$url_path" ] && [ -n "$count" ]; then
            encoded_url_path=$(echo -n "$url_path" | base64)
            current_url_summary_for_sorting="${current_url_summary_for_sorting}${encoded_url_path}\t${count}\n"
        fi
    done <<< "$extracted_urls_raw_counts"
    
    if [ -n "$current_url_summary_for_sorting" ]; then
        top_urls_for_summary_raw=$(printf "%b" "$current_url_summary_for_sorting" | sort -t$'\t' -k2nr | head -n "$TOP_N_URL")
    fi

    extracted_referers_raw_counts=$(awk -F'"' '{ referer_field = $(NF-3); if (NF >= 6 && referer_field != "-" && referer_field != "") print referer_field }' "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{$1=$1; printf "%s\t%s\n", $2, $1}')
    
    current_referer_summary_for_sorting=""
    while IFS=$'\t' read -r referer_path count; do
        if [ -n "$referer_path" ] && [ -n "$count" ]; then
            encoded_referer_path=$(echo -n "$referer_path" | base64)
            current_referer_summary_for_sorting="${current_referer_summary_for_sorting}${encoded_referer_path}\t${count}\n"
        fi
    done <<< "$extracted_referers_raw_counts"

    if [ -n "$current_referer_summary_for_sorting" ]; then
        top_referers_for_summary_raw=$(printf "%b" "$current_referer_summary_for_sorting" | sort -t$'\t' -k2nr | head -n "$TOP_N_REFERER")
    fi

fi

if [ "$found_any_threat" = true ]; then
    for current_threat_type_code in "${unique_threat_types_in_order[@]}"; do
        type_total_detections_str=$(echo "$threat_type_summary_data" | grep -o -E "${current_threat_type_code}=[^;]+" | cut -d'=' -f2)
        type_total_detections=${type_total_detections_str:-0}
        if [ "$type_total_detections" -gt 0 ]; then
            threat_desc_full=$(get_threat_description "$current_threat_type_code")
            threat_name_for_report=$(echo "$threat_desc_full" | cut -d':' -f1)
            echo "----------------------------------------" >> "$REPORT_FILE"
            echo "Threat Type: $threat_name_for_report (Code: $current_threat_type_code, Total Detected Log Lines: $type_total_detections)" >> "$REPORT_FILE"
            echo "Description: $(echo "$threat_desc_full" | cut -d':' -f2-)" >> "$REPORT_FILE"
            echo "Detected Logs:" >> "$REPORT_FILE"
            for pattern_item_inner in "${PATTERNS[@]}"; do
                IFS=":" read -r inner_threat_type inner_pattern <<< "$pattern_item_inner"
                if [[ "$inner_threat_type" == "$current_threat_type_code" ]]; then
                    grep_output=$(grep -E -i "$inner_pattern" "$LOG_FILE")
                    if [ -n "$grep_output" ]; then echo "$grep_output" >> "$REPORT_FILE"; fi
                fi
            done
            echo "" >> "$REPORT_FILE"
        fi
    done
fi
echo "========================================" >> "$REPORT_FILE"


if [ "$found_any_threat" = true ]; then
    echo "===== Audit Summary =====" >> "$SUMMARY_FILE"
    echo "Total Matched Log Lines (all patterns, duplicates possible): $total_log_lines_matched_overall" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"

    echo "--- Web Vulnerability Check Results (Detections by Threat Type) ---" >> "$SUMMARY_FILE"
    OLD_IFS_SUMMARY="$IFS"; IFS=';'
    for item in $threat_type_summary_data; do
        if [ -n "$item" ]; then
            threat_type_code_summary=$(echo "$item" | cut -d'=' -f1)
            threat_count_summary=$(echo "$item" | cut -d'=' -f2)
            if [ "$threat_count_summary" -gt 0 ]; then
                full_desc_summary=$(get_threat_description "$threat_type_code_summary")
                name_for_summary=$(echo "$full_desc_summary" | cut -d':' -f1)
                printf "  - %-35s : %s log lines detected\n" "$name_for_summary ($threat_type_code_summary)" "$threat_count_summary" >> "$SUMMARY_FILE"
            fi
        fi
    done
    IFS="$OLD_IFS_SUMMARY"
    echo "" >> "$SUMMARY_FILE"

    if [ -n "$top_dates_for_summary" ]; then
        echo "--- Daily Detection Status (Top $TOP_N_DATE) ---" >> "$SUMMARY_FILE"
        while IFS="=" read -r date count; do
            if [ -n "$date" ] && [ -n "$count" ]; then
                 printf "  - %-15s : %s events\n" "$date" "$count" >> "$SUMMARY_FILE"
            fi
        done <<< "$top_dates_for_summary"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_ips_for_summary" ]; then
        echo "--- IP Address Detection Status (Top $TOP_N_IP) ---" >> "$SUMMARY_FILE"
        while IFS="=" read -r ip count; do
            if [ -n "$ip" ] && [ -n "$count" ]; then
                 printf "  - %-15s : %s events\n" "$ip" "$count" >> "$SUMMARY_FILE"
            fi
        done <<< "$top_ips_for_summary"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_urls_for_summary_raw" ]; then
        echo "--- URL Detection Status (Top $TOP_N_URL) ---" >> "$SUMMARY_FILE"
        while IFS=$'\t' read -r encoded_url count; do
            if [ -n "$encoded_url" ] && [ -n "$count" ]; then
                decoded_url_base64=$(echo "$encoded_url" | base64 -d 2>/dev/null)
                 if [ $? -eq 0 ] && [ -n "$decoded_url_base64" ]; then
                    final_decoded_url=$(url_decode "$decoded_url_base64")
                    if [ ${#final_decoded_url} -gt 70 ]; then
                        display_url="${final_decoded_url:0:67}..."
                    else
                        display_url="$final_decoded_url"
                    fi
                    printf "  - %s : %s events\n" "$display_url" "$count" >> "$SUMMARY_FILE"
                else
                    if [ ${#encoded_url} -gt 70 ]; then
                        display_url="${encoded_url:0:67}..."
                    else
                        display_url="$encoded_url"
                    fi
                    printf "  - %s (decoding_failed) : %s events\n" "$display_url" "$count" >> "$SUMMARY_FILE"
                fi
            fi
        done <<< "$top_urls_for_summary_raw"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_referers_for_summary_raw" ]; then
        echo "--- Referer Detection Status (Top $TOP_N_REFERER) ---" >> "$SUMMARY_FILE"
        while IFS=$'\t' read -r encoded_referer count; do
            if [ -n "$encoded_referer" ] && [ -n "$count" ]; then
                decoded_referer_base64=$(echo "$encoded_referer" | base64 -d 2>/dev/null)
                 if [ $? -eq 0 ] && [ -n "$decoded_referer_base64" ]; then
                    final_decoded_referer=$(url_decode "$decoded_referer_base64")
                    if [ ${#final_decoded_referer} -gt 70 ]; then
                        display_referer="${final_decoded_referer:0:67}..."
                    else
                        display_referer="$final_decoded_referer"
                    fi
                    printf "  - %s : %s events\n" "$display_referer" "$count" >> "$SUMMARY_FILE"
                else
                    if [ ${#encoded_referer} -gt 70 ]; then
                        display_referer="${encoded_referer:0:67}..."
                    else
                        display_referer="$encoded_referer"
                    fi
                    printf "  - %s (decoding_failed) : %s events\n" "$display_referer" "$count" >> "$SUMMARY_FILE"
                fi
            fi
        done <<< "$top_referers_for_summary_raw"
        echo "" >> "$SUMMARY_FILE"
    fi

    echo "=========================" >> "$SUMMARY_FILE"
    echo "For detailed logs, check the $REPORT_FILE file." >> "$SUMMARY_FILE"
else
    echo "No security threat logs detected." >> "$SUMMARY_FILE"
    echo "=========================" >> "$SUMMARY_FILE"
fi


if [ "$found_any_threat" = true ] && [ -f "$TEMP_MATCHED_LOGS" ] && [ -s "$TEMP_MATCHED_LOGS" ]; then
    grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort -u | awk '{print "- " $0}' > "$BLACKLIST_FILE"
    echo "IP blacklist created: $BLACKLIST_FILE"
else
    > "$BLACKLIST_FILE" 
    echo "No threats detected, empty IP blacklist file created: $BLACKLIST_FILE"
fi


if [ "$found_any_threat" = false ]; then
    echo "No security threat logs detected."
    echo "Report generation complete: $REPORT_FILE, $SUMMARY_FILE, $BLACKLIST_FILE"
else
    echo "Report generation complete: $REPORT_FILE, $SUMMARY_FILE, $BLACKLIST_FILE"
    echo ""
    cat "$SUMMARY_FILE"
fi

if [ -f "$TEMP_MATCHED_LOGS" ]; then
    rm -f "$TEMP_MATCHED_LOGS"
fi