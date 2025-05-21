#!/bin/bash

DEFAULT_LOG_FILE="access.log"
DEFAULT_REPORT_FILE="report.txt"
DEFAULT_SUMMARY_FILE="summary.txt"
DEFAULT_BLACKLIST_FILE="blacklist.txt"
DEFAULT_OUTPUT_DIR="output"
DEFAULT_TOP_N_DATE=10
DEFAULT_TOP_N_IP=10
DEFAULT_TOP_N_URL=10
DEFAULT_TOP_N_REFERER=10
DEFAULT_ONLY_PATTERNS="SQL_INJECTION_GROUP,XSS_GROUP"

LOG_FILE="$DEFAULT_LOG_FILE"
REPORT_FILE="$DEFAULT_REPORT_FILE"
SUMMARY_FILE="$DEFAULT_SUMMARY_FILE"
BLACKLIST_FILE="$DEFAULT_BLACKLIST_FILE"
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
TOP_N_DATE="$DEFAULT_TOP_N_DATE"
TOP_N_IP="$DEFAULT_TOP_N_IP"
TOP_N_URL="$DEFAULT_TOP_N_URL"
TOP_N_REFERER="$DEFAULT_TOP_N_REFERER"
ONLY_PATTERNS_SPECIFIED="$DEFAULT_ONLY_PATTERNS"

usage() {
    echo "Usage: $0 [OPTIONS...]"
    echo "Options:"
    echo "  --file LOG_FILE, -f LOG_FILE         Path to the log file to analyze (default: $DEFAULT_LOG_FILE)"
    echo "  --output OUTPUT_DIR, -o OUTPUT_DIR   Directory to save report files (default: $DEFAULT_OUTPUT_DIR)"
    echo "  --report-file REPORT_FILE            Detailed report file name (default: $DEFAULT_REPORT_FILE)"
    echo "  --summary-file SUMMARY_FILE          Summary report file name (default: $DEFAULT_SUMMARY_FILE)"
    echo "  --blacklist-file BLACKLIST_FILE      IP blacklist file name (default: $DEFAULT_BLACKLIST_FILE)"
    echo "  --top-date TOP_N_DATE                Number of daily detection entries to display (default: $DEFAULT_TOP_N_DATE)"
    echo "  --top-ip TOP_N_IP                  Number of IP address detection entries to display (default: $DEFAULT_TOP_N_IP)"
    echo "  --top-url TOP_N_URL                Number of URL detection entries to display (default: $DEFAULT_TOP_N_URL)"
    echo "  --top-referer TOP_N_REFERER        Number of Referer detection entries to display (default: $DEFAULT_TOP_N_REFERER)"
    echo "  --only-patterns PATTERN_TYPES      Comma-separated list of pattern types or group names to run."
    echo "                                       (e.g., SQL_INJECTION_GROUP,XSS,CMD_INJECTION)."
    echo "                                       Default is \"$DEFAULT_ONLY_PATTERNS\"."
    echo "                                       To run ALL patterns, specify --only-patterns \"ALL\" or an empty string --only-patterns \"\"."
    echo "  --list-groups                        List available pattern groups and their members."
    echo "  --help, -h                           Display this help message."
    exit 1
}

GROUP_SQL_INJECTION="SQL_INJECTION,SQL_INJECTION_NOSQL"
GROUP_XSS="XSS,XSS_ENCODED,XSS_DOM"
GROUP_SENSITIVE_FILE="SENSITIVE_FILE_ACCESS,SENSITIVE_FILE_BACKUP"
GROUP_LFI_RFI="PATH_TRAVERSAL_LFI,RFI"
GROUP_INJECTION_COMMANDS="CMD_INJECTION,LOG4J_JNDI_LOOKUP,SPRING4SHELL_RCE,SSTI"
GROUP_DESERIALIZATION="DESERIALIZATION_PHP_OBJECT,DESERIALIZATION_JAVA_OBJECT"


PATTERN_GROUP_NAMES=(
    "SQL_INJECTION_GROUP"
    "XSS_GROUP"
    "SENSITIVE_FILE_GROUP"
    "LFI_RFI_GROUP"
    "INJECTION_COMMANDS_GROUP"
    "DESERIALIZATION_GROUP"
)

get_group_members() {
    local group_name_input="$1"
    case "$group_name_input" in
        "SQL_INJECTION_GROUP") echo "$GROUP_SQL_INJECTION" ;;
        "XSS_GROUP") echo "$GROUP_XSS" ;;
        "SENSITIVE_FILE_GROUP") echo "$GROUP_SENSITIVE_FILE" ;;
        "LFI_RFI_GROUP") echo "$GROUP_LFI_RFI" ;;
        "INJECTION_COMMANDS_GROUP") echo "$GROUP_INJECTION_COMMANDS" ;;
        "DESERIALIZATION_GROUP") echo "$GROUP_DESERIALIZATION" ;;
        *) echo "" ;;
    esac
}

list_groups() {
    echo "Available Pattern Groups and their members:"
    for group_name_iter in "${PATTERN_GROUP_NAMES[@]}"; do
        local members
        members=$(get_group_members "$group_name_iter")
        if [ -n "$members" ]; then
            echo "  Group: $group_name_iter"
            echo "    Members: $members"
        fi
    done
    exit 0
}


ARGS=()
only_patterns_option_provided=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            if [[ -n "$2" && "$2" != -* ]]; then LOG_FILE="$2"; shift 2; else echo "Error: --file or -f option requires a file path argument." >&2; usage; fi ;;
        -o|--output)
            if [[ -n "$2" && "$2" != -* ]]; then OUTPUT_DIR="$2"; shift 2; else echo "Error: --output or -o option requires a directory argument." >&2; usage; fi ;;
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
        --only-patterns)
            only_patterns_option_provided=true
            if [[ -n "$2" && "$2" != -* ]]; then
                ONLY_PATTERNS_SPECIFIED="$2"; shift 2;
            elif [[ "$2" == "" || $# -eq 1 ]]; then # Handles --only-patterns ""
                ONLY_PATTERNS_SPECIFIED=""; shift $(($# > 1 ? 2 : 1));
            else
                echo "Error: --only-patterns option requires a comma-separated list of pattern types/groups argument or an empty string for all." >&2; usage;
            fi ;;
        --list-groups)
            list_groups ;;
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


if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
    if [ $? -ne 0 ]; then
        echo "Error: Could not create output directory '$OUTPUT_DIR'." >&2
        exit 1
    fi
    echo "INFO: Created output directory '$OUTPUT_DIR'."
fi


if [[ "$REPORT_FILE" != */* ]]; then
    REPORT_FILE="${OUTPUT_DIR}/${REPORT_FILE}"
fi

mkdir -p "$(dirname "$REPORT_FILE")"
if [ $? -ne 0 ]; then
    echo "Error: Could not create directory for report file: $(dirname "$REPORT_FILE")" >&2
    exit 1
fi


if [[ "$SUMMARY_FILE" != */* ]]; then
    SUMMARY_FILE="${OUTPUT_DIR}/${SUMMARY_FILE}"
fi

mkdir -p "$(dirname "$SUMMARY_FILE")"
if [ $? -ne 0 ]; then
    echo "Error: Could not create directory for summary file: $(dirname "$SUMMARY_FILE")" >&2
    exit 1
fi


if [[ "$BLACKLIST_FILE" != */* ]]; then
    BLACKLIST_FILE="${OUTPUT_DIR}/${BLACKLIST_FILE}"
fi

mkdir -p "$(dirname "$BLACKLIST_FILE")"
if [ $? -ne 0 ]; then
    echo "Error: Could not create directory for blacklist file: $(dirname "$BLACKLIST_FILE")" >&2
    exit 1
fi

# Determine the path to display for the log file (relative to current directory if possible)
DISPLAY_LOG_FILE_PATH="$LOG_FILE" # Default to the input path

# Attempt to get a canonical absolute path first
ABS_LOG_FILE_FOR_DISPLAY=$(realpath "$LOG_FILE" 2>/dev/null)

if [ $? -eq 0 ] && [ -n "$ABS_LOG_FILE_FOR_DISPLAY" ]; then
    # If absolute path was obtained successfully, try to make it relative to current directory
    REL_PATH_ATTEMPT=$(realpath --relative-to=. "$ABS_LOG_FILE_FOR_DISPLAY" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$REL_PATH_ATTEMPT" ]; then
        DISPLAY_LOG_FILE_PATH="$REL_PATH_ATTEMPT"
    else
        # Fallback if 'realpath --relative-to=.' is not supported or fails
        current_pwd_for_rel="$(pwd)"
        # Ensure current_pwd_for_rel ends with a slash for correct prefix removal, unless it's "/"
        if [ "$current_pwd_for_rel" = "/" ]; then
            current_pwd_prefix="/"
        else
            current_pwd_prefix="${current_pwd_for_rel}/"
        fi

        if [[ "$ABS_LOG_FILE_FOR_DISPLAY" == "$current_pwd_prefix"* ]]; then
            DISPLAY_LOG_FILE_PATH="${ABS_LOG_FILE_FOR_DISPLAY#$current_pwd_prefix}"
        elif [[ "$ABS_LOG_FILE_FOR_DISPLAY" == "$current_pwd_for_rel" ]]; then # e.g. PWD is /foo and file is /foo
            DISPLAY_LOG_FILE_PATH=$(basename "$ABS_LOG_FILE_FOR_DISPLAY")
        else
            # If it's not under PWD, and original LOG_FILE was relative, prefer original relative path
            if [[ "$LOG_FILE" != /* ]]; then # Original LOG_FILE was relative
                DISPLAY_LOG_FILE_PATH="$LOG_FILE"
            else # Original LOG_FILE was absolute and not under PWD, stick with its absolute form
                DISPLAY_LOG_FILE_PATH="$ABS_LOG_FILE_FOR_DISPLAY"
            fi
        fi
    fi
else
    # realpath "$LOG_FILE" failed (e.g., file doesn't exist yet, or realpath command issue).
    # DISPLAY_LOG_FILE_PATH remains the original $LOG_FILE.
    # The script will later check for file existence.
    : # No action needed, DISPLAY_LOG_FILE_PATH already defaults to LOG_FILE
fi


PATTERNS=(
    # SQL Injection
    "SQL_INJECTION:.*' OR '1'='1"
    "SQL_INJECTION:.*(\b(UNION|SELECT)\b.{1,100}?\b(FROM|SLEEP|BENCHMARK|PG_SLEEP|WAITFOR)\b)"
    "SQL_INJECTION:.*(information_schema|pg_catalog|mysql\.user|sys\.tables|sysobjects)"
    "SQL_INJECTION:.*(SLEEP\(|BENCHMARK\(|pg_sleep\(|WAITFOR DELAY)"
    "SQL_INJECTION:.*(--|#|/\*|\*/|;).*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\b"
    "SQL_INJECTION:.*(xp_cmdshell|sp_configure|OPENROWSET|OPENDATASOURCE)"
    "SQL_INJECTION_NOSQL:.*([$]ne|[$]gt|[$]lt|[$]regex|[$]where)"

    # Cross-Site Scripting (XSS)
    "XSS:.*<script\b[^>]*>.*?</script\b[^>]*>"
    "XSS:.*<img\b[^>]*\b(src|onerror|onload)\s*=\s*[^>]*javascript:[^>]+>"
    "XSS:.*<[a-zA-Z]+\b[^>]*\b(on\w+)\s*=\s*[^>]*[^'\"\s>]+"
    "XSS:.*<iframe\b[^>]*\b(src|srcdoc)\s*=\s*[^>]*javascript:[^>]+>"
    "XSS:.*(alert\(|confirm\(|prompt\(|document\.cookie|document\.write\(|window\.location)"
    "XSS:.*(expression\(|eval\(|setTimeout\(|setInterval\()"
    "XSS_ENCODED:.*(%3Cscript|%3Cimg|%3Csvg|%253Cscript|<script|<script)" # Decoded <script>, <img, <svg
    "XSS_DOM:.*(#|location\.hash\s*=).*(<script>|javascript:)"

    # Path Traversal & Local File Inclusion (LFI)
    "PATH_TRAVERSAL_LFI:.*(\.\.[/\\]|\.%2e%2e[%2f%5c]|\.%252e%252e[%252f%255c])" # ../, %2e%2e%2f, %252e%252e%252f etc.
    "PATH_TRAVERSAL_LFI:.*(etc/passwd|boot\.ini|win\.ini|system32/drivers/etc/hosts)"
    "PATH_TRAVERSAL_LFI:.*(WEB-INF/web\.xml|META-INF/MANIFEST\.MF)"
    "PATH_TRAVERSAL_LFI:.*(\%00|\0)" # Null byte

    # Remote File Inclusion (RFI)
    "RFI:.*(include|require|include_once|require_once)\s*[_A-Z0-9\[\]\"']*\s*=\s*(ht|f)tps?://[^&?\s]+"
    "RFI:.*(include|require|include_once|require_once)\s*[_A-Z0-9\[\]\"']*\s*=\s*(php|data|expect)://[^&?\s]+"
    
    # Command Injection
    "CMD_INJECTION:.*(;|%3B|\n|%0A|\r|%0D|[\`]|[$]\(|\&\&|\|\|)" # Shell metacharacters
    "CMD_INJECTION:.*(cmd=|exec=|command=|system=|passthru=|shell_exec=|popen=|pcntl_exec|eval\(|assert\()" # Common functions
    "CMD_INJECTION:.*(cat\s+/etc/passwd|whoami|uname\s+-a|id|ls\s+-la|netstat|ifconfig|ipconfig|ping\s+-c\s+\d)" # Common commands
    "CMD_INJECTION:.*(nc\s+-l\s+-p|ncat|powershell|bash\s+-c|perl\s+-e|python\s+-c|ruby\s+-e)" # Reverse shells / execution
    
    # Sensitive File Access
    "SENSITIVE_FILE_ACCESS:.*wp-config\.php"
    "SENSITIVE_FILE_ACCESS:.*(\.env|\.htpasswd|\.htaccess|\.git/config|config\.php|settings\.php|localsettings\.php|credentials|database\.yml|secrets\.yml)"
    "SENSITIVE_FILE_ACCESS:.*(\.pem|\.key|\.p12|\.crt|\.csr|\.jks)" # Key files
    "SENSITIVE_FILE_ACCESS:.*(phpinfo\.php|test\.php|info\.php|status\?full|server-status|manager/html)" # Info/status pages
    "SENSITIVE_FILE_ACCESS:.*(web\.config|appsettings\.json)" # .NET config files
    "SENSITIVE_FILE_BACKUP:.*(\.(bak|backup|old|orig|sql|config|conf|zip|tar\.gz|tgz|swp|~|save|copy|dev|prod|staging|bkp|bk))([\?&]|$)" # Backup extensions
    
    # Directory Listing
    "DIRECTORY_LISTING:.*(Index of /|parent directory)" # Common directory listing phrases

    # Server-Side Request Forgery (SSRF)
    "SSRF:.*(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)" # Loopback addresses
    "SSRF:.*(169\.254\.169\.254|metadata\.google\.internal|instance-data/latest/)" # Cloud metadata services
    "SSRF:.*(url=|uri=|target=|dest=|file=|path=|host=|data=|feed=|image_url=).*(file:///|dict://|sftp://|ldap://|gopher://|jar://)" # SSRF with various schemes
    "SSRF:.*(url=|uri=|target=|dest=).*(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" # SSRF targeting private IPs
    
    # XML External Entity (XXE) Injection
    "XXE_INJECTION:.*(<!ENTITY\s+[^>]*\s+(SYSTEM|PUBLIC)\s+[\"'][^\"']*[\"']>)"
    "XXE_INJECTION:.*(<!ENTITY\s+%\s+[^>]*\s+SYSTEM)" # Parameter entities
    "XXE_INJECTION:.*(xxe_payload|ENTITY\s+xxe)"
    
    # Log4Shell (JNDI Lookup)
    "LOG4J_JNDI_LOOKUP:.*\\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds):" # Log4j JNDI lookup
    
    # Spring4Shell (RCE)
    "SPRING4SHELL_RCE:.*class\.module\.classLoader" # Spring4Shell RCE

    # Insecure Deserialization
    "DESERIALIZATION_PHP_OBJECT:.*O:[0-9]+:\"" # PHP serialized object
    "DESERIALIZATION_JAVA_OBJECT:.*( rO0ABXNy|aced0005|ysoserial| Javassist\.CtClass|weblogic\.jms\.common\.StreamMessageImpl)" # Java serialized object markers
    
    # File Upload Vulnerabilities
    "FILE_UPLOAD_VULN:.*POST .*/(upload|files|uploads|tmp|temp|images)/.*\.(php[3457s]?|phtml|phar|aspx?|jspx?|sh|exe|dll|cgi|pl|py|rb|war|jar)(\.[^./]+)*" # Upload of executable extensions
    "FILE_UPLOAD_VULN:.*Content-Disposition:.*\bfilename\s*=\s*[\"'].*\.(php|jsp|asp|sh)[\"']" # Dangerous extensions in filename
    
    # Authentication Bypass
    "AUTH_BYPASS:.*(admin_bypass|is_admin=(true|1)|role=(admin|root)|user_level=0|debug_mode=1)" # Common auth bypass parameters
    "AUTH_BYPASS:.*(X-Forwarded-For:\s*127\.0\.0\.1|X-Original-URL:|X-Rewrite-URL:|Authorization:\s*Basic\s*YWRtaW46YWRtaW4=)" # Header-based bypass (admin:admin base64)
    
    # Vulnerable Component Access
    "VULN_COMPONENT_ACCESS:.*(/phpmyadmin/|/pma/|/wp-admin/|/admin/|/manager/html|/jmx-console/|/web-console/|struts/dojo/)" # Access to admin/vulnerable paths
    
    # Open Redirect
    "OPEN_REDIRECT:.*(redirect=|url=|next=|location=|goto=|target=|return=|return_to=|checkout_url=)(https?%3A%2F%2F|%2F%2F|\\\\|%5C%5C)[^/\\s?&][^\"'<>]+" # Open redirect parameters
    
    # Information Disclosure / Debug
    "INFO_DISCLOSURE_DEBUG:.*(debug=(true|1)|TRACE\s+/|TRACK\s+/|X-Debug-Token:|phpinfo\(\))" # Debug parameters/methods
    "VERBOSE_ERROR_MESSAGES:.*(Stack Trace|Traceback \(most recent call last\)|PHP Fatal error:|Syntax error near|ORA-\d{5}:|java\.lang\.|Warning: Division by zero|Undefined index:)" # Verbose error messages
    
    # Log Injection / CRLF Injection
    "LOG_INJECTION:.*(%0d|%0a|\\r|\\n|\r\n)" # CRLF characters (URL encoded or literal)
    
    # Server-Side Template Injection (SSTI)
    "SSTI:.*(\{\{.*\}\}|\{\%.*\%\}|<%=.*%>|[$]\{[^\}]+\}|#\{[^\}]+\})" # Common template engine syntaxes
    "SSTI:.*(config.SECRET_KEY|settings.SECRET_KEY|getattribute|lipsum|self.__init__|class.__bases__|mro\(\))" # SSTI payloads
    
    # Prototype Pollution
    "PROTOTYPE_POLLUTION:.*(__proto__|constructor\.prototype|Object\.prototype).*\s*=\s*\{" # Prototype pollution assignment
    
    # HTTP Desync / Request Smuggling
    "HTTP_DESYNC:.*(Content-Length:\s*\d+\r\nTransfer-Encoding:\s*chunked|Transfer-Encoding:\s*chunked\r\nContent-Length:\s*\d+)" # Conflicting headers
)

PATTERNS_TO_RUN=()
final_selected_types_for_filtering=()

if [[ "$only_patterns_option_provided" == true && ( -z "$ONLY_PATTERNS_SPECIFIED" || "$ONLY_PATTERNS_SPECIFIED" == "ALL" ) ]]; then
    PATTERNS_TO_RUN=("${PATTERNS[@]}")
    echo "INFO: Running with ALL patterns as specified by --only-patterns."
elif [ -n "$ONLY_PATTERNS_SPECIFIED" ]; then
    IFS=',' read -ra initial_selected_items <<< "$ONLY_PATTERNS_SPECIFIED"

    temp_final_types_str=" " # Using spaces for word boundary matching
    for item in "${initial_selected_items[@]}"; do
        trimmed_item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') # Trim whitespace
        group_members_str=$(get_group_members "$trimmed_item")

        if [ -n "$group_members_str" ]; then
            IFS=',' read -ra group_members_array <<< "$group_members_str"
            for member in "${group_members_array[@]}"; do
                trimmed_member=$(echo "$member" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                # Add if not already present
                if ! echo "$temp_final_types_str" | grep -q " $trimmed_member "; then
                    final_selected_types_for_filtering+=("$trimmed_member")
                    temp_final_types_str="$temp_final_types_str$trimmed_member "
                fi
            done
        else
            # Add if not already present (for individual types)
            if ! echo "$temp_final_types_str" | grep -q " $trimmed_item "; then
                 final_selected_types_for_filtering+=("$trimmed_item")
                 temp_final_types_str="$temp_final_types_str$trimmed_item "
            fi
        fi
    done
    
    # Populate PATTERNS_TO_RUN based on final_selected_types_for_filtering
    for pattern_item in "${PATTERNS[@]}"; do
        IFS=":" read -r threat_type _ <<< "$pattern_item"
        should_add=false
        for selected_type_final in "${final_selected_types_for_filtering[@]}"; do
            if [[ "$threat_type" == "$selected_type_final" ]]; then
                should_add=true
                break
            fi
        done
        if [[ "$should_add" == true ]]; then
            PATTERNS_TO_RUN+=("$pattern_item")
        fi
    done

    if [ ${#PATTERNS_TO_RUN[@]} -eq 0 ]; then
        echo "Error: No patterns matched the specified types/groups: '$ONLY_PATTERNS_SPECIFIED'" >&2
        echo "Please check the pattern types/groups. Default is '$DEFAULT_ONLY_PATTERNS'. To run all, use --only-patterns \"ALL\" or --only-patterns \"\"." >&2
        echo "Use --list-groups to see available groups. Available individual types are:" >&2
        local unique_types_string_err=" "
        for p_item in "${PATTERNS[@]}"; do
            IFS=":" read -r t_type _ <<< "$p_item"
            if [[ -n "$t_type" ]]; then # Ensure type is not empty
                if ! echo "$unique_types_string_err" | grep -q " $t_type "; then # Check if type already listed
                    unique_types_string_err="$unique_types_string_err$t_type "
                    echo "  $t_type" >&2
                fi
            fi
        done
        exit 1
    fi
else # No --only-patterns provided, or it was empty and not caught by the first 'if' (should not happen due to option parsing fix)
    # Fallback to default if ONLY_PATTERNS_SPECIFIED is empty and option was not explicitly used to set it empty
    if [[ -z "$ONLY_PATTERNS_SPECIFIED" && "$only_patterns_option_provided" == false ]]; then
        ONLY_PATTERNS_SPECIFIED="$DEFAULT_ONLY_PATTERNS" # Apply default
        echo "INFO: Running with default patterns: $DEFAULT_ONLY_PATTERNS"
    elif [[ "$ONLY_PATTERNS_SPECIFIED" == "ALL" || ( -z "$ONLY_PATTERNS_SPECIFIED" && "$only_patterns_option_provided" == true ) ]]; then
        PATTERNS_TO_RUN=("${PATTERNS[@]}")
        echo "INFO: Running with ALL patterns (default or specified as ALL/empty)."
    fi

    # This block re-processes if defaults were applied or if it's not ALL
    if ! [[ "$ONLY_PATTERNS_SPECIFIED" == "ALL" || ( -z "$ONLY_PATTERNS_SPECIFIED" && "$only_patterns_option_provided" == true ) ]]; then
         IFS=',' read -ra initial_selected_items <<< "$ONLY_PATTERNS_SPECIFIED" # Use the (potentially default) list
        temp_final_types_str=" "
        for item in "${initial_selected_items[@]}"; do
            trimmed_item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            group_members_str=$(get_group_members "$trimmed_item")

            if [ -n "$group_members_str" ]; then
                IFS=',' read -ra group_members_array <<< "$group_members_str"
                for member in "${group_members_array[@]}"; do
                    trimmed_member=$(echo "$member" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                    if ! echo "$temp_final_types_str" | grep -q " $trimmed_member "; then
                        final_selected_types_for_filtering+=("$trimmed_member")
                        temp_final_types_str="$temp_final_types_str$trimmed_member "
                    fi
                done
            else
                if ! echo "$temp_final_types_str" | grep -q " $trimmed_item "; then
                     final_selected_types_for_filtering+=("$trimmed_item")
                     temp_final_types_str="$temp_final_types_str$trimmed_item "
                fi
            fi
        done

        for pattern_item in "${PATTERNS[@]}"; do
            IFS=":" read -r threat_type _ <<< "$pattern_item"
            should_add=false
            for selected_type_final in "${final_selected_types_for_filtering[@]}"; do
                if [[ "$threat_type" == "$selected_type_final" ]]; then
                    should_add=true
                    break
                fi
            done
            if [[ "$should_add" == true ]]; then
                PATTERNS_TO_RUN+=("$pattern_item")
            fi
        done
        if [ ${#PATTERNS_TO_RUN[@]} -eq 0 ] && [ -n "$ONLY_PATTERNS_SPECIFIED" ]; then # Check if it's non-empty but yielded no patterns
             echo "Error: Default patterns '$ONLY_PATTERNS_SPECIFIED' resulted in no active patterns. Check definitions." >&2
             exit 1
        fi
    fi
fi

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
    echo "Error: Log file '$DISPLAY_LOG_FILE_PATH' not found." # Use DISPLAY_LOG_FILE_PATH for user message
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
echo "Log File Analyzed: $DISPLAY_LOG_FILE_PATH" >> "$REPORT_FILE"
echo "Output Directory: $OUTPUT_DIR" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Security Audit Summary - $(date)" > "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Log File Analyzed: $DISPLAY_LOG_FILE_PATH" >> "$SUMMARY_FILE"
echo "Output Directory: $OUTPUT_DIR" >> "$SUMMARY_FILE"
echo "Number of Daily Detections to Display: $TOP_N_DATE" >> "$SUMMARY_FILE"
echo "Number of IP Address Detections to Display: $TOP_N_IP" >> "$SUMMARY_FILE"
echo "Number of URL Detections to Display: $TOP_N_URL" >> "$SUMMARY_FILE"
echo "Number of Referer Detections to Display: $TOP_N_REFERER" >> "$SUMMARY_FILE"

if [[ "$only_patterns_option_provided" == true && ( -z "$ONLY_PATTERNS_SPECIFIED" || "$ONLY_PATTERNS_SPECIFIED" == "ALL" ) ]]; then
    echo "Patterns Executed: ALL patterns" >> "$SUMMARY_FILE"
elif [ -n "$ONLY_PATTERNS_SPECIFIED" ]; then # This covers both user-provided and default that got set if user didn't provide
    echo "Patterns Executed (User Input or Default): [$ONLY_PATTERNS_SPECIFIED]" >> "$SUMMARY_FILE"
# else, if ONLY_PATTERNS_SPECIFIED is empty AND it was due to --only-patterns "", it's covered by "ALL patterns"
fi
echo "Number of Web Vulnerability Check Patterns Used: ${#PATTERNS_TO_RUN[@]} (out of ${#PATTERNS[@]} total defined)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

found_any_threat=false
total_log_lines_matched_overall=0
threat_type_summary_data=""
ip_summary_data=""
daily_summary_data=""
referer_summary_data_raw="" # Will store base64_encoded_path\tcount
top_ips_for_summary=""
top_urls_for_summary_raw="" # Will store base64_encoded_path\tcount
top_dates_for_summary=""
top_referers_for_summary_raw="" # Will store base64_encoded_path\tcount


# Determine unique threat types from the patterns that will be run, maintaining their general order
unique_threat_types_in_order=()
temp_seen_types_str_report=" " # Using spaces for word boundary matching
for pattern_item in "${PATTERNS_TO_RUN[@]}"; do
    IFS=":" read -r threat_type _ <<< "$pattern_item"
    if [ -z "$threat_type" ]; then continue; fi # Skip if threat type is somehow empty
    if ! echo "$temp_seen_types_str_report" | grep -q " $threat_type "; then
        unique_threat_types_in_order+=("$threat_type")
        temp_seen_types_str_report="$temp_seen_types_str_report$threat_type "
    fi
done

TEMP_MATCHED_LOGS=$(mktemp)
# Ensure TEMP_MATCHED_LOGS is removed on exit
trap 'rm -f "$TEMP_MATCHED_LOGS"' EXIT

# Populate threat_type_summary_data first
for current_threat_type in "${unique_threat_types_in_order[@]}"; do
    type_specific_total_count=0
    # Iterate through PATTERNS_TO_RUN to find all patterns for this specific type
    for pattern_item in "${PATTERNS_TO_RUN[@]}"; do
        IFS=":" read -r threat_type_from_pattern pattern <<< "$pattern_item"
        if [[ "$threat_type_from_pattern" == "$current_threat_type" ]]; then
            # Use process substitution to avoid issues with grep -c and empty files or no matches
            current_pattern_detection_count=$(grep -E -i -c "$pattern" "$LOG_FILE" || echo 0)
            type_specific_total_count=$((type_specific_total_count + current_pattern_detection_count))
        fi
    done
    if [ "$type_specific_total_count" -gt 0 ]; then
        threat_type_summary_data="${threat_type_summary_data}${current_threat_type}=${type_specific_total_count};"
        found_any_threat=true # Set this if any type has detections
    fi
done

# If any threat was found (based on counts), then populate TEMP_MATCHED_LOGS
if [ "$found_any_threat" = true ]; then
    for pattern_item in "${PATTERNS_TO_RUN[@]}"; do
        IFS=":" read -r _ pattern <<< "$pattern_item" # We only need the pattern part here
         if [ -z "$pattern" ]; then continue; fi # Skip if pattern is somehow empty
        grep -E -i "$pattern" "$LOG_FILE" >> "$TEMP_MATCHED_LOGS" # Append all matches
    done
fi

# Calculate total_log_lines_matched_overall based on aggregated counts to avoid issues with overlapping patterns
total_log_lines_matched_overall=0
OLD_IFS_SUM_CALC="$IFS"; IFS=';'
for item in $threat_type_summary_data; do
    if [ -n "$item" ]; then
        threat_count_for_total=$(echo "$item" | cut -d'=' -f2)
        total_log_lines_matched_overall=$((total_log_lines_matched_overall + threat_count_for_total))
    fi
done
IFS="$OLD_IFS_SUM_CALC"


# Process TEMP_MATCHED_LOGS for IPs, Dates, URLs, Referers if it's not empty
if [ -f "$TEMP_MATCHED_LOGS" ] && [ -s "$TEMP_MATCHED_LOGS" ]; then
    # IP Summary (from matched logs)
    extracted_ips_raw_for_summary=$(grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_ips_raw_for_summary; do ip_summary_data="${ip_summary_data}${item};"; done
    if [ -n "$ip_summary_data" ]; then
        # Sort by count (desc) and take top N for summary display
        top_ips_for_summary=$(echo "$ip_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n "$TOP_N_IP" | awk '{print $2 "=" $1}')
    fi

    # Daily Summary (from matched logs)
    extracted_dates_raw_for_summary=$(grep -o -E "$DATE_REGEX" "$TEMP_MATCHED_LOGS" | sed -E 's/^\[//' | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_dates_raw_for_summary; do daily_summary_data="${daily_summary_data}${item};"; done
    if [ -n "$daily_summary_data" ]; then
         # Sort by count (desc) and take top N for summary display
         top_dates_for_summary=$(echo "$daily_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n "$TOP_N_DATE" | awk '{print $2 "=" $1}')
    fi

    # URL Summary (from matched logs)
    # Extracts GET/POST etc. path, counts unique, stores base64(path)\tcount
    extracted_urls_raw_counts=$(awk -F'"' '{
        if (NF >= 2 && $2 ~ /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) /) {
            split($2, request_parts, " ");
            if (request_parts[2] != "") { # Ensure path is not empty
                print request_parts[2];
            }
        }
    }' "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{$1=$1; printf "%s\t%s\n", $2, $1}') # path\tcount

    current_url_summary_for_sorting=""
    while IFS=$'\t' read -r url_path count; do
        if [ -n "$url_path" ] && [ -n "$count" ]; then
            # Base64 encode to handle special characters in path before sorting/storing
            encoded_url_path=$(echo -n "$url_path" | base64)
            current_url_summary_for_sorting="${current_url_summary_for_sorting}${encoded_url_path}\t${count}\n"
        fi
    done <<< "$extracted_urls_raw_counts"

    if [ -n "$current_url_summary_for_sorting" ]; then
        top_urls_for_summary_raw=$(printf "%b" "$current_url_summary_for_sorting" | sort -t$'\t' -k2nr | head -n "$TOP_N_URL")
    fi

    # Referer Summary (from matched logs)
    # Extracts referer (field before user-agent), counts unique, stores base64(referer)\tcount
    extracted_referers_raw_counts=$(awk -F'"' '{ referer_field = $(NF-3); if (NF >= 6 && referer_field != "-" && referer_field != "") print referer_field }' "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{$1=$1; printf "%s\t%s\n", $2, $1}') # referer\tcount

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

fi # End of processing TEMP_MATCHED_LOGS

# === Generate Detailed Report File ===
if [ "$found_any_threat" = true ]; then
    # Iterate over unique_threat_types_in_order to write to report
    for current_threat_type_code in "${unique_threat_types_in_order[@]}"; do
        # Get the total detections for this type from threat_type_summary_data
        type_total_detections_str=$(echo "$threat_type_summary_data" | grep -o -E "${current_threat_type_code}=[^;]+" | cut -d'=' -f2)
        type_total_detections=${type_total_detections_str:-0} # Default to 0 if not found (should not happen if logic is correct)

        if [ "$type_total_detections" -gt 0 ]; then
            threat_desc_full=$(get_threat_description "$current_threat_type_code")
            threat_name_for_report=$(echo "$threat_desc_full" | cut -d':' -f1) # Get name part
            echo "----------------------------------------" >> "$REPORT_FILE"
            echo "Threat Type: $threat_name_for_report (Code: $current_threat_type_code, Total Detected Log Lines: $type_total_detections)" >> "$REPORT_FILE"
            echo "Description: $(echo "$threat_desc_full" | cut -d':' -f2- | sed 's/^[[:space:]]*//')" >> "$REPORT_FILE" # Get description part, trim leading space
            echo "Detected Logs:" >> "$REPORT_FILE"
            # Grep from the original LOG_FILE for logs matching patterns of this current_threat_type_code
            for pattern_item_inner in "${PATTERNS_TO_RUN[@]}"; do
                IFS=":" read -r inner_threat_type inner_pattern <<< "$pattern_item_inner"
                if [[ "$inner_threat_type" == "$current_threat_type_code" ]]; then
                    grep_output=$(grep -E -i "$inner_pattern" "$LOG_FILE")
                    if [ -n "$grep_output" ]; then
                        echo "$grep_output" >> "$REPORT_FILE"
                    fi
                fi
            done
            echo "" >> "$REPORT_FILE"
        fi
    done
fi
echo "========================================" >> "$REPORT_FILE"


# === Generate Summary Report File ===
if [ "$found_any_threat" = true ]; then
    echo "===== Audit Summary =====" >> "$SUMMARY_FILE"
    # total_log_lines_matched_overall is now sum of counts from threat_type_summary_data
    echo "Total Detected Events (sum of detections per type): $total_log_lines_matched_overall" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"

    echo "--- Web Vulnerability Check Results (Detections by Threat Type) ---" >> "$SUMMARY_FILE"
    OLD_IFS_SUMMARY="$IFS"; IFS=';'
    sorted_threat_type_summary_data=$(echo "$threat_type_summary_data" | tr ';' '\n' | grep . | \
        awk -F'=' '{print $2 " " $1}' | sort -nr | awk '{print $2 "=" $1}' | tr '\n' ';')

    for item in $sorted_threat_type_summary_data; do
        if [ -n "$item" ]; then # Ensure item is not empty
            threat_type_code_summary=$(echo "$item" | cut -d'=' -f1)
            threat_count_summary=$(echo "$item" | cut -d'=' -f2)
            # Ensure count is greater than 0 before printing
            if [ "$threat_count_summary" -gt 0 ]; then
                full_desc_summary=$(get_threat_description "$threat_type_code_summary")
                name_for_summary=$(echo "$full_desc_summary" | cut -d':' -f1)
                printf "  - %-35s : %s events detected\n" "$name_for_summary ($threat_type_code_summary)" "$threat_count_summary" >> "$SUMMARY_FILE"
            fi
        fi
    done
    IFS="$OLD_IFS_SUMMARY"
    echo "" >> "$SUMMARY_FILE"

    if [ -n "$top_dates_for_summary" ]; then
        echo "--- Daily Detection Status (Top $TOP_N_DATE from matched logs) ---" >> "$SUMMARY_FILE"
        # top_dates_for_summary is already sorted and formatted as date=count
        while IFS="=" read -r date count; do
            if [ -n "$date" ] && [ -n "$count" ]; then # Ensure not empty
                 printf "  - %-15s : %s events\n" "$date" "$count" >> "$SUMMARY_FILE"
            fi
        done <<< "$top_dates_for_summary" # Process the pre-sorted list
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_ips_for_summary" ]; then
        echo "--- IP Address Detection Status (Top $TOP_N_IP from matched logs) ---" >> "$SUMMARY_FILE"
        while IFS="=" read -r ip count; do
            if [ -n "$ip" ] && [ -n "$count" ]; then
                 printf "  - %-15s : %s events\n" "$ip" "$count" >> "$SUMMARY_FILE"
            fi
        done <<< "$top_ips_for_summary"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_urls_for_summary_raw" ]; then
        echo "--- URL Detection Status (Top $TOP_N_URL from matched logs) ---" >> "$SUMMARY_FILE"
        # top_urls_for_summary_raw is base64_encoded_url\tcount
        while IFS=$'\t' read -r encoded_url count; do
            if [ -n "$encoded_url" ] && [ -n "$count" ]; then
                decoded_url_base64=$(echo "$encoded_url" | base64 -d 2>/dev/null)
                 if [ $? -eq 0 ] && [ -n "$decoded_url_base64" ]; then # Check decode success and non-empty
                    final_decoded_url=$(url_decode "$decoded_url_base64") # Further URL decode
                    # Truncate for display if too long
                    if [ ${#final_decoded_url} -gt 70 ]; then
                        display_url="${final_decoded_url:0:67}..."
                    else
                        display_url="$final_decoded_url"
                    fi
                    printf "  - %s : %s events\n" "$display_url" "$count" >> "$SUMMARY_FILE"
                else
                    # Fallback if base64 decoding fails (should be rare)
                    if [ ${#encoded_url} -gt 70 ]; then # Use encoded_url for display if it's a path, or base64 if it fails to decode
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
        echo "--- Referer Detection Status (Top $TOP_N_REFERER from matched logs) ---" >> "$SUMMARY_FILE"
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
    echo "No security threat logs detected for the specified patterns." >> "$SUMMARY_FILE"
    echo "=========================" >> "$SUMMARY_FILE"
fi


# Create IP blacklist from IPs found in TEMP_MATCHED_LOGS
if [ "$found_any_threat" = true ] && [ -f "$TEMP_MATCHED_LOGS" ] && [ -s "$TEMP_MATCHED_LOGS" ]; then
    grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort -u > "$BLACKLIST_FILE"
    echo "INFO: IP blacklist created: $BLACKLIST_FILE"
else
    # Create an empty blacklist file if no threats or no matched logs
    > "$BLACKLIST_FILE"
    echo "INFO: No threats detected (or no logs matched selected patterns), empty IP blacklist file created: $BLACKLIST_FILE"
fi


if [ "$found_any_threat" = false ]; then
    echo "INFO: No security threat logs detected for the specified patterns."
fi
echo "Report generation complete. Files saved in '$OUTPUT_DIR':"
echo "  Report: $REPORT_FILE"
echo "  Summary: $SUMMARY_FILE"
echo "  Blacklist: $BLACKLIST_FILE"

# TEMP_MATCHED_LOGS is cleaned up by trap