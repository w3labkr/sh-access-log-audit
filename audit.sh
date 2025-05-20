#!/bin/bash

# 기본값 설정
DEFAULT_LOG_FILE="access.log"
DEFAULT_REPORT_FILE="report.txt"
DEFAULT_SUMMARY_FILE="summary.txt"
DEFAULT_BLACKLIST_FILE="blacklist.txt" # 블랙리스트 파일 기본 이름
DEFAULT_TOP_N_DATE=10
DEFAULT_TOP_N_IP=10
DEFAULT_TOP_N_URL=10
DEFAULT_TOP_N_REFERER=10

# 변수 초기화
LOG_FILE="$DEFAULT_LOG_FILE"
REPORT_FILE="$DEFAULT_REPORT_FILE"
SUMMARY_FILE="$DEFAULT_SUMMARY_FILE"
BLACKLIST_FILE="$DEFAULT_BLACKLIST_FILE" # 블랙리스트 파일 변수
TOP_N_DATE="$DEFAULT_TOP_N_DATE"
TOP_N_IP="$DEFAULT_TOP_N_IP"
TOP_N_URL="$DEFAULT_TOP_N_URL"
TOP_N_REFERER="$DEFAULT_TOP_N_REFERER"

# 사용법 안내 함수
usage() {
    echo "사용법: $0 [옵션...]"
    echo "옵션:"
    echo "  --file LOG_FILE, -f LOG_FILE         분석할 로그 파일 경로 (기본값: $DEFAULT_LOG_FILE)"
    echo "  --report-file REPORT_FILE            상세 리포트 파일 이름 (기본값: $DEFAULT_REPORT_FILE)"
    echo "  --summary-file SUMMARY_FILE          요약 리포트 파일 이름 (기본값: $DEFAULT_SUMMARY_FILE)"
    echo "  --blacklist-file BLACKLIST_FILE      IP 블랙리스트 파일 이름 (기본값: $DEFAULT_BLACKLIST_FILE)" # 블랙리스트 파일 옵션 추가
    echo "  --top-date TOP_N_DATE                일별 탐지 현황 표시 개수 (기본값: $DEFAULT_TOP_N_DATE)"
    echo "  --top-ip TOP_N_IP                  IP 주소별 탐지 현황 표시 개수 (기본값: $DEFAULT_TOP_N_IP)"
    echo "  --top-url TOP_N_URL                URL별 탐지 현황 표시 개수 (기본값: $DEFAULT_TOP_N_URL)"
    echo "  --top-referer TOP_N_REFERER        Referer별 탐지 현황 표시 개수 (기본값: $DEFAULT_TOP_N_REFERER)"
    echo "  --help, -h                           이 도움말 메시지를 표시합니다."
    exit 1
}

# 롱 옵션 및 일부 숏 옵션 파싱
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file|-f)
            if [[ -n "$2" && "$2" != -* ]]; then LOG_FILE="$2"; shift 2; else echo "오류: --file 또는 -f 옵션에는 파일 경로가 필요합니다." >&2; usage; fi ;;
        --report-file)
            if [[ -n "$2" && "$2" != -* ]]; then REPORT_FILE="$2"; shift 2; else echo "오류: --report-file 옵션에는 파일 이름이 필요합니다." >&2; usage; fi ;;
        --summary-file)
            if [[ -n "$2" && "$2" != -* ]]; then SUMMARY_FILE="$2"; shift 2; else echo "오류: --summary-file 옵션에는 파일 이름이 필요합니다." >&2; usage; fi ;;
        --blacklist-file) # 블랙리스트 파일 옵션 처리
            if [[ -n "$2" && "$2" != -* ]]; then BLACKLIST_FILE="$2"; shift 2; else echo "오류: --blacklist-file 옵션에는 파일 이름이 필요합니다." >&2; usage; fi ;;
        --top-date)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_DATE="$2"; shift 2; else echo "오류: --top-date 옵션에는 숫자가 필요합니다." >&2; usage; fi ;;
        --top-ip)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_IP="$2"; shift 2; else echo "오류: --top-ip 옵션에는 숫자가 필요합니다." >&2; usage; fi ;;
        --top-url)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_URL="$2"; shift 2; else echo "오류: --top-url 옵션에는 숫자가 필요합니다." >&2; usage; fi ;;
        --top-referer)
            if [[ -n "$2" && "$2" != -* ]]; then TOP_N_REFERER="$2"; shift 2; else echo "오류: --top-referer 옵션에는 숫자가 필요합니다." >&2; usage; fi ;;
        --help|-h)
            usage ;;
        *) # 알 수 없는 옵션 또는 인자
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ${#ARGS[@]} -ne 0 ]; then
    echo "알 수 없는 인자 또는 잘못된 옵션 사용: ${ARGS[*]}"
    usage
fi


PATTERNS=(
    # SQL Injection (기존 + 보강)
    "SQL_INJECTION:.*' OR '1'='1"
    "SQL_INJECTION:.*(\b(UNION|SELECT)\b.{1,100}?\b(FROM|SLEEP|BENCHMARK|PG_SLEEP|WAITFOR)\b)"
    "SQL_INJECTION:.*(information_schema|pg_catalog|mysql\.user|sys\.tables|sysobjects)"
    "SQL_INJECTION:.*(SLEEP\(|BENCHMARK\(|pg_sleep\(|WAITFOR DELAY)"
    "SQL_INJECTION:.*(--|#|/\*|\*/|;).*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\b"
    "SQL_INJECTION:.*(xp_cmdshell|sp_configure|OPENROWSET|OPENDATASOURCE)"
    "SQL_INJECTION_NOSQL:.*([$]ne|[$]gt|[$]lt|[$]regex|[$]where)"

    # XSS (Cross-Site Scripting) (기존 + 보강)
    "XSS:.*<script\b[^>]*>.*?</script\b[^>]*>"
    "XSS:.*<img\b[^>]*\b(src|onerror|onload)\s*=\s*[^>]*javascript:[^>]+>"
    "XSS:.*<[a-zA-Z]+\b[^>]*\b(on\w+)\s*=\s*[^>]*[^'\"\s>]+"
    "XSS:.*<iframe\b[^>]*\b(src|srcdoc)\s*=\s*[^>]*javascript:[^>]+>"
    "XSS:.*(alert\(|confirm\(|prompt\(|document\.cookie|document\.write\(|window\.location)"
    "XSS:.*(expression\(|eval\(|setTimeout\(|setInterval\()"
    "XSS_ENCODED:.*(%3Cscript|%3Cimg|%3Csvg|%253Cscript|<script|<script)"
    "XSS_DOM:.*(#|location\.hash\s*=).*(<script>|javascript:)"

    # Path Traversal / LFI (Local File Inclusion) (기존 + 보강)
    "PATH_TRAVERSAL_LFI:.*(\.\.[/\\]|\.%2e%2e[%2f%5c]|\.%252e%252e[%252f%255c])"
    "PATH_TRAVERSAL_LFI:.*(etc/passwd|boot\.ini|win\.ini|system32/drivers/etc/hosts)"
    "PATH_TRAVERSAL_LFI:.*(WEB-INF/web\.xml|META-INF/MANIFEST\.MF)"
    "PATH_TRAVERSAL_LFI:.*(\%00|\0)"

    # RFI (Remote File Inclusion) (기존 + 보강)
    "RFI:.*(include|require|include_once|require_once)\s*[_A-Z0-9\[\]\"']*\s*=\s*(ht|f)tps?://[^&?\s]+"
    "RFI:.*(include|require|include_once|require_once)\s*[_A-Z0-9\[\]\"']*\s*=\s*(php|data|expect)://[^&?\s]+"

    # Command Injection (기존 + 보강)
    "CMD_INJECTION:.*(;|%3B|\n|%0A|\r|%0D|[\`]|[$]\(|\&\&|\|\|)"
    "CMD_INJECTION:.*(cmd=|exec=|command=|system=|passthru=|shell_exec=|popen=|pcntl_exec|eval\(|assert\()"
    "CMD_INJECTION:.*(cat\s+/etc/passwd|whoami|uname\s+-a|id|ls\s+-la|netstat|ifconfig|ipconfig|ping\s+-c\s+\d)"
    "CMD_INJECTION:.*(nc\s+-l\s+-p|ncat|powershell|bash\s+-c|perl\s+-e|python\s+-c|ruby\s+-e)"

    # Sensitive File Access (기존 + 보강)
    "SENSITIVE_FILE_ACCESS:.*wp-config\.php"
    "SENSITIVE_FILE_ACCESS:.*(\.env|\.htpasswd|\.htaccess|\.git/config|config\.php|settings\.php|localsettings\.php|credentials|database\.yml|secrets\.yml)"
    "SENSITIVE_FILE_ACCESS:.*(\.pem|\.key|\.p12|\.crt|\.csr|\.jks)"
    "SENSITIVE_FILE_ACCESS:.*(phpinfo\.php|test\.php|info\.php|status\?full|server-status|manager/html)"
    "SENSITIVE_FILE_ACCESS:.*(web\.config|appsettings\.json)"

    # Sensitive Backup File Access (기존 + 보강)
    "SENSITIVE_FILE_BACKUP:.*(\.(bak|backup|old|orig|sql|config|conf|zip|tar\.gz|tgz|swp|~|save|copy|dev|prod|staging|bkp|bk))([\?&]|$)"

    # Directory Listing (유지)
    "DIRECTORY_LISTING:.*(Index of /|parent directory)"

    # SSRF (Server-Side Request Forgery) (기존 + 보강)
    "SSRF:.*(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)"
    "SSRF:.*(169\.254\.169\.254|metadata\.google\.internal|instance-data/latest/)"
    "SSRF:.*(url=|uri=|target=|dest=|file=|path=|host=|data=|feed=|image_url=).*(file:///|dict://|sftp://|ldap://|gopher://|jar://)"
    "SSRF:.*(url=|uri=|target=|dest=).*(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"

    # XXE (XML External Entity) Injection (기존 + 보강)
    "XXE_INJECTION:.*(<!ENTITY\s+[^>]*\s+(SYSTEM|PUBLIC)\s+[\"'][^\"']*[\"']>)"
    "XXE_INJECTION:.*(<!ENTITY\s+%\s+[^>]*\s+SYSTEM)"
    "XXE_INJECTION:.*(xxe_payload|ENTITY\s+xxe)"

    # Log4Shell (CVE-2021-44228) (유지)
    "LOG4J_JNDI_LOOKUP:.*\\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds):"

    # Spring4Shell (CVE-2022-22965) (유지)
    "SPRING4SHELL_RCE:.*class\.module\.classLoader"

    # Insecure Deserialization
    "DESERIALIZATION_PHP_OBJECT:.*O:[0-9]+:\""
    "DESERIALIZATION_JAVA_OBJECT:.*( rO0ABXNy|aced0005|ysoserial| Javassist\.CtClass|weblogic\.jms\.common\.StreamMessageImpl)"

    # File Upload Vulnerabilities
    "FILE_UPLOAD_VULN:.*POST .*/(upload|files|uploads|tmp|temp|images)/.*\.(php[3457s]?|phtml|phar|aspx?|jspx?|sh|exe|dll|cgi|pl|py|rb|war|jar)(\.[^./]+)*"
    "FILE_UPLOAD_VULN:.*Content-Disposition:.*\bfilename\s*=\s*[\"'].*\.(php|jsp|asp|sh)[\"']"

    # Authentication Bypass
    "AUTH_BYPASS:.*(admin_bypass|is_admin=(true|1)|role=(admin|root)|user_level=0|debug_mode=1)"
    "AUTH_BYPASS:.*(X-Forwarded-For:\s*127\.0\.0\.1|X-Original-URL:|X-Rewrite-URL:|Authorization:\s*Basic\s*YWRtaW46YWRtaW4=)"

    # Vulnerable Component Access
    "VULN_COMPONENT_ACCESS:.*(/phpmyadmin/|/pma/|/wp-admin/|/admin/|/manager/html|/jmx-console/|/web-console/|struts/dojo/)"

    # Open Redirect
    "OPEN_REDIRECT:.*(redirect=|url=|next=|location=|goto=|target=|return=|return_to=|checkout_url=)(https?%3A%2F%2F|%2F%2F|\\\\|%5C%5C)[^/\\s?&][^\"'<>]+"

    # Information Disclosure / Debug Mode
    "INFO_DISCLOSURE_DEBUG:.*(debug=(true|1)|TRACE\s+/|TRACK\s+/|X-Debug-Token:|phpinfo\(\))"
    "VERBOSE_ERROR_MESSAGES:.*(Stack Trace|Traceback \(most recent call last\)|PHP Fatal error:|Syntax error near|ORA-\d{5}:|java\.lang\.|Warning: Division by zero|Undefined index:)"

    # Log Injection
    "LOG_INJECTION:.*(%0d|%0a|\\r|\\n|\r\n)"

    # Server-Side Template Injection (SSTI)
    "SSTI:.*(\{\{.*\}\}|\{\%.*\%\}|<%=.*%>|[$]\{[^\}]+\}|#\{[^\}]+\})"
    "SSTI:.*(config.SECRET_KEY|settings.SECRET_KEY|getattribute|lipsum|self.__init__|class.__bases__|mro\(\))"

    # Prototype Pollution
    "PROTOTYPE_POLLUTION:.*(__proto__|constructor\.prototype|Object\.prototype).*\s*=\s*\{"

    # HTTP Request Smuggling / Desync
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
    case "$type_code" in
        "SQL_INJECTION") description="SQL Injection: 데이터베이스 쿼리 조작 시도. 입력값 검증 및 Prepared Statement 사용 권고." ;;
        "SQL_INJECTION_NOSQL") description="NoSQL Injection: NoSQL 데이터베이스 쿼리 조작 시도 (예: MongoDB). 입력값 검증 및 연산자 사용 주의." ;;
        "XSS") description="Cross-Site Scripting (XSS): 악성 스크립트 주입 시도. 출력값 인코딩 및 Content Security Policy(CSP) 적용 권고." ;;
        "XSS_ENCODED") description="Encoded XSS Attempt: 인코딩된 악성 스크립트 주입 시도. 디코딩 후 검증 및 출력값 인코딩 필요." ;;
        "XSS_DOM") description="DOM-based XSS Attempt: 클라이언트 측 스크립트를 통한 DOM 조작 시도. 안전한 DOM API 사용 및 입력값 검증." ;;
        "PATH_TRAVERSAL_LFI") description="Path Traversal/LFI: 허가되지 않은 파일 접근 시도. 사용자 입력 경로 검증 및 접근 권한 최소화 권고." ;;
        "RFI") description="Remote File Inclusion (RFI): 외부 악성 파일 실행 시도. 파일 포함 기능 사용 시 화이트리스트 기반 검증 권고." ;;
        "CMD_INJECTION") description="Command Injection: 서버 명령어 실행 시도. 시스템 명령어 호출 시 사용자 입력 직접 사용 금지 및 API 사용 권고." ;;
        "SENSITIVE_FILE_ACCESS") description="Sensitive File Access: 설정 파일, 키 파일 등 민감 정보 접근 시도. 접근 통제 강화 및 불필요한 파일 노출 금지." ;;
        "SENSITIVE_FILE_BACKUP") description="Sensitive Backup File Access: 백업/임시 파일 접근 시도. 웹 루트 외부에 백업 저장 및 접근 통제." ;;
        "DIRECTORY_LISTING") description="Directory Listing: 디렉터리 목록 노출. 웹 서버 설정에서 비활성화 권고." ;;
        "SSRF") description="Server-Side Request Forgery (SSRF): 서버를 이용한 내부/외부 자원 접근 시도. URL 검증 및 내부 IP 접근 제한 권고." ;;
        "XXE_INJECTION") description="XML External Entity (XXE) Injection: XML 외부 엔티티 처리 취약점 악용 시도. XML 파서의 외부 엔티티 기능 비활성화 권고." ;;
        "LOG4J_JNDI_LOOKUP") description="Log4Shell (CVE-2021-44228): Log4j 라이브러리 JNDI 주입 취약점 악용 시도. Log4j 최신 버전 업데이트 또는 JndiLookup 클래스 제거." ;;
        "SPRING4SHELL_RCE") description="Spring4Shell (CVE-2022-22965): Spring Framework RCE 취약점 악용 시도. Spring Framework/JDK 최신 버전 업데이트." ;;
        "DESERIALIZATION_PHP_OBJECT") description="Insecure Deserialization (PHP): 안전하지 않은 PHP 객체 역직렬화 시도. 신뢰할 수 없는 데이터 역직렬화 금지." ;;
        "DESERIALIZATION_JAVA_OBJECT") description="Insecure Deserialization (Java): 안전하지 않은 Java 객체 역직렬화 시도. 신뢰할 수 없는 데이터 역직렬화 금지 및 라이브러리 업데이트." ;;
        "FILE_UPLOAD_VULN") description="Malicious File Upload: 악성 파일(웹쉘 등) 업로드 시도. 파일 확장자/타입 검증, 저장 경로 웹 루트 외부 지정, 실행 권한 제거." ;;
        "AUTH_BYPASS") description="Authentication Bypass Attempt: 인증 우회 시도. 강력한 인증 메커니즘 적용 및 접근 통제 검증." ;;
        "VULN_COMPONENT_ACCESS") description="Sensitive Component Access: 관리 도구, 취약한 컴포넌트 접근 시도. 불필요한 컴포넌트 제거 및 접근 통제 강화." ;;
        "OPEN_REDIRECT") description="Open Redirect: 신뢰할 수 없는 외부 사이트로 리디렉션 시도. 리디렉션 URL 화이트리스트 검증." ;;
        "INFO_DISCLOSURE_DEBUG") description="Debug Mode Enabled: 디버그 모드 활성화로 인한 정보 노출. 운영 환경에서 디버그 모드 비활성화." ;;
        "VERBOSE_ERROR_MESSAGES") description="Verbose Error Messages: 상세 오류 메시지로 인한 내부 정보 노출. 일반화된 오류 메시지 사용." ;;
        "LOG_INJECTION") description="Log Injection / CRLF Injection: 로그 파일 조작 또는 HTTP 응답 분할 시도. 입력값 필터링 및 CRLF 문자 제거." ;;
        "SSTI") description="Server-Side Template Injection (SSTI): 서버 측 템플릿을 이용한 코드 실행 시도. 사용자 입력 템플릿 사용 금지 또는 안전한 샌드박싱 적용." ;;
        "PROTOTYPE_POLLUTION") description="Prototype Pollution: JavaScript 프로토타입 오염을 통한 속성 조작 또는 코드 실행 시도. 객체 병합 시 주의 및 라이브러리 업데이트." ;;
        "HTTP_DESYNC") description="HTTP Request Smuggling/Desync: HTTP 요청 해석 불일치를 이용한 공격 시도. 프록시 및 웹 서버 설정 검토 및 업데이트." ;;
        *) description="$type_code: (설명 없음)" ;;
    esac
    echo "$description"
}

# 입력값 유효성 검사
if [ ! -f "$LOG_FILE" ]; then
    echo "오류: 로그 파일 '$LOG_FILE'을(를) 찾을 수 없습니다."
    usage
fi
if ! [[ "$TOP_N_DATE" =~ ^[0-9]+$ ]]; then
    echo "오류: 일별 Top N 값(--top-date)은 숫자여야 합니다. 입력값: $TOP_N_DATE"
    usage
fi
if ! [[ "$TOP_N_IP" =~ ^[0-9]+$ ]]; then
    echo "오류: IP별 Top N 값(--top-ip)은 숫자여야 합니다. 입력값: $TOP_N_IP"
    usage
fi
if ! [[ "$TOP_N_URL" =~ ^[0-9]+$ ]]; then
    echo "오류: URL별 Top N 값(--top-url)은 숫자여야 합니다. 입력값: $TOP_N_URL"
    usage
fi
if ! [[ "$TOP_N_REFERER" =~ ^[0-9]+$ ]]; then
    echo "오류: Referer별 Top N 값(--top-referer)은 숫자여야 합니다. 입력값: $TOP_N_REFERER"
    usage
fi

# 파일 초기화
if [ -f "$REPORT_FILE" ]; then rm "$REPORT_FILE"; fi
if [ -f "$SUMMARY_FILE" ]; then rm "$SUMMARY_FILE"; fi
# 블랙리스트 파일은 기존 내용을 유지하고 추가할 수도 있지만, 여기서는 매번 새로 생성하도록 함
if [ -f "$BLACKLIST_FILE" ]; then rm "$BLACKLIST_FILE"; fi


# 상세 리포트 파일 헤더 작성
echo "보안 감사 리포트 (상세 로그) - $(date)" > "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "분석 대상 로그 파일: $LOG_FILE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 요약 리포트 파일 헤더 작성
echo "보안 감사 요약 - $(date)" > "$SUMMARY_FILE"
echo "========================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "분석 대상 로그 파일: $LOG_FILE" >> "$SUMMARY_FILE"
echo "일별 탐지 요약 표시 개수: $TOP_N_DATE" >> "$SUMMARY_FILE"
echo "IP 주소별 탐지 요약 표시 개수: $TOP_N_IP" >> "$SUMMARY_FILE"
echo "URL별 탐지 요약 표시 개수: $TOP_N_URL" >> "$SUMMARY_FILE"
echo "Referer별 탐지 요약 표시 개수: $TOP_N_REFERER" >> "$SUMMARY_FILE"
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
    # IP별 요약
    extracted_ips_raw_for_summary=$(grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_ips_raw_for_summary; do ip_summary_data="${ip_summary_data}${item};"; done
    if [ -n "$ip_summary_data" ]; then
        top_ips_for_summary=$(echo "$ip_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n "$TOP_N_IP" | awk '{print $2 "=" $1}')
    fi

    # 일별 요약
    extracted_dates_raw_for_summary=$(grep -o -E "$DATE_REGEX" "$TEMP_MATCHED_LOGS" | sed -E 's/^\[//' | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_dates_raw_for_summary; do daily_summary_data="${daily_summary_data}${item};"; done
    if [ -n "$daily_summary_data" ]; then
         top_dates_for_summary=$(echo "$daily_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n "$TOP_N_DATE" | awk '{print $2 "=" $1}')
    fi

    # URL별 요약
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

    # Referer별 요약
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

# 상세 리포트 파일 (audit_report.txt) 작성
if [ "$found_any_threat" = true ]; then
    for current_threat_type_code in "${unique_threat_types_in_order[@]}"; do
        type_total_detections_str=$(echo "$threat_type_summary_data" | grep -o -E "${current_threat_type_code}=[^;]+" | cut -d'=' -f2)
        type_total_detections=${type_total_detections_str:-0}
        if [ "$type_total_detections" -gt 0 ]; then
            threat_desc_full=$(get_threat_description "$current_threat_type_code")
            threat_name_for_report=$(echo "$threat_desc_full" | cut -d':' -f1)
            echo "----------------------------------------" >> "$REPORT_FILE"
            echo "위협 유형: $threat_name_for_report (코드: $current_threat_type_code, 총 탐지된 로그 라인 수: $type_total_detections)" >> "$REPORT_FILE"
            echo "설명: $(echo "$threat_desc_full" | cut -d':' -f2-)" >> "$REPORT_FILE"
            echo "탐지된 로그:" >> "$REPORT_FILE"
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


# 요약 리포트 파일 (summary.txt) 작성
if [ "$found_any_threat" = true ]; then
    echo "===== 감사 결과 요약 =====" >> "$SUMMARY_FILE"
    echo "총 매칭된 로그 라인 수 (모든 패턴 합계, 중복 포함 가능): $total_log_lines_matched_overall" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"

    echo "--- 웹 취약점 점검 결과 (위협 유형별 탐지 현황) ---" >> "$SUMMARY_FILE"
    OLD_IFS_SUMMARY="$IFS"; IFS=';'
    for item in $threat_type_summary_data; do
        if [ -n "$item" ]; then
            threat_type_code_summary=$(echo "$item" | cut -d'=' -f1)
            threat_count_summary=$(echo "$item" | cut -d'=' -f2)
            if [ "$threat_count_summary" -gt 0 ]; then
                full_desc_summary=$(get_threat_description "$threat_type_code_summary")
                name_for_summary=$(echo "$full_desc_summary" | cut -d':' -f1)
                printf "  - %-30s : %s 개의 로그 라인에서 탐지됨\n" "$name_for_summary ($threat_type_code_summary)" "$threat_count_summary" >> "$SUMMARY_FILE"
            fi
        fi
    done
    IFS="$OLD_IFS_SUMMARY"
    echo "" >> "$SUMMARY_FILE"

    if [ -n "$top_dates_for_summary" ]; then
        echo "--- 일별 탐지 현황 (Top $TOP_N_DATE) ---" >> "$SUMMARY_FILE"
        while IFS="=" read -r date count; do
            if [ -n "$date" ] && [ -n "$count" ]; then
                 printf "  - %-15s : %s 건\n" "$date" "$count" >> "$SUMMARY_FILE"
            fi
        done <<< "$top_dates_for_summary"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_ips_for_summary" ]; then
        echo "--- IP 주소별 탐지 현황 (Top $TOP_N_IP) ---" >> "$SUMMARY_FILE"
        while IFS="=" read -r ip count; do
            if [ -n "$ip" ] && [ -n "$count" ]; then
                 printf "  - %-15s : %s 건\n" "$ip" "$count" >> "$SUMMARY_FILE"
            fi
        done <<< "$top_ips_for_summary"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_urls_for_summary_raw" ]; then
        echo "--- URL별 탐지 현황 (Top $TOP_N_URL) ---" >> "$SUMMARY_FILE"
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
                    printf "  - %s : %s 건\n" "$display_url" "$count" >> "$SUMMARY_FILE"
                else
                    if [ ${#encoded_url} -gt 70 ]; then
                        display_url="${encoded_url:0:67}..."
                    else
                        display_url="$encoded_url"
                    fi
                    printf "  - %s (decoding_failed) : %s 건\n" "$display_url" "$count" >> "$SUMMARY_FILE"
                fi
            fi
        done <<< "$top_urls_for_summary_raw"
        echo "" >> "$SUMMARY_FILE"
    fi

    if [ -n "$top_referers_for_summary_raw" ]; then
        echo "--- Referer별 탐지 현황 (Top $TOP_N_REFERER) ---" >> "$SUMMARY_FILE"
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
                    printf "  - %s : %s 건\n" "$display_referer" "$count" >> "$SUMMARY_FILE"
                else
                    if [ ${#encoded_referer} -gt 70 ]; then
                        display_referer="${encoded_referer:0:67}..."
                    else
                        display_referer="$encoded_referer"
                    fi
                    printf "  - %s (decoding_failed) : %s 건\n" "$display_referer" "$count" >> "$SUMMARY_FILE"
                fi
            fi
        done <<< "$top_referers_for_summary_raw"
        echo "" >> "$SUMMARY_FILE"
    fi

    echo "=========================" >> "$SUMMARY_FILE"
    echo "상세 로그는 $REPORT_FILE 파일을 확인하세요." >> "$SUMMARY_FILE"
else
    echo "탐지된 보안 위협 로그가 없습니다." >> "$SUMMARY_FILE"
    echo "=========================" >> "$SUMMARY_FILE"
fi


# 블랙리스트 파일 생성
if [ "$found_any_threat" = true ] && [ -f "$TEMP_MATCHED_LOGS" ] && [ -s "$TEMP_MATCHED_LOGS" ]; then
    grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort -u | awk '{print "- " $0}' > "$BLACKLIST_FILE"
    echo "IP 블랙리스트 생성 완료: $BLACKLIST_FILE"
else
    # 위협이 탐지되지 않았거나 TEMP_MATCHED_LOGS가 비어있으면 빈 블랙리스트 파일 생성
    > "$BLACKLIST_FILE" 
    echo "탐지된 위협이 없어 빈 IP 블랙리스트 파일 생성: $BLACKLIST_FILE"
fi


# 터미널 최종 출력
if [ "$found_any_threat" = false ]; then
    echo "탐지된 보안 위협 로그가 없습니다."
    echo "리포트 생성 완료: $REPORT_FILE, $SUMMARY_FILE, $BLACKLIST_FILE"
else
    echo "리포트 생성 완료: $REPORT_FILE, $SUMMARY_FILE, $BLACKLIST_FILE"
    echo ""
    cat "$SUMMARY_FILE"
fi

if [ -f "$TEMP_MATCHED_LOGS" ]; then
    rm -f "$TEMP_MATCHED_LOGS"
fi