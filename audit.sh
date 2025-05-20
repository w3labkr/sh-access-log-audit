#!/bin/bash

LOG_FILE="access.log"
REPORT_FILE="audit_report.txt"
PATTERNS=(
    "SQL_INJECTION:.*' OR '1'='1"
    "SQL_INJECTION:.*UNION SELECT"
    "SQL_INJECTION:.*(information_schema|pg_catalog|mysql\.user)"
    "SQL_INJECTION:.*(SLEEP\(|BENCHMARK\(|pg_sleep\(|WAITFOR DELAY)"
    "XSS:.*<script>.*</script>"
    "XSS:.*javascript:"
    "XSS:.*onerror="
    "XSS:.*onload="
    "XSS:.*<iframe.*src="
    "PATH_TRAVERSAL_LFI:.*(\.\./|\.%2e%2e%2f|\.%252e%252e%252f)"
    "PATH_TRAVERSAL_LFI:.*etc/passwd"
    "PATH_TRAVERSAL_LFI:.*WEB-INF/web\.xml"
    "RFI:.*(include|require).*=(http://|https://|ftp://|php://input|php://filter)"
    "CMD_INJECTION:.*(cmd=|exec=|command=|system=|passthru=|shell_exec=|popen=|pcntl_exec)"
    "CMD_INJECTION:.*(&&|\|\||;|%0a|%0d|\\\`|\$\(|\$\{)"
    "CMD_INJECTION:.*(cat /etc/passwd|whoami|uname -a|id)"
    "SENSITIVE_FILE_ACCESS:.*wp-login\.php"
    "SENSITIVE_FILE_ACCESS:.*\.env"
    "SENSITIVE_FILE_ACCESS:.*\.git/config"
    "SENSITIVE_FILE_ACCESS:.*\.pem"
    "SENSITIVE_FILE_ACCESS:.*\.key"
    "SENSITIVE_FILE_ACCESS:.*\.htaccess"
    "SENSITIVE_FILE_ACCESS:.*\.htpasswd"
    "SENSITIVE_FILE_ACCESS:.*phpinfo\.php"
    "SENSITIVE_FILE_ACCESS:.*server-status"
    "SENSITIVE_FILE_BACKUP:.*(\.bak|\.backup|\.old|\.orig|\.sql|\.config|\.conf|\.zip|\.tar\.gz|\.tgz|~)$"
    "DIRECTORY_LISTING:.*Index of /"
    "DIRECTORY_LISTING:.*parent directory"
    "SSRF:.*(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\])"
    "SSRF:.*(url=|uri=|target=|dest=|file=|path=).*(file:///|http://127|http://localhost|http://169\.254)"
    "XXE_INJECTION:.*<!ENTITY.*SYSTEM.*>"
    "LOG4J_JNDI_LOOKUP:.*\\$\{jndi:(ldap|ldaps|rmi|dns):"
    "SPRING4SHELL_RCE:.*class\.module\.classLoader"
    "DESERIALIZATION_PHP_OBJECT:.*O:[0-9]+:\""
    "FILE_UPLOAD_VULN:.*POST .*/(upload|files|uploads)/.*(\.php[3457s]?|\.phtml|\.phar|\.jsp|\.asp|\.aspx|\.sh|\.exe|\.cgi|\.pl)"
    "AUTH_BYPASS:.*(admin_bypass|is_admin=true|role=admin)"
    "VULN_COMPONENT_ACCESS:.*(/phpmyadmin/|/pma/|/wp-admin/|/admin/|/manager/html)"
    "OPEN_REDIRECT:.*(redirect=|url=|next=|location=|goto=)(http://|https://|//)[^/\\s?&]"
    "INFO_DISCLOSURE_DEBUG:.*debug=(true|1)"
    "VERBOSE_ERROR_MESSAGES:.*(Stack Trace|Traceback \(most recent call last\)|PHP Fatal error:|Syntax error near)"
    "LOG_INJECTION:.*(%0d|%0a|\\r|\\n)"
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
        "XSS") description="Cross-Site Scripting (XSS): 악성 스크립트 주입 시도. 출력값 인코딩 및 Content Security Policy(CSP) 적용 권고." ;;
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
        "DESERIALIZATION_PHP_OBJECT") description="Insecure Deserialization (PHP): 안전하지 않은 객체 역직렬화 시도. 신뢰할 수 없는 데이터 역직렬화 금지." ;;
        "FILE_UPLOAD_VULN") description="Malicious File Upload: 악성 파일(웹쉘 등) 업로드 시도. 파일 확장자/타입 검증, 저장 경로 웹 루트 외부 지정, 실행 권한 제거." ;;
        "AUTH_BYPASS") description="Authentication Bypass Attempt: 인증 우회 시도. 강력한 인증 메커니즘 적용 및 접근 통제 검증." ;;
        "VULN_COMPONENT_ACCESS") description="Sensitive Component Access: 관리 도구, 취약한 컴포넌트 접근 시도. 불필요한 컴포넌트 제거 및 접근 통제 강화." ;;
        "OPEN_REDIRECT") description="Open Redirect: 신뢰할 수 없는 외부 사이트로 리디렉션 시도. 리디렉션 URL 화이트리스트 검증." ;;
        "INFO_DISCLOSURE_DEBUG") description="Debug Mode Enabled: 디버그 모드 활성화로 인한 정보 노출. 운영 환경에서 디버그 모드 비활성화." ;;
        "VERBOSE_ERROR_MESSAGES") description="Verbose Error Messages: 상세 오류 메시지로 인한 내부 정보 노출. 일반화된 오류 메시지 사용." ;;
        "LOG_INJECTION") description="Log Injection / CRLF Injection: 로그 파일 조작 또는 HTTP 응답 분할 시도. 입력값 필터링 및 CRLF 문자 제거." ;;
        *) description="$type_code: (설명 없음)" ;;
    esac
    echo "$description"
}

if [ -f "$REPORT_FILE" ]; then rm "$REPORT_FILE"; fi
echo "보안 감사 리포트 - $(date)" > "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "분석 대상 로그 파일: $LOG_FILE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

found_any_threat=false
total_log_lines_matched_overall=0
threat_type_summary_data=""
ip_summary_data=""
daily_summary_data=""
top_ips_for_summary=""

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
    extracted_ips_raw=$(grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_ips_raw; do ip_summary_data="${ip_summary_data}${item};"; done
    top_ips_for_summary=$(echo "$extracted_ips_raw" | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n 10 | awk '{print $2 "=" $1}')

    extracted_dates_raw=$(grep -o -E "$DATE_REGEX" "$TEMP_MATCHED_LOGS" | sed -E 's/^\[//' | sort | uniq -c | awk '{print $2 "=" $1}')
    for item in $extracted_dates_raw; do daily_summary_data="${daily_summary_data}${item};"; done
fi

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

    if [ -n "$daily_summary_data" ]; then
        echo "----------------------------------------" >> "$REPORT_FILE"
        echo "일별 탐지 현황 (의심 로그 발생 횟수)" >> "$REPORT_FILE"
        echo "----------------------------------------" >> "$REPORT_FILE"
        OLD_IFS_DAILY="$IFS"; IFS=';'
        echo "$daily_summary_data" | tr ';' '\n' | grep . | sort | awk -F'=' '{printf "  - %-15s : %s 건\n", $1, $2}' >> "$REPORT_FILE"
        IFS="$OLD_IFS_DAILY"; echo "" >> "$REPORT_FILE"
    fi

    if [ -n "$ip_summary_data" ]; then
        echo "----------------------------------------" >> "$REPORT_FILE"
        echo "IP 주소별 탐지 현황 (의심 로그 발생 횟수)" >> "$REPORT_FILE"
        echo "----------------------------------------" >> "$REPORT_FILE"
        OLD_IFS_IP="$IFS"; IFS=';'
        echo "$ip_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | awk '{printf "  - %-15s : %s 건\n", $2, $1}' >> "$REPORT_FILE"
        IFS="$OLD_IFS_IP"; echo "" >> "$REPORT_FILE"
    fi
fi
echo "========================================" >> "$REPORT_FILE"

if [ "$found_any_threat" = false ]; then
    echo "탐지된 보안 위협 로그가 없습니다."
    echo "리포트 생성 완료: $REPORT_FILE"
else
    echo "리포트 생성 완료: $REPORT_FILE"
    echo ""
    echo "===== 감사 결과 요약 ====="
    echo "총 매칭된 로그 라인 수 (모든 패턴 합계, 중복 포함 가능): $total_log_lines_matched_overall"
    
    echo "--- 웹 취약점 점검 결과 (위협 유형별 탐지 현황) ---"
    OLD_IFS_SUMMARY="$IFS"; IFS=';'
    for item in $threat_type_summary_data; do
        if [ -n "$item" ]; then
            threat_type_code_summary=$(echo "$item" | cut -d'=' -f1)
            threat_count_summary=$(echo "$item" | cut -d'=' -f2)
            if [ "$threat_count_summary" -gt 0 ]; then
                full_desc_summary=$(get_threat_description "$threat_type_code_summary")
                name_for_summary=$(echo "$full_desc_summary" | cut -d':' -f1)
                printf "  - %-30s : %s 개의 로그 라인에서 탐지됨\n" "$name_for_summary ($threat_type_code_summary)" "$threat_count_summary"
            fi
        fi
    done
    IFS="$OLD_IFS_SUMMARY"

    if [ -n "$daily_summary_data" ]; then
        echo "--- 일별 탐지 현황 (Top 10일, 건수 기준) ---"
        OLD_IFS_DAILY_SUMMARY="$IFS"; IFS=';'
        echo "$daily_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n 10 | awk '{printf "  - %-15s : %s 건\n", $2, $1}'
        IFS="$OLD_IFS_DAILY_SUMMARY"
    fi

    if [ -n "$top_ips_for_summary" ]; then
        echo "--- IP 주소별 탐지 현황 (Top 10) ---"
        echo "$top_ips_for_summary" | while IFS="=" read -r ip count; do
            if [ -n "$ip" ] && [ -n "$count" ]; then
                 printf "  - %-15s : %s 건\n" "$ip" "$count"
            fi
        done
    fi

    echo "========================="
    echo "상세 내용은 $REPORT_FILE 파일을 확인하세요."
fi

if [ -f "$TEMP_MATCHED_LOGS" ]; then
    rm -f "$TEMP_MATCHED_LOGS"
fi