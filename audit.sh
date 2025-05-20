#!/bin/bash

LOG_FILE="access.log"
REPORT_FILE="audit_report.txt"
PATTERNS=(
    # --- SQL Injection (매우 중요) ---
    "SQL_INJECTION:.*' OR '1'='1"
    "SQL_INJECTION:.*UNION SELECT"
    "SQL_INJECTION:.*(information_schema|pg_catalog|mysql\.user)"
    "SQL_INJECTION:.*(SLEEP\(|BENCHMARK\(|pg_sleep\(|WAITFOR DELAY)"

    # --- Cross-Site Scripting (XSS - 주요 패턴) ---
    "XSS:.*<script>.*</script>"
    "XSS:.*javascript:"
    "XSS:.*onerror="
    "XSS:.*onload="
    "XSS:.*<iframe.*src="

    # --- Path Traversal / Local File Inclusion (LFI) (매우 중요) ---
    "PATH_TRAVERSAL_LFI:.*(\.\./|\.%2e%2e%2f|\.%252e%252e%252f)"
    "PATH_TRAVERSAL_LFI:.*etc/passwd"
    "PATH_TRAVERSAL_LFI:.*WEB-INF/web\.xml"

    # --- Remote File Inclusion (RFI) (매우 중요) ---
    "RFI:.*(include|require).*=(http://|https://|ftp://|php://input|php://filter)"

    # --- Command Injection (매우 중요) ---
    "CMD_INJECTION:.*(cmd=|exec=|command=|system=|passthru=|shell_exec=|popen=|pcntl_exec)"
    "CMD_INJECTION:.*(&&|\|\||;|%0a|%0d|\\\`|\$\(|\$\{)" # 쉘 메타 문자
    "CMD_INJECTION:.*(cat /etc/passwd|whoami|uname -a|id)" # 흔한 명령어

    # --- Sensitive File & Directory Access (중요 정보 노출) ---
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

    # --- Directory Listing (정보 노출) ---
    "DIRECTORY_LISTING:.*Index of /"
    "DIRECTORY_LISTING:.*parent directory"

    # --- Server-Side Request Forgery (SSRF) (중요) ---
    "SSRF:.*(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\])"
    "SSRF:.*(url=|uri=|target=|dest=|file=|path=).*(file:///|http://127|http://localhost|http://169\.254)"

    # --- XML External Entity (XXE) Injection (중요) ---
    "XXE_INJECTION:.*<!ENTITY.*SYSTEM.*>"

    # --- Log4Shell (JNDI Injection - 특정 주요 취약점) ---
    "LOG4J_JNDI_LOOKUP:.*\\$\{jndi:(ldap|ldaps|rmi|dns):"

    # --- Spring4Shell (특정 주요 취약점) ---
    "SPRING4SHELL_RCE:.*class\.module\.classLoader"

    # --- Insecure Deserialization (PHP 예시 - 사용 환경에 따라 추가) ---
    "DESERIALIZATION_PHP_OBJECT:.*O:[0-9]+:\""

    # --- File Upload Vulnerabilities (실행 파일 업로드 시도) ---
    "FILE_UPLOAD_VULN:.*POST .*/(upload|files|uploads)/.*(\.php[3457s]?|\.phtml|\.phar|\.jsp|\.asp|\.aspx|\.sh|\.exe|\.cgi|\.pl)"

    # --- Authentication Bypass / Admin Panel Access (중요) ---
    "AUTH_BYPASS:.*(admin_bypass|is_admin=true|role=admin)"
    "VULN_COMPONENT_ACCESS:.*(/phpmyadmin/|/pma/|/wp-admin/|/admin/|/manager/html)"

    # --- Open Redirect (주의 필요, 필수적인 패턴 위주) ---
    "OPEN_REDIRECT:.*(redirect=|url=|next=|location=|goto=)(http://|https://|//)[^/\\s?&]"

    # --- Debug Mode / Verbose Errors (정보 노출) ---
    "INFO_DISCLOSURE_DEBUG:.*debug=(true|1)"
    "VERBOSE_ERROR_MESSAGES:.*(Stack Trace|Traceback \(most recent call last\)|PHP Fatal error:|Syntax error near)"

    # --- Log Injection (CRLF) ---
    "LOG_INJECTION:.*(%0d|%0a|\\r|\\n)"
)

IP_REGEX='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

if [ -f "$REPORT_FILE" ]; then
    rm "$REPORT_FILE"
fi

echo "보안 감사 리포트 - $(date)" > "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "분석 대상 로그 파일: $LOG_FILE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

found_any_threat=false
total_log_lines_matched_overall=0
threat_type_summary_data=""
ip_summary_data=""
top_ips_for_summary="" # 터미널 요약용 Top 10 IP 저장

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
            # 임시 파일에는 현재 위협 유형에 매칭되는 로그만 추가 (IP 집계 정확도 향상)
            # 단, 이렇게 하면 TEMP_MATCHED_LOGS는 각 위협 유형별로 한 번씩만 로그를 담게 됨
            # -> IP 집계 시, 한 IP가 여러 위협 유형에 걸쳐 활동했으면, 각 위협 유형별로 한 번씩만 카운트될 수 있음.
            #    이는 "IP별 의심 로그 발생 횟수"가 아니라 "IP가 관련된 위협 유형의 수"에 가까워질 수 있음.
            #    "IP별 의심 로그 발생 횟수"를 원하면 모든 패턴 매칭 로그를 TEMP_MATCHED_LOGS에 넣어야 함.
            #    일단 이전 로직(모든 패턴 매칭 로그)을 유지하고, IP 집계 시 TEMP_MATCHED_LOGS를 한 번만 채우도록 수정.
            # grep_output_for_type=$(grep -E -i "$pattern" "$LOG_FILE")
            # if [ -n "$grep_output_for_type" ]; then
            #     echo "$grep_output_for_type" >> "$TEMP_MATCHED_LOGS"
            # fi
            # 위협 유형별 합계는 이전처럼 각 패턴의 grep -c 결과로.
            current_pattern_detection_count=$(grep -E -i -c "$pattern" "$LOG_FILE")
            type_specific_total_count=$((type_specific_total_count + current_pattern_detection_count))
        fi
    done
    if [ "$type_specific_total_count" -gt 0 ]; then
        threat_type_summary_data="${threat_type_summary_data}${current_threat_type}=${type_specific_total_count};"
        found_any_threat=true
    fi
done

# TEMP_MATCHED_LOGS 파일 채우기 (모든 패턴에 대해 한 번만)
# 이렇게 해야 IP별 "총 의심 로그 발생 횟수"가 정확해짐
if [ "$found_any_threat" = true ]; then
    for pattern_item in "${PATTERNS[@]}"; do
        IFS=":" read -r _ pattern <<< "$pattern_item" # threat_type은 여기서 불필요
         if [ -z "$pattern" ]; then continue; fi
        grep_output_for_ip_aggregation=$(grep -E -i "$pattern" "$LOG_FILE")
        if [ -n "$grep_output_for_ip_aggregation" ]; then
            echo "$grep_output_for_ip_aggregation" >> "$TEMP_MATCHED_LOGS"
        fi
    done
fi


for pattern_item in "${PATTERNS[@]}"; do
    IFS=":" read -r _ pattern <<< "$pattern_item"
    if [ -z "$pattern" ]; then continue; fi
    count_for_this_pattern=$(grep -E -i -c "$pattern" "$LOG_FILE")
    total_log_lines_matched_overall=$((total_log_lines_matched_overall + count_for_this_pattern))
done

if [ -f "$TEMP_MATCHED_LOGS" ] && [ -s "$TEMP_MATCHED_LOGS" ]; then
    # IP 주소 추출 및 정렬, 건수 계산 (이전과 동일)
    # extracted_ips_raw: "1.2.3.4=10\n5.6.7.8=20\n..." 형태의 멀티라인 문자열
    extracted_ips_raw=$(grep -o -E "$IP_REGEX" "$TEMP_MATCHED_LOGS" | sort | uniq -c | awk '{print $2 "=" $1}')
    
    # ip_summary_data 구성 (리포트 파일용 - 전체)
    for item in $extracted_ips_raw; do
        ip_summary_data="${ip_summary_data}${item};"
    done

    # top_ips_for_summary 구성 (터미널 요약용 - Top 10)
    # extracted_ips_raw를 건수 기준으로 내림차순 정렬 후 상위 10개만 가져옴
    top_ips_for_summary=$(echo "$extracted_ips_raw" | awk -F'=' '{print $2 " " $1}' | sort -nr | head -n 10 | awk '{print $2 "=" $1}')

fi
rm -f "$TEMP_MATCHED_LOGS"

# 2단계: 리포트 파일 작성
if [ "$found_any_threat" = true ]; then
    for current_threat_type in "${unique_threat_types_in_order[@]}"; do
        type_total_detections_str=$(echo "$threat_type_summary_data" | grep -o -E "${current_threat_type}=[^;]+" | cut -d'=' -f2)
        type_total_detections=${type_total_detections_str:-0}

        if [ "$type_total_detections" -gt 0 ]; then
            echo "----------------------------------------" >> "$REPORT_FILE"
            echo "위협 유형: $current_threat_type (총 탐지된 로그 라인 수: $type_total_detections)" >> "$REPORT_FILE"
            echo "탐지된 로그:" >> "$REPORT_FILE"

            for pattern_item_inner in "${PATTERNS[@]}"; do
                IFS=":" read -r inner_threat_type inner_pattern <<< "$pattern_item_inner"
                 if [ -z "$inner_threat_type" ]; then continue; fi
                if [[ "$inner_threat_type" == "$current_threat_type" ]]; then
                    grep_output=$(grep -E -i "$inner_pattern" "$LOG_FILE")
                    if [ -n "$grep_output" ]; then
                        echo "$grep_output" >> "$REPORT_FILE"
                    fi
                fi
            done
            echo "" >> "$REPORT_FILE"
        fi
    done

    if [ -n "$ip_summary_data" ]; then
        echo "----------------------------------------" >> "$REPORT_FILE"
        echo "IP 주소별 탐지 현황 (의심 로그 발생 횟수)" >> "$REPORT_FILE"
        echo "----------------------------------------" >> "$REPORT_FILE"
        OLD_IFS_IP="$IFS"
        IFS=';'
        echo "$ip_summary_data" | tr ';' '\n' | grep . | awk -F'=' '{print $2 " " $1}' | sort -nr | awk '{printf "  - %-15s : %s 건\n", $2, $1}' >> "$REPORT_FILE"
        IFS="$OLD_IFS_IP"
        echo "" >> "$REPORT_FILE"
    fi
fi

echo "========================================" >> "$REPORT_FILE"

# 3단계: 최종 요약 출력
if [ "$found_any_threat" = false ]; then
    echo "탐지된 보안 위협 로그가 없습니다." >> "$REPORT_FILE"
    echo "리포트 생성 완료: $REPORT_FILE"
    echo "분석 결과: 탐지된 보안 위협 로그가 없습니다."
else
    echo "리포트 생성 완료: $REPORT_FILE"
    echo ""
    echo "===== 감사 결과 요약 ====="
    echo "총 매칭된 로그 라인 수 (모든 패턴 합계, 중복 포함 가능): $total_log_lines_matched_overall"
    echo "--- 위협 유형별 탐지 현황 ---"
    OLD_IFS_SUMMARY="$IFS"
    IFS=';'
    for item in $threat_type_summary_data; do
        if [ -n "$item" ]; then
            threat_name=$(echo "$item" | cut -d'=' -f1)
            threat_count=$(echo "$item" | cut -d'=' -f2)
            if [ "$threat_count" -gt 0 ]; then
                printf "  - %-30s : %s 개의 로그 라인에서 탐지됨\n" "$threat_name" "$threat_count"
            fi
        fi
    done
    IFS="$OLD_IFS_SUMMARY"

    # IP 주소별 Top 10 탐지 현황 추가
    if [ -n "$top_ips_for_summary" ]; then
        echo "--- IP 주소별 탐지 현황 (Top 10) ---"
        # top_ips_for_summary는 이미 "IP=COUNT" 형태의 멀티라인 문자열이거나 공백으로 구분된 문자열일 수 있음
        # echo "$top_ips_for_summary" 를 파이프로 넘겨 처리
        echo "$top_ips_for_summary" | while IFS="=" read -r ip count; do
            if [ -n "$ip" ] && [ -n "$count" ]; then # IP와 count가 모두 있는지 확인
                 printf "  - %-15s : %s 건\n" "$ip" "$count"
            fi
        done
    fi

    echo "========================="
    echo "상세 내용은 $REPORT_FILE 파일을 확인하세요."
fi