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

# 이전 리포트 파일 삭제
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

# 위협 유형과 해당 유형의 총 탐지 수를 저장할 문자열 변수들
# (연관 배열 대용)
# 예: "SQL_INJECTION=10;XSS=5;" 형태로 저장 후 파싱
threat_type_summary_data=""


# 1단계: 각 위협 유형별 총 매칭 로그 라인 수 계산
# PATTERNS에서 유니크한 threat_type 목록을 먼저 얻음
unique_threat_types_in_order=()
temp_seen_types="" # 문자열로 관리 "SQL_INJECTION XSS "
for pattern_item in "${PATTERNS[@]}"; do
    IFS=":" read -r threat_type _ <<< "$pattern_item"
    if [ -z "$threat_type" ]; then continue; fi

    # temp_seen_types에 threat_type이 없으면 unique_threat_types_in_order에 추가
    if ! echo "$temp_seen_types" | grep -q -w "$threat_type"; then
        unique_threat_types_in_order+=("$threat_type")
        temp_seen_types="$temp_seen_types$threat_type "
    fi
done
unset temp_seen_types

# 각 unique_threat_type에 대해 총 탐지 건수 계산
for current_threat_type in "${unique_threat_types_in_order[@]}"; do
    type_specific_total_count=0
    for pattern_item in "${PATTERNS[@]}"; do
        IFS=":" read -r threat_type_from_pattern pattern <<< "$pattern_item"
        if [ -z "$threat_type_from_pattern" ]; then continue; fi

        if [[ "$threat_type_from_pattern" == "$current_threat_type" ]]; then
            current_pattern_detection_count=$(grep -E -i -c "$pattern" "$LOG_FILE")
            type_specific_total_count=$((type_specific_total_count + current_pattern_detection_count))
            if [ "$current_pattern_detection_count" -gt 0 ]; then
                 found_any_threat=true # 어떤 패턴이라도 매칭되면 플래그 설정
            fi
        fi
    done

    if [ "$type_specific_total_count" -gt 0 ]; then
        # 위협 유형별 요약 데이터 구성 (예: "SQL_INJECTION=10;")
        threat_type_summary_data="${threat_type_summary_data}${current_threat_type}=${type_specific_total_count};"
        # 전체 매칭 로그 라인 수에도 더함 (이 부분은 중복을 허용하는 전체 합계)
        # 주의: 이 방식은 total_log_lines_matched_overall을 이 루프에서 계산하면
        #       각 패턴별 grep -c 결과를 더하는 이전 방식과 결과가 다를 수 있음.
        #       이전 방식(각 패턴별로 더하기)을 유지하려면 별도 루프 필요.
        #       여기서는 각 위협 유형의 합계를 더하는 방식으로 변경.
        # total_log_lines_matched_overall=$((total_log_lines_matched_overall + type_specific_total_count))
        # -> 이전 방식대로 total_log_lines_matched_overall 은 아래 2단계에서 계산
    fi
done

# total_log_lines_matched_overall을 이전처럼 모든 패턴의 grep -c 합계로 계산
for pattern_item in "${PATTERNS[@]}"; do
    IFS=":" read -r _ pattern <<< "$pattern_item" # threat_type은 여기선 불필요
    if [ -z "$pattern" ]; then continue; fi
    count_for_this_pattern=$(grep -E -i -c "$pattern" "$LOG_FILE")
    total_log_lines_matched_overall=$((total_log_lines_matched_overall + count_for_this_pattern))
done


# 2단계: 리포트 파일 작성 및 실제 로그 기록
if [ "$found_any_threat" = true ]; then
    for current_threat_type in "${unique_threat_types_in_order[@]}"; do
        # threat_type_summary_data에서 이 유형의 총 카운트를 가져옴
        # 예: "SQL_INJECTION=10;" 에서 10을 추출
        type_total_detections_str=$(echo "$threat_type_summary_data" | grep -o -E "${current_threat_type}=[^;]+" | cut -d'=' -f2)
        type_total_detections=${type_total_detections_str:-0} # 문자열이 비면 0

        if [ "$type_total_detections" -gt 0 ]; then
            # echo "[$current_threat_type] 패턴 검색 중 (리포트 작성)" # 사용자 요청으로 제거
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
    
    # threat_type_summary_data를 파싱하여 출력
    # "SQL_INJECTION=10;XSS=5;" 형태
    OLD_IFS="$IFS"
    IFS=';'
    for item in $threat_type_summary_data; do
        if [ -n "$item" ]; then # 빈 항목 방지
            threat_name=$(echo "$item" | cut -d'=' -f1)
            threat_count=$(echo "$item" | cut -d'=' -f2)
            if [ "$threat_count" -gt 0 ]; then # 실제로 탐지된 경우만 출력
                printf "  - %-30s : %s 개의 로그 라인에서 탐지됨\n" "$threat_name" "$threat_count"
            fi
        fi
    done
    IFS="$OLD_IFS"

    echo "========================="
    echo "상세 내용은 $REPORT_FILE 파일을 확인하세요."
fi