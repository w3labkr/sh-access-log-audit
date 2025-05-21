#!/bin/bash

AUDIT_SCRIPT_PATH="./audit.sh"
LOG_DIR="./"
LOG_FILE_PATTERN="access-*.log"
LOG_FILE_DEFAULT="access.log"
SPECIFIC_LOG_FILE=""

ONLY_PATTERNS_TO_RUN_DEFAULT="SQL_INJECTION_GROUP,XSS_GROUP"
ONLY_PATTERNS_TO_RUN="$ONLY_PATTERNS_TO_RUN_DEFAULT"
REPORTS_BASE_DIR="output" # 기본값

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --only-patterns)
        if [[ -n "$2" && "$2" != -* ]]; then
            ONLY_PATTERNS_TO_RUN="$2"; shift 2
        elif [[ "$2" == "" || ($# -eq 1 && "$2" != -*) ]]; then
            ONLY_PATTERNS_TO_RUN=""; shift $(($# > 1 && "$2" != -* ? 2 : 1))
        else
            echo "래퍼 스크립트 경고: --only-patterns 옵션에 값이 없거나 잘못되었습니다. audit.sh로 전달합니다."; shift
        fi
        ;;
        --file)
        if [[ -n "$2" && "$2" != -* ]]; then
            SPECIFIC_LOG_FILE="$2"; shift 2
        else
            echo "래퍼 스크립트 오류: --file 옵션에 파일명이 필요합니다." >&2; exit 1
        fi
        ;;
        -o|--output)
        if [[ -n "$2" && "$2" != -* ]]; then
            REPORTS_BASE_DIR="$2"; shift 2
        else
            echo "래퍼 스크립트 오류: $key 옵션에 디렉토리명이 필요합니다." >&2; exit 1
        fi
        ;;
        *)
        echo "래퍼 스크립트: 알 수 없는 옵션 '$1'. 무시합니다."
        shift
        ;;
    esac
done

if [ ! -f "$AUDIT_SCRIPT_PATH" ]; then echo "오류: 감사 스크립트 '$AUDIT_SCRIPT_PATH' 없음"; exit 1; fi
if [ ! -x "$AUDIT_SCRIPT_PATH" ]; then echo "오류: 감사 스크립트 '$AUDIT_SCRIPT_PATH' 실행 권한 없음"; exit 1; fi

if [ -z "$SPECIFIC_LOG_FILE" ] && [ ! -d "$LOG_DIR" ]; then
    echo "경고: 주 로그 디렉토리 '$LOG_DIR' 없음. 패턴 검색 및 기본 ${LOG_FILE_DEFAULT} 검색 영향."
fi

if [ -n "$REPORTS_BASE_DIR" ]; then
    mkdir -p "$REPORTS_BASE_DIR"
    if [ ! -d "$REPORTS_BASE_DIR" ]; then echo "오류: 보고서 디렉토리 '$REPORTS_BASE_DIR' 생성 불가"; exit 1; fi
else
    # 이 경우는 REPORTS_BASE_DIR이 빈 문자열로 명시적으로 설정된 드문 경우
    echo "경고: REPORTS_BASE_DIR이 비어 있습니다. 현재 디렉토리('.') 사용."; REPORTS_BASE_DIR="."; mkdir -p "$REPORTS_BASE_DIR"
fi

echo "로그 파일 분석을 시작합니다..."
log_files_to_process=()

if [ -n "$SPECIFIC_LOG_FILE" ]; then
    if [ ! -f "$SPECIFIC_LOG_FILE" ]; then echo "오류: --file 지정 파일 '$SPECIFIC_LOG_FILE' 없음"; exit 1; fi
    if [ ! -r "$SPECIFIC_LOG_FILE" ]; then echo "오류: --file 지정 파일 '$SPECIFIC_LOG_FILE' 읽기 불가"; exit 1; fi
    log_files_to_process+=("$SPECIFIC_LOG_FILE")
else
    if [ -d "$LOG_DIR" ] && [ -n "$LOG_FILE_PATTERN" ]; then
        while IFS= read -r found_file; do
            [ -n "$found_file" ] && log_files_to_process+=("$found_file")
        done < <(find "$LOG_DIR" -maxdepth 1 -type f -name "$LOG_FILE_PATTERN" 2>/dev/null)
    fi

    if [ ${#log_files_to_process[@]} -eq 0 ]; then
        default_log_file_path=""
        if [ -f "$LOG_DIR$LOG_FILE_DEFAULT" ]; then default_log_file_path="$LOG_DIR$LOG_FILE_DEFAULT"
        elif [ -f "$LOG_FILE_DEFAULT" ]; then default_log_file_path="$LOG_FILE_DEFAULT"; fi

        if [ -n "$default_log_file_path" ] && [ -f "$default_log_file_path" ] && [ -r "$default_log_file_path" ]; then
            log_files_to_process+=("$default_log_file_path")
        else
            msg="오류: 분석할 로그 파일을 찾을 수 없습니다. "
            if [ -n "$SPECIFIC_LOG_FILE" ]; then
                msg+="'--file' 옵션으로 지정된 파일 문제."
            elif [ ${#log_files_to_process[@]} -eq 0 ] && [ -z "$default_log_file_path" ]; then
                msg+="패턴('$LOG_FILE_PATTERN')과 일치하는 파일도 없고, 기본 파일('$LOG_FILE_DEFAULT')도 '$LOG_DIR' 또는 현재 디렉토리에서 찾을 수 없습니다."
            elif [ -n "$default_log_file_path" ]; then
                 msg+="기본 로그 파일 '$default_log_file_path'을(를) 찾을 수 없거나 읽을 수 없습니다."
            fi
            echo "$msg"; exit 1
        fi
    fi
fi

if [ -n "$ONLY_PATTERNS_TO_RUN" ]; then echo "적용될 패턴 (--only-patterns): $ONLY_PATTERNS_TO_RUN"
else echo "적용될 패턴: audit.sh 스크립트 기본값 사용"; fi

if [ ${#log_files_to_process[@]} -eq 0 ]; then echo "오류: 분석할 로그 파일 없음."; exit 1; fi

total_files=${#log_files_to_process[@]}
current_file_num=0

for log_file_path_loop_var in "${log_files_to_process[@]}"; do
    current_file_num=$((current_file_num + 1))
    if [ -z "$log_file_path_loop_var" ]; then continue; fi
    log_file_name=$(basename "$log_file_path_loop_var")
    if [ -z "$log_file_name" ]; then continue; fi

    file_identifier_suffix=""
    if [ -z "$SPECIFIC_LOG_FILE" ] && [[ "$LOG_FILE_PATTERN" == *"*"* ]]; then
        if [[ "$log_file_name" == $LOG_FILE_PATTERN ]]; then
            pattern_prefix="${LOG_FILE_PATTERN%%\**}"
            pattern_suffix="${LOG_FILE_PATTERN##*\*}"
            temp_no_prefix="${log_file_name#$pattern_prefix}"
            identifier_candidate="${temp_no_prefix%$pattern_suffix}"
            if [ -n "$identifier_candidate" ] && \
               [[ ! "$identifier_candidate" =~ "/" ]] && \
               [ "$pattern_prefix$identifier_candidate$pattern_suffix" == "$log_file_name" ]; then
                file_identifier_suffix="-$identifier_candidate"
            fi
        fi
    fi

    report_filename="report${file_identifier_suffix}.txt"
    summary_filename="summary${file_identifier_suffix}.txt"
    blacklist_filename="blacklist${file_identifier_suffix}.txt"

    report_file_for_audit="$REPORTS_BASE_DIR/$report_filename"
    summary_file_for_audit="$REPORTS_BASE_DIR/$summary_filename"
    blacklist_file_for_audit="$REPORTS_BASE_DIR/$blacklist_filename"
    
    log_file_abs_path="$log_file_path_loop_var"
    if [[ "$log_file_path_loop_var" != /* ]]; then
         if [[ "$log_file_path_loop_var" == "./"* ]]; then
            log_file_abs_path="$(pwd)/${log_file_path_loop_var#./}"
         elif [[ "$log_file_path_loop_var" != */* ]]; then
            log_file_abs_path="$(pwd)/$log_file_path_loop_var"
         else
            log_file_abs_path="$(cd "$(dirname "$log_file_path_loop_var")" && pwd)/$(basename "$log_file_path_loop_var")"
         fi
    fi

    audit_sh_options="--file \"$log_file_abs_path\""
    audit_sh_options="$audit_sh_options --report-file \"$report_file_for_audit\""
    audit_sh_options="$audit_sh_options --summary-file \"$summary_file_for_audit\""
    audit_sh_options="$audit_sh_options --blacklist-file \"$blacklist_file_for_audit\""

    if [ -n "$ONLY_PATTERNS_TO_RUN" ]; then
        audit_sh_options="$audit_sh_options --only-patterns \"$ONLY_PATTERNS_TO_RUN\""
    fi

    percentage=$((current_file_num * 100 / total_files))
    bar_length=30
    filled_length=$((percentage * bar_length / 100))
    bar=$(printf "%${filled_length}s" "" | tr ' ' '❚')
    empty_bar=$(printf "%$((bar_length - filled_length))s" "")
    
    printf "\r\033[K분석 중: [%s%s] %3d%% (%d/%d) - %s" "$bar" "$empty_bar" "$percentage" "$current_file_num" "$total_files" "$log_file_name"

    eval "$AUDIT_SCRIPT_PATH $audit_sh_options" > /dev/null 2>&1
    
done

if [ "$total_files" -gt 0 ]; then
    printf "\r\033[K"
fi
echo "모든 로그 파일 분석 완료. ($current_file_num 개 파일 처리)"
echo "보고서는 '$REPORTS_BASE_DIR' 디렉토리에 저장되었습니다."

if [ -z "$SPECIFIC_LOG_FILE" ] && [ ${#log_files_to_process[@]} -gt 1 ] && [ -z "$file_identifier_suffix" ]; then
    echo "주의: 여러 로그 파일이 처리되었고 보고서 파일명에 식별자가 사용되지 않아, 보고서 파일은 마지막 로그 파일 결과로 덮어쓰였을 수 있습니다."
elif [ -z "$SPECIFIC_LOG_FILE" ] && [ ${#log_files_to_process[@]} -eq 1 ] && [ -z "$file_identifier_suffix" ] && [[ "$log_file_name" == "$LOG_FILE_DEFAULT" ]]; then
    :
elif [ -n "$SPECIFIC_LOG_FILE" ]; then
    :
fi