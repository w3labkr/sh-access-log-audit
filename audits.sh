#!/bin/bash

# Path to the main audit script.
AUDIT_SCRIPT_PATH="./audit.sh"
LOG_DIR="./"
LOG_FILE_PATTERN="access-*.log"
LOG_FILE_DEFAULT="access.log"
SPECIFIC_LOG_FILE=""

# Pattern groups for audit.sh; comma-separated. Default: SQL_INJECTION_GROUP,XSS_GROUP
ONLY_PATTERNS_TO_RUN_DEFAULT="SQL_INJECTION_GROUP,XSS_GROUP"
ONLY_PATTERNS_TO_RUN="$ONLY_PATTERNS_TO_RUN_DEFAULT"
REPORTS_BASE_DIR="output"

# Process command-line arguments.
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -f|--file)
        # Specify a single log file to analyze.
        if [[ -n "$2" && "$2" != -* ]]; then
            SPECIFIC_LOG_FILE="$2"; shift 2
        else
            echo "Wrapper script error: $key option requires a filename." >&2; exit 1
        fi
        ;;
        -o|--output)
        # Specify the output directory for reports.
        if [[ -n "$2" && "$2" != -* ]]; then
            REPORTS_BASE_DIR="$2"; shift 2
        else
            echo "Wrapper script error: $key option requires a directory name." >&2; exit 1
        fi
        ;;
        --only-patterns)
        # Specify which pattern groups to run in audit.sh.
        # An empty value allows audit.sh to use its own defaults.
        if [[ -n "$2" && "$2" != -* ]]; then
            ONLY_PATTERNS_TO_RUN="$2"; shift 2
        elif [[ "$2" == "" || ($# -eq 1 && "$2" != -*) ]]; then
            ONLY_PATTERNS_TO_RUN=""; shift $(($# > 1 && "$2" != -* ? 2 : 1))
        else
            echo "Wrapper script warning: --only-patterns option is missing a value or has an invalid value. Passing to audit.sh."; shift
        fi
        ;;
        *)
        echo "Wrapper script: Unknown option '$1'. Ignoring."
        shift
        ;;
    esac
done

if [ ! -f "$AUDIT_SCRIPT_PATH" ]; then echo "Error: Audit script '$AUDIT_SCRIPT_PATH' not found."; exit 1; fi
if [ ! -x "$AUDIT_SCRIPT_PATH" ]; then echo "Error: Audit script '$AUDIT_SCRIPT_PATH' is not executable."; exit 1; fi

if [ -z "$SPECIFIC_LOG_FILE" ] && [ ! -d "$LOG_DIR" ]; then
    echo "Warning: Main log directory '$LOG_DIR' not found. This may affect pattern search and default ${LOG_FILE_DEFAULT} lookup."
fi

if [ -n "$REPORTS_BASE_DIR" ]; then
    mkdir -p "$REPORTS_BASE_DIR"
    if [ ! -d "$REPORTS_BASE_DIR" ]; then echo "Error: Could not create reports directory '$REPORTS_BASE_DIR'."; exit 1; fi
else
    echo "Warning: REPORTS_BASE_DIR is empty. Using current directory ('.')."; REPORTS_BASE_DIR="."; mkdir -p "$REPORTS_BASE_DIR"
fi

echo "Starting log file analysis..."
log_files_to_process=()

if [ -n "$SPECIFIC_LOG_FILE" ]; then
    if [ ! -f "$SPECIFIC_LOG_FILE" ]; then echo "Error: File specified with $key (or --file/-f) '$SPECIFIC_LOG_FILE' not found."; exit 1; fi
    if [ ! -r "$SPECIFIC_LOG_FILE" ]; then echo "Error: File specified with $key (or --file/-f) '$SPECIFIC_LOG_FILE' not readable."; exit 1; fi
    log_files_to_process+=("$SPECIFIC_LOG_FILE")
else
    if [ -d "$LOG_DIR" ] && [ -n "$LOG_FILE_PATTERN" ]; then
        # Find files in LOG_DIR (non-recursive) matching LOG_FILE_PATTERN.
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
            msg="Error: Could not find any log files to analyze. "
            if [ -n "$SPECIFIC_LOG_FILE" ]; then
                msg+="Problem with the file specified by the '--file' (or '-f') option."
            elif [ ${#log_files_to_process[@]} -eq 0 ] && [ -z "$default_log_file_path" ]; then
                msg+="No files matched the pattern ('$LOG_FILE_PATTERN'), and the default file ('$LOG_FILE_DEFAULT') was not found in '$LOG_DIR' or the current directory."
            elif [ -n "$default_log_file_path" ]; then
                 msg+="The default log file '$default_log_file_path' could not be found or is not readable."
            fi
            echo "$msg"; exit 1
        fi
    fi
fi

if [ -n "$ONLY_PATTERNS_TO_RUN" ]; then echo "Patterns to apply (--only-patterns): $ONLY_PATTERNS_TO_RUN"
else echo "Patterns to apply: Using audit.sh script defaults."; fi

if [ ${#log_files_to_process[@]} -eq 0 ]; then echo "Error: No log files to analyze."; exit 1; fi

total_files=${#log_files_to_process[@]}
current_file_num=0

for log_file_path_loop_var in "${log_files_to_process[@]}"; do
    current_file_num=$((current_file_num + 1))
    if [ -z "$log_file_path_loop_var" ]; then continue; fi
    log_file_name=$(basename "$log_file_path_loop_var")
    if [ -z "$log_file_name" ]; then continue; fi

    file_identifier_suffix=""
    # If processing multiple files via wildcard, extract the variable part of the filename for unique report names.
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
    
    # Ensure log file path passed to audit.sh is absolute.
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

    # Progress Bar
    percentage=$((current_file_num * 100 / total_files))
    bar_length=30
    filled_length=$((percentage * bar_length / 100))
    bar=$(printf "%${filled_length}s" "" | tr ' ' '❚')
    empty_bar=$(printf "%$((bar_length - filled_length))s" "")
    
    # \r moves cursor to line start, \033[K clears line from cursor.
    printf "\r\033[KAnalyzing: [%s%s] %3d%% (%d/%d) - %s" "$bar" "$empty_bar" "$percentage" "$current_file_num" "$total_files" "$log_file_name"

    # `eval` is used for correct interpretation of quotes in $audit_sh_options.
    # audit.sh output is suppressed.
    eval "$AUDIT_SCRIPT_PATH $audit_sh_options" > /dev/null 2>&1
    
done

# Clear the progress bar line after completion.
if [ "$total_files" -gt 0 ]; then
    printf "\r\033[K"
fi
echo "All log files analyzed. ($current_file_num files processed)"
echo "Reports have been saved to the '$REPORTS_BASE_DIR' directory."

# Warn about potential report overwriting if multiple files were processed without filename identifiers.
if [ -z "$SPECIFIC_LOG_FILE" ] && [ ${#log_files_to_process[@]} -gt 1 ] && [ -z "$file_identifier_suffix" ]; then
    echo "Warning: Multiple log files were processed without using an identifier in the report filenames. Report files may have been overwritten by the results from the last log file."
elif [ -z "$SPECIFIC_LOG_FILE" ] && [ ${#log_files_to_process[@]} -eq 1 ] && [ -z "$file_identifier_suffix" ] && [[ "$log_file_name" == "$LOG_FILE_DEFAULT" ]]; then
    :
elif [ -n "$SPECIFIC_LOG_FILE" ]; then
    :
fi