# sh-access-log-audit

`sh-access-log-audit` is a suite of shell scripts designed to analyze web server access logs for potential security threats and generate reports. It includes:

* `audits.sh`: A wrapper script to analyze multiple log files or specific log files, managing report generation for each.
* `audit.sh`: The core script that analyzes a single log file for various types of attacks based on predefined patterns.

## Features

* Analyzes access logs for common web attack patterns.
* Handles single or multiple log files (via `audits.sh`).
* Generates a detailed report of detected threats for each analyzed log file.
* Generates a summary report with top N statistics for each analyzed log file.
* Creates a blacklist of suspicious IP addresses from each analyzed log file.
* Customizable through command-line options for both scripts.
* Allows selection of specific threat patterns or groups to run.

## Usage

There are two main scripts you can use:

### 1. `audits.sh` (Wrapper for multiple/specific log files)

This script is recommended for analyzing multiple log files (e.g., `access-*.log`) or a specific log file, and it will call `audit.sh` for each.

```bash
./audits.sh [OPTIONS...]
```

**Options for `audits.sh`:**

* `-f LOG_FILE`, `--file LOG_FILE`: Path to a specific log file to analyze. If not provided, the script looks for files matching `access-*.log` in the current directory, and then for `access.log`.
* `-o OUTPUT_DIR`, `--output OUTPUT_DIR`: Base directory to save all report files.
  * Default: `output`
* `--only-patterns "PATTERNS"`: Comma-separated list of pattern types or group names (from `audit.sh`) to run.
  * Default: `"SQL_INJECTION_GROUP,XSS_GROUP"`
  * Example: `--only-patterns "SQL_INJECTION_GROUP,XSS,CMD_INJECTION"`
  * To run all patterns defined in `audit.sh`, pass an empty string (`--only-patterns ""`) or `"ALL"`.

### 2. `audit.sh` (Core analysis script for a single log file)

This script performs the actual analysis on a single log file. It's typically called by `audits.sh` but can be run directly.

```bash
./audit.sh [OPTIONS...]
```

**Options for `audit.sh`:**

* `--file LOG_FILE`, `-f LOG_FILE`: Path to the log file to analyze.
  * Default: `access.log` (relative to the script's execution directory if not found in `OUTPUT_DIR`)
* `--output OUTPUT_DIR`, `-o OUTPUT_DIR`: Directory where report files will be saved.
  * Default: `output`
* `--report-file REPORT_FILE`: Detailed report file name. Will be placed in `OUTPUT_DIR`.
  * Default: `report.txt`
* `--summary-file SUMMARY_FILE`: Summary report file name. Will be placed in `OUTPUT_DIR`.
  * Default: `summary.txt`
* `--blacklist-file BLACKLIST_FILE`: IP blacklist file name. Will be placed in `OUTPUT_DIR`.
  * Default: `blacklist.txt`
* `--top-date TOP_N_DATE`: Number of daily detection entries to display in the summary.
  * Default: `10`
* `--top-ip TOP_N_IP`: Number of IP address detection entries to display in the summary.
  * Default: `10`
* `--top-url TOP_N_URL`: Number of URL detection entries to display in the summary.
  * Default: `10`
* `--top-referer TOP_N_REFERER`: Number of Referer detection entries to display in the summary.
  * Default: `10`
* `--only-patterns PATTERN_TYPES`: Comma-separated list of pattern types or group names to run.
  * Default: `"SQL_INJECTION_GROUP,XSS_GROUP"` (as defined in the script)
  * To run ALL patterns, specify `--only-patterns "ALL"` or an empty string `--only-patterns ""`.
* `--list-groups`: List available pattern groups and their members, then exit.
* `--help`, `-h`: Display the help message for `audit.sh`.

## Default Values Summary

**For `audits.sh`:**

* Log Files: `access-*.log` in `./`, then `./access.log` if no specific file via `-f`.
* Output Directory: `output/`
* Patterns to Run: `SQL_INJECTION_GROUP,XSS_GROUP`

**For `audit.sh` (when run directly):**

* Log File: `access.log`
* Output Directory for reports: `output/`
* Report File: `output/report.txt`
* Summary File: `output/summary.txt`
* Blacklist File: `output/blacklist.txt`
* Top N Statistics: `10` for each category (date, IP, URL, referer)
* Patterns to Run: `SQL_INJECTION_GROUP,XSS_GROUP`

## Output Files

The scripts generate the following files, typically within the specified output directory (default `output/`):

When using `audits.sh` to process multiple log files (e.g., `access-202301.log`, `access-202302.log`), the report files will include an identifier from the log filename:

* `report-<identifier>.txt`
* `summary-<identifier>.txt`
* `blacklist-<identifier>.txt`

If a single specific file is processed by `audits.sh`, or if `audit.sh` is run directly, the default filenames are used (unless overridden by options), placed inside the output directory:

* **Detailed Report (e.g., `output/report.txt`):** Contains all log lines that matched any of the threat patterns. For each detected threat category, it lists:
  * The threat name and its internal code.
  * The total number of log lines detected for this threat category.
  * A description of the threat, including general mitigation advice.
  * The specific log entries that matched patterns for this threat category.
* **Summary Report (e.g., `output/summary.txt`):** Provides a summary of the analysis, including:
  * Log file analyzed and the Top N configuration values used for the report.
  * Top N statistics for daily detections, IP addresses (URLs and Referers are decoded and truncated if long) associated with threats.
  * Total counts for each threat type, displaying the threat name, its internal code, and the number of detected log lines.
  * Overall total of matched log lines (duplicates possible across different patterns).
* **IP Blacklist (e.g., `output/blacklist.txt`):** A list of unique IP addresses (each prefixed with `- `) that were found in threatening log entries. This file will be empty if no threats are detected.

## Identified Threats

The `audit.sh` script checks for a wide range of common web vulnerabilities and malicious activities. The identified threat categories include (this list may evolve; use `./audit.sh --list-groups` for the most current list of pattern groups):

* SQL Injection
* NoSQL Injection
* Cross-Site Scripting (XSS)
* Encoded XSS Attempt
* DOM-based XSS Attempt
* Path Traversal/LFI
* Remote File Inclusion (RFI)
* Command Injection
* Sensitive File Access
* Sensitive Backup File Access
* Directory Listing
* Server-Side Request Forgery (SSRF)
* XML External Entity (XXE) Injection
* Log4Shell (CVE-2021-44228)
* Spring4Shell (CVE-2022-22965)
* Insecure Deserialization (PHP)
* Insecure Deserialization (Java)
* Malicious File Upload
* Authentication Bypass Attempt
* Sensitive Component Access
* Open Redirect
* Debug Mode Enabled
* Verbose Error Messages
* Log Injection / CRLF Injection
* Server-Side Template Injection (SSTI)
* Prototype Pollution
* HTTP Request Smuggling/Desync

## How to Run

1. Ensure the scripts `audits.sh` and `audit.sh` have execute permissions:

   ```bash
   chmod +x audits.sh audit.sh
   ```

2. **To analyze multiple log files or with more control over batching, use `audits.sh`:**

   * Analyze all `access-*.log` files in the current directory and then `access.log` if no pattern matches, saving reports to `output/`:

     ```bash
     ./audits.sh
     ```

   * Analyze a specific log file:

     ```bash
     ./audits.sh -f /var/log/nginx/access.log
     ```

   * Analyze a specific log file and save reports to a custom directory:

     ```bash
     ./audits.sh -f /path/to/your/access.log -o /path/to/reports
     ```

   * Analyze default log files but only for SQL Injection and XSS patterns:

     ```bash
     ./audits.sh --only-patterns "SQL_INJECTION_GROUP,XSS_GROUP"
     ```

3. **To analyze a single log file directly with `audit.sh`:**

   ```bash
   ./audit.sh -f /var/log/nginx/access.log -o my_reports --report-file detailed_threats.txt
   ```

   (If no log file is specified with `-f` for `audit.sh`, it attempts to find `access.log`.)

The scripts will then process the log file(s) and generate the report, summary, and blacklist files in the designated output directory. The summary from `audit.sh` (when run directly or via `audits.sh`) will also be printed to the console if threats are found.

## License

This project is licensed under the [MIT License](LICENSE).
