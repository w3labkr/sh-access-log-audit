# sh-access-log-audit

`sh-access-log-audit` is a shell script designed to analyze web server access logs for potential security threats and generate reports. It identifies various types of attacks based on predefined patterns.

## Features

* Analyzes access logs for common web attack patterns.
* Generates a detailed report of detected threats.
* Generates a summary report with top N statistics.
* Creates a blacklist of suspicious IP addresses.
* Customizable through command-line options.

## Usage

```bash
./audit.sh [OPTIONS...]
```

### Options

* `--file LOG_FILE`, `-f LOG_FILE`: Path to the log file to analyze.
  * Default: `access.log`
* `--report-file REPORT_FILE`: Detailed report file name.
  * Default: `report.txt`
* `--summary-file SUMMARY_FILE`: Summary report file name.
  * Default: `summary.txt`
* `--blacklist-file BLACKLIST_FILE`: IP blacklist file name.
  * Default: `blacklist.txt`
* `--top-date TOP_N_DATE`: Number of daily detection entries to display in the summary.
  * Default: `10`
* `--top-ip TOP_N_IP`: Number of IP address detection entries to display in the summary.
  * Default: `10`
* `--top-url TOP_N_URL`: Number of URL detection entries to display in the summary.
  * Default: `10`
* `--top-referer TOP_N_REFERER`: Number of Referer detection entries to display in the summary.
  * Default: `10`
* `--help`, `-h`: Display the help message.

## Default Values

If no options are specified, the script uses the following default values:

* Log File: `access.log`
* Report File: `report.txt`
* Summary File: `summary.txt`
* Blacklist File: `blacklist.txt`
* Top N Daily Detections: `10`
* Top N IP Detections: `10`
* Top N URL Detections: `10`
* Top N Referer Detections: `10`

## Output Files

The script generates the following files:

* **Detailed Report (`report.txt` by default):** Contains all log lines that matched any of the threat patterns. For each detected threat category, it lists:
  * The threat name and its internal code.
  * The total number of log lines detected for this threat category.
  * A description of the threat, including general mitigation advice.
  * The specific log entries that matched patterns for this threat category.
* **Summary Report (`summary.txt` by default):** Provides a summary of the analysis, including:
  * Log file analyzed and the Top N configuration values used for the report.
  * Top N statistics for daily detections, IP addresses (URLs and Referers are decoded and truncated if long) associated with threats.
  * Total counts for each threat type, displaying the threat name, its internal code, and the number of detected log lines.
  * Overall total of matched log lines (duplicates possible across different patterns).
* **IP Blacklist (`blacklist.txt` by default):** A list of unique IP addresses (each prefixed with `- `) that were found in threatening log entries. This file will be empty if no threats are detected.

## Identified Threats

The script checks for a wide range of common web vulnerabilities and malicious activities. The identified threat categories include:

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

1. Ensure the script `audit.sh` has execute permissions:

   ```bash
   chmod +x audit.sh
   ```

2. Run the script with desired options. For example, to analyze a specific log file:

   ```bash
   ./audit.sh -f /var/log/nginx/access.log
   ```

3. If no log file is specified with `-f`, ensure an `access.log` file exists in the same directory as the script, or provide the correct path.

The script will then process the log file and generate the report, summary, and blacklist files. The summary will also be printed to the console if threats are found.

## License

This project is licensed under the [MIT License](LICENSE).
