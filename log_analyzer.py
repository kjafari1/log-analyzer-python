import re

def analyze_log(log_file_path):
    """
    This function analyzes a log file for unusual activities based on the regular expression pattern detection.

    Args:
        log_file_path (str): the path to the log file being analyzed.

    Returns:
        list: a list of strings where each describes a detected unusual activity.
    """
    unusual_activities = []

    #These regex variables are made to detect specific patterns within the logs
    #factors are based on username, IP address, SQL Injection keywords/patterns
    failed_login_pattern = r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    sql_injection_pattern = r"(?:' OR \d+=\d+--|UNION SELECT|SLEEP\(.+\))"
    unauth_access_pattern = r"Unauthorized access attempt from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to (\S+)"

    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(failed_login_pattern, line) #attempts to match the failed login pattern against the current line
            if match:
                user = match.group(1).strip() if match.group(1) else "unknown" #extracts captured username
                ip_address = match.group(2) #extracts captured IP address
                unusual_activities.append(f"Failed login attempt for user '{user}' from IP {ip_address}: {line.strip()}")

            match = re.search(sql_injection_pattern, line, re.IGNORECASE) #attempts to match the SQL injection pattern (case-insensitive)
            if match:
                unusual_activities.append(f"Potential SQL Injection attempt: {line.strip()}")

            match = re.search(unauth_access_pattern, line) #attempts to match the unauthorized access pattern
            if match:
                ip_address = match.group(1) #extracts the captured IP address
                resource = match.group(2) #extracts the captured resource
                unusual_activities.append(f"Unauthorized access attempt from IP {ip_address} to {resource}: {line.strip()}")

    return unusual_activities

if __name__ == "__main__":
    log_file = "sample.log"

    #Creates a sample log file with predefined entries for testing
    #This code simulates receiving log data
    with open (log_file, "w") as f:
        f.write("Jul 18 14:00:01 server sshd[123]: Failed password for invalid user guest from 192.168.1.100 port 5000\n")
        f.write("Jul 18 14:00:02 server webserver: GET /index.php?id=1' OR 1=1-- HTTP/1.1\n")
        f.write("Jul 18 14:00:03 server system: Normal activity here.\n")
        f.write("Jul 18 14:00:04 server ftp: Unauthorized access attempt from 10.0.0.5 to /admin/settings\n")

    anomalies = analyze_log(log_file)

    if anomalies:
        print("Unusual activities detected:")
        for activity in anomalies:
            print(f"{activity}\n")

    else:
        print("No unusual activities.")
