import re
import csv
from collections import defaultdict

# Configurable threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 5

# Regular expression to parse log file entries
LOG_ENTRY_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] "(?P<method>[A-Z]+) (?P<endpoint>\/\S*) .*?" (?P<status>\d{3})'
)

def parse_log_file(log_file):
    """Parse the log file and collect required data."""
    request_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            match = LOG_ENTRY_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = match.group("status")

                # Count requests per IP
                request_counts[ip] += 1

                # Count requests per endpoint
                endpoint_counts[endpoint] += 1

                # Detect failed login attempts (401 status)
                if status == "401" or "Invalid credentials" in line:
                    failed_logins[ip] += 1

    return request_counts, endpoint_counts, failed_logins


def find_most_accessed_endpoint(endpoint_counts):
    """Find the endpoint that was accessed the most."""
    if endpoint_counts:
        return max(endpoint_counts.items(), key=lambda x: x[1])
    return None, 0


def detect_suspicious_activity(failed_logins, threshold):
    """Detect IP addresses with failed login attempts exceeding the threshold."""
    return {ip: count for ip, count in failed_logins.items() if count > threshold}


def display_results(request_counts, most_accessed_endpoint, suspicious_activity):
    """Display the results in the terminal."""
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in sorted(request_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    if suspicious_activity:
        print("\nSuspicious Activity Detected (Failed Login Attempts):")
        print(f"{'IP Address':<20} {'Failed Login Attempts'}")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo suspicious activity detected.")


def save_results_to_csv(request_counts, most_accessed_endpoint, suspicious_activity, output_file):
    """Save the results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP Address
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in request_counts.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    """Main function to orchestrate the log analysis."""
    log_file = "sample.log"
    output_file = "log_analysis_results.csv"

    # Parse the log file
    request_counts, endpoint_counts, failed_logins = parse_log_file(log_file)

    # Find the most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_counts)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)

    # Display results in the terminal
    display_results(request_counts, most_accessed_endpoint, suspicious_activity)

    # Save results to a CSV file
    save_results_to_csv(request_counts, most_accessed_endpoint, suspicious_activity, output_file)

    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
