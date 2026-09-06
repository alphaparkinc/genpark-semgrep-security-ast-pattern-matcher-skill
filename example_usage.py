"""
Demonstration of genpark-semgrep-security-ast-pattern-matcher-skill
"""

from client import SecurityPatternMatcherClient

def main():
    scanner = SecurityPatternMatcherClient()

    vulnerable_code = """
import os
import pickle
import subprocess

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE99X7QZ"

def handle_request(user_input, query_param):
    # SQL injection
    cursor.execute(f"SELECT * FROM users WHERE username = '{query_param}'")

    # Command injection
    os.system("ping -c 1 " + user_input)
    subprocess.run("ls " + user_input, shell=True)

    # Insecure deserialization
    data = pickle.loads(user_input)

    # Code injection
    eval(user_input)
"""

    report = scanner.scan_source(vulnerable_code)
    print("=== SECURITY PATTERN SCAN REPORT ===")
    print(f"Status: {report['status']}")
    print(f"Total Findings: {report['findings_count']}")
    for f in report['findings']:
        print(f"  [{f['severity'].upper()}] Line {f['line']} | {f['cwe']} ({f['rule_id']}): {f['message']}")
        print(f"    Suggested Remediation: {f['remediation']}")

if __name__ == "__main__":
    main()
