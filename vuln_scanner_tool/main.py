
import argparse
import configparser
from termcolor import colored
from scanner.xss import scan_xss
from scanner.sqli import scan_sqli
import smtplib
from email.mime.text import MIMEText

def send_alert(subject, body, config):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = config.get('email', 'smtp_user')
    msg['To'] = config.get('email', 'to_email')

    try:
        with smtplib.SMTP(config.get('email', 'smtp_server'), config.getint('email', 'smtp_port')) as server:
            server.starttls()
            server.login(config.get('email', 'smtp_user'), config.get('email', 'smtp_password'))
            server.send_message(msg)
            print(colored("Email alert sent.", "green"))
    except Exception as e:
        print(colored(f"Failed to send email alert: {e}", "red"))

def main():
    parser = argparse.ArgumentParser(description="A simple web vulnerability scanner.")
    parser.add_argument("-u", "--url", help="The URL to scan.", required=True)
    parser.add_argument("--scan-type", choices=["xss", "sqli", "all"], default="all", help="The type of scan to perform.")
    parser.add_argument("--email-alert", action="store_true", help="Send an email alert if vulnerabilities are found.")
    args = parser.parse_args()

    print(colored("=====================================", "cyan"))
    print(colored("      WEB VULNERABILITY SCANNER      ", "cyan"))
    print(colored("=====================================", "cyan"))

    vulnerabilities = []
    if args.scan_type == "xss" or args.scan_type == "all":
        vulnerabilities.extend(scan_xss(args.url))
    if args.scan_type == "sqli" or args.scan_type == "all":
        vulnerabilities.extend(scan_sqli(args.url))

    if vulnerabilities:
        print(colored("\n[!] Vulnerabilities Found:", "red"))
        for vuln in vulnerabilities:
            print(f"  - Type: {vuln['type']}")
            print(f"    URL: {vuln['url']}")
            print(f"    Payload: {vuln['payload']}")

        if args.email_alert:
            config = configparser.ConfigParser()
            config.read('/home/jeevs/sachin/vuln_scanner_tool/config.ini')
            if config.has_section("email") and config.get("email", "smtp_user"):
                body = "The following vulnerabilities were found:\n\n"
                for vuln in vulnerabilities:
                    body += f"- Type: {vuln['type']}\n"
                    body += f"  URL: {vuln['url']}\n"
                    body += f"  Payload: {vuln['payload']}\n\n"
                send_alert("Vulnerabilities Found!", body, config)
            else:
                print(colored("Email configuration not found or incomplete. Skipping email alert.", "yellow"))
    else:
        print(colored("\n[+] No vulnerabilities found.", "green"))

if __name__ == "__main__":
    main()
