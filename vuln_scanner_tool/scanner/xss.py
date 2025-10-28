
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from termcolor import colored

def get_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(colored(f"Could not get forms from {url}: {e}", "red"))
        return []

def form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def scan_xss(url):
    print(colored(f"Scanning for XSS vulnerabilities on {url}", "blue"))
    forms = get_forms(url)
    print(f"Found {len(forms)} forms.")
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg onload=alert(1)>",
    ]
    vulnerabilities = []

    for form in forms:
        details = form_details(form)
        target_url = urljoin(url, details["action"])
        for payload in xss_payloads:
            data = {}
            for input in details["inputs"]:
                if input["type"] == "text" or input["type"] == "search":
                    data[input["name"]] = payload

            try:
                if details["method"] == "post":
                    response = requests.post(target_url, data=data)
                else:
                    response = requests.get(target_url, params=data)

                if payload in response.text:
                    vulnerabilities.append({
                        "type": "XSS",
                        "url": target_url,
                        "payload": payload
                    })
                    print(colored(f"  [+] XSS vulnerability found at {target_url} with payload: {payload}", "red"))
            except Exception as e:
                print(colored(f"  [-] Error testing form at {target_url}: {e}", "yellow"))

    return vulnerabilities
