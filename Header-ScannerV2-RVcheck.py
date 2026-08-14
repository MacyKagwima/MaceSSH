import requests
security_headers = {"Content-Security-Policy": "default-src","Strict-Transport-Security": "max-age", "X-Frame-Options": "DENY", "X-XSS-Protection": "1; mode=block"}

url = input("Enter website URL: ")
if not url.startswith("http"):
    url = "https://" + url
try:
    response = requests.get(url)
    print("Security Header Scanner")
    print("Scanning:" , url)
    print("-----------------")
    for header, expected_value in security_headers.items():
        if header in response.headers:
            if expected_value in response.headers[header]:
                print(header, "-Present and configured correctly!")
            else:
                print(header, "-Present but misconfigured")
        else:
            print(header, "-Missing!")
except:
    print("The website could not be reached. Please check the URL and try again.")
 
    
