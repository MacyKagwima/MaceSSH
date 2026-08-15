import requests
security_headers = {"Content-Security-Policy": {"Expected": "default-src", "Issue": "CSP is present but missing a default-src directive, leaving resource loading partially uncontrolled"} , "Strict-Transport-Security": {"Expected": "max-age", "Issue": "The max-age set is lower than the set standard"}, "X-Frame-Options": {"Expected": "DENY", "Issue": "SAMEORIGIN is set and not appropriate for high security webpages where credentials or sensitive information is loaded"}, "X-XSS-Protection": {"Expected":"1; mode=block" , "Issue": "XSS filtering is not fully enabled or is explicitly disabled"} }

keep_scanning = True
while keep_scanning:
    url = input("Enter website URL: ")
    if not url.startswith("http"):
        url = "https://" + url
    try:
        response = requests.get(url)
        print("Security Header Scanner")
        print("Scanning:" , url)
        print("-----------------")
        for header in security_headers:
            expected_value = security_headers[header]["Expected"]
            issue_message = security_headers[header]["Issue"]
            if header in response.headers:
                if expected_value in response.headers[header]:
                    print(header, "-Present and configured correctly!")
                else:
                    print(header, "-Present but misconfigured")
                    print("Current value:",response.headers[header])
                    print("Expected:" , expected_value)
                    print("Issue:" , issue_message)
            else:
                print(header, "-Missing!")
    except:
        print("The website could not be reached. Please check the URL and try again.")
    while True:
        another = input ("Would you like to enter another URL? ").strip().lower()
        if another == "yes" or another == "no":
            break
        else:
            print("Please enter yes or no.")
        keep_scanning = False
