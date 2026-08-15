import requests
security_headers = {"Content-Security-Policy": {"Expected": "default-src", "Issue": "CSP is present but missing a default-src directive, leaving resource loading partially uncontrolled"} , "Strict-Transport-Security": {"Expected": "max-age", "Issue": "The max-age set is lower than the set standard"}, "X-Frame-Options": {"Expected": "DENY", "Issue": "SAMEORIGIN is set and not appropriate for high security webpages where credentials or sensitive information is loaded"}, "X-XSS-Protection": {"Expected":"1; mode=block" , "Issue": "XSS filtering is not fully enabled or is explicitly disabled"} }

results = []
keep_scanning = True
while keep_scanning:
    url = input("Enter website URL: ")
    if not url.startswith("http"):
        url = "https://" + url
    header_results = {}
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
                    status ="Present and configured correctly!"
                    print(header, "-Present and configured correctly!")
                    header_results[header] = status
                else:
                    status = "Present but misconfigured"
                    print(header, "-Present but misconfigured")
                    print("Current value:",response.headers[header])
                    print("Expected:" , expected_value)
                    print("Issue:" , issue_message)
                    header_results[header] = status
            else:
                status = "Missing!"
                print(header, "-Missing!")
                header_results[header] = status
        results.append({"url": url, "headers": header_results})
    except:
        print("The website could not be reached. Please check the URL and try again.")
    while True:
        another = input ("Would you like to enter another URL? ").strip().lower()
        if another == "yes" or another == "no":
            break
        else:
            print("Please enter yes or no.")
    if another == "no":
        keep_scanning = False
print("\n======FINAL REPORT======")
for result in results:
    print("\nURL:", result["url"])
    print("------------------")
    for header, status in result["headers"].items():
        print(header, "-", status)
