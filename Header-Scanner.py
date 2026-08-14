import requests
security_headers = ["Content-Security-Policy","Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection"]

url = input("Enter website URL: ")
if not url.startswith("http"):
    url = "https://" + url
try:
    response = requests.get(url)
    print("Security Header Scanner")
    print("Scanning:" , url)
    print("-----------------")
    for header in security_headers:
        if header in response.headers:
            print(header, "Present!")
        else:
            print(header, "Missing!")
except:
    print("The website could not be reached. Please check the URL and try again.")
 
    