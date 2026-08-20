# Network Security Header Scanner

A simple Python tool that scans a website's HTTP headers and checks 
whether key security headers are present and correctly configured.

## What it does
Takes a URL input from the user, fetches the server's response headers, 
and produces a short report showing which security headers are present, 
misconfigured, or missing entirely.

## How it works
The program checks for four key security headers:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-XSS-Protection

Each header is checked for both presence and reasonable configuration. 
The result is one of three outcomes: present and configured, present but 
misconfigured, or missing.

## How to run it
1. Make sure Python is installed
2. Install the requests library: `pip install requests`
3. Run the script and enter a URL when prompted

## Versions

**v1** — Checks whether the four security headers are present or missing.

**v2** — Adds reasonable value checking. Headers are now reported as 
present and configured correctly, present but misconfigured, or missing.

**v3** — Misconfigured headers now show the current value, expected value, 
and a plain English explanation of the issue.

**v4** — Scan multiple URLs in a single session with input validation. 
Only accepts yes/no to continue or exit.

**v5** — All scanned URLs are stored during the session and compiled into 
a final report at the end.

**v6** — Weighted security scoring system added. Each header is assigned 
a maximum score based on its importance (CSP: 40, STS: 30, 
X-Frame-Options: 20, X-XSS-Protection: 10). Scores are rated as 
Good, Moderate, Poor, or Critical.

**v7** — Full web interface built with Flask. Scan URLs through a browser, 
view results per scan, and generate a compiled final report. Features 
automatic dark/light mode, session management, and input validation. 
Named MaceSSH.

**v8** - Export scan results as CSV or PDF directly from the final report page. CSV opens in Excel for further analysis. PDF generates a clean formatted report for sharing.

**v9** - Expanded to eight security headers. Added Referrer-Policy, Permissions-Policy, X-Content-Type-Options, and Cross-Origin-Opener-Policy. Scoring redistributed across all eight headers with weights reflecting each header's relative importance.

## Limitations

This tool is a lightweight educational scanner, not a professional 
security audit. Please read the following before interpreting results:

**1. Four headers only**:
MaceSSH checks for four specific HTTP security headers: 
Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, 
and X-XSS-Protection. Any other security measures a site uses are 
not captured in this scan.

**2. Simplified misconfiguration detection**:
The scanner checks for specific strings inside header values. A header 
can be genuinely well-configured using different syntax than what MaceSSH 
expects and still be flagged as misconfigured. Spotify's CSP is a real 
example of this — complex and deliberate, but flagged by our checker.

**3. Surface level only**:
MaceSSH sees only what the server sends back publicly. Infrastructure-level 
security such as load balancers, CDN configurations, API security, 
authentication systems, and data encryption are completely invisible to 
this tool.

**4. Results vary by endpoint**:
Different pages on the same site can return different headers. Scanning 
google.com and gmail.com returns different results even though both 
belong to Google.

**5. X-XSS-Protection is outdated**:
Modern browsers have largely moved away from this header. A missing or 
disabled X-XSS-Protection is not necessarily a security flaw — many sites 
deliberately omit it in favour of stronger Content-Security-Policy 
implementations.

**6. This is not a security audit**:
A low score does not mean a site is insecure. It means the four specific 
headers MaceSSH checks for were not all present or correctly configured. 
A site can score 0 on MaceSSH and still have robust security 
infrastructure in place.
