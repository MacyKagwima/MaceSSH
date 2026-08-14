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
- **v1** — Checks whether headers are present or missing
- **v2** — Adds reasonable value checking (present vs misconfigured)
- **v3** — Coming soon
