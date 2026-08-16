from flask import Flask, render_template, request, session
import requests
app = Flask(__name__)
app.secret_key = "mace_scanner_2026_unique_key"
security_headers = {"Content-Security-Policy": {"Expected": "default-src", "Issue": "CSP is present but missing a default-src directive, leaving resource loading partially uncontrolled"} , "Strict-Transport-Security": {"Expected": "max-age", "Issue": "The max-age set is lower than the set standard"}, "X-Frame-Options": {"Expected": "DENY", "Issue": "SAMEORIGIN is set and not appropriate for high security webpages where credentials or sensitive information is loaded"}, "X-XSS-Protection": {"Expected":"1; mode=block" , "Issue": "XSS filtering is not fully enabled or is explicitly disabled"} }
scores = {"Content-Security-Policy": {"max": 40} , "Strict-Transport-Security": {"max": 30}, "X-Frame-Options": {"max": 20}, "X-XSS-Protection": {"max": 10} }


@app.route("/")
def index():
    return render_template("index.html")
@app.route("/scan", methods=["POST"])
def scan():
    url = request.form["url"]
    if not url.startswith("http"):
        url = "https://"+ url
        
    results = []
    score_accum = 0
    
    try:
        response = requests.get(url)
        for header in security_headers:
            expected_value = security_headers[header]["Expected"]
            issue_message = security_headers[header]["Issue"]
            if header in response.headers:
                if expected_value in response.headers[header]:
                    score_accum += scores[header]["max"]
                    results.append({"header":header, "status": "Present and configured correctly", "current": None, "issue": None})
                else:
                    score_accum += scores[header]["max"]/2
                    results.append({"header": header, "status": "Present but Misconfigured", "current": response.headers[header], "issue": issue_message})
            else:
                results.append({"header": header, "status": "Missing","current": None, "issue": None})
        
        if score_accum >= 80:
            rating = "Good"
        elif score_accum >= 50:
            rating = "Moderate"
        elif score_accum >= 20:
            rating = "Poor"
        else:
            rating = "Critical"
    except:
        return render_template("index.html", error="Could not reach that website")
    all_results = session.get("all_results",[])
    all_results.append({
        "url": url,
        "results": results,
        "score": score_accum,
        "rating": rating
    })
    session["all_results"] = all_results
    return render_template("results.html", url=url, results=results, score=score_accum, rating=rating)

@app.route("/report")
def report():
    all_results = session.get("all_results", [])
    return render_template("report.html", all_results=all_results)

@app.route("/clear")
def clear():
    session.clear()
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080, use_reloader=False)