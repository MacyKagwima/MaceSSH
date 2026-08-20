from flask import Flask, render_template, request, session
import requests
import csv
import io
from flask import send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
app = Flask(__name__)
app.secret_key = "mace_scanner_2026_unique_key"
security_headers = {"Content-Security-Policy": {"Expected": "default-src", "Issue": "CSP is present but missing a default-src directive, leaving resource loading partially uncontrolled"} , "Strict-Transport-Security": {"Expected": "max-age", "Issue": "The max-age set is lower than the set standard"}, "X-Frame-Options": {"Expected": "DENY", "Issue": "SAMEORIGIN is set and not appropriate for high security webpages where credentials or sensitive information is loaded"}, "X-XSS-Protection": {"Expected":"1; mode=block" , "Issue": "XSS filtering is not fully enabled or is explicitly disabled"}, "Referrer-Policy": {"Expected": "strict-origin", "Issue": "Referrer information may be leaked to third parties"}, "Permissions-Policy": {"Expected": "camera=()", "Issue": "Browser permissions are not explicitly restricted"}, "X-Content-Type-Options": {"Expected": "nosniff", "Issue": "Browser may misinterpret file types, enabling injection attacks"}, "Cross-Origin-Opener-Policy": {"Expected": "same-origin", "Issue": "Page may be vulnerable to cross-origin attacks via shared browsing context"} }
scores = {"Content-Security-Policy": {"max": 25} , "Strict-Transport-Security": {"max": 20}, "X-Frame-Options": {"max": 15}, "X-Content-Type-Options": {"max": 12}, "Cross-Origin-Opener-Policy": {"max": 10}, "Permissions-Policy": {"max": 8}, "Referrer-Policy": {"max": 6}, "X-XSS-Protection": {"max": 4} }


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
@app.route("/export/csv")
def export_csv():
    all_results = session.get("all_results",[])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Header", "Status", "Issue"])
    for site in all_results:
        for result in site["results"]:
            writer.writerow([
                site["url"],
                result["header"],
                result["status"],
                result["issue"] or ""
            ])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="maceSSH_scan_report.csv"
            )
@app.route("/export/pdf")
def export_pdf():
    all_results = session.get("all_results", [])
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    y = height - 50
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, y, "MaceSSH - Security Scan Report")
    y -= 20
    p.setFont("Helvetica", 8)
    p.drawString(50, y, "Security Score measureshow well a site's HTTP headers are configured, from 0 (critical risk) to 100 (well configured).")
    y -= 30
    
    for site in all_results:
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y, site["url"])
        y -= 15
        p.setFont("Helvetica", 10)
        p.drawString(50, y, f"Score: {site['score']}/100 - {site['rating']}")
        y -= 15
        
        for result in site["results"]:
            p.setFont("Helvetica", 9)
            p.drawString(60, y, f"{result['header']} - {result['status']}")
            y -= 12
            if result["issue"]:
                p.setFont("Helvetica-Oblique", 8)
                p.drawString(70, y, f"Issue: {result['issue']}")
                y -= 12
            if y < 100:
                p.showPage()
                y = height - 50
        y -=  10
        
    p.save()
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="maceSSH_scan_report.pdf"
    )

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080, use_reloader=False)