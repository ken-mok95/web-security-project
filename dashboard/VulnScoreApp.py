from flask import Flask, render_template, jsonify, send_file
import json
import os
from datetime import datetime
import logging
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define risk weightings based on OWASP Top 10 (2021) - Top 5 vulnerabilities
OWASP_WEIGHTS = {
    "Broken Access Control": 1.0,
    "Cryptographic Failures": 0.9,
    "Injection": 1.0,  # This includes SQL Injection, Command Injection, etc.
    "Insecure Design": 0.8,
    "Security Misconfiguration": 0.7,
}

# Map ZAP risk levels to numeric scores
RISK_LEVELS = {
    "High": 9.0,
    "Medium": 6.0,
    "Low": 3.0,
}

# Categorize risk based on calculated risk score
def categorize_risk(risk_score):
    if risk_score >= 7.0:
        return "Critical"
    elif risk_score >= 5.0:
        return "High"
    elif risk_score >= 3.0:
        return "Medium"
    else:
        return "Low"

# Process scan data and calculate risk scores
def calculate_risk(alerts):
    scored_alerts = []
    for alert in alerts:
        alert_name = alert.get("alert", "Unknown")
        risk_level = alert.get("risk", "Low")
        cvss_score = RISK_LEVELS.get(risk_level, 3.0)  # Default to Low if risk level is unknown
        weight = OWASP_WEIGHTS.get(alert_name, 0.5)

        risk_score = round(cvss_score * weight, 2)
        severity = categorize_risk(risk_score)

        alert["risk_score"] = risk_score
        alert["severity"] = severity
        scored_alerts.append(alert)
    
    return scored_alerts

# Load scan results and process them
def load_results():
    try:
        with open('../scanner/mock_scan_results.json', 'r') as file:
            alerts = json.load(file)
    except FileNotFoundError:
        return {"error": "Scan results file not found."}
    except Exception as e:
        return {"error": f"Invalid scan results format: {str(e)}"}
    
    scored_alerts = calculate_risk(alerts)
    return {
        "alerts": scored_alerts,
    }

# Route to serve scan results as JSON
@app.route('/results')
def results():
    try:
        data = load_results()
        return jsonify(data)
    except Exception as e:
        logging.error(f"Error in /results: {str(e)}")
        return jsonify({"error": "An internal error occurred."}), 500

# Generate and return PDF report
@app.route('/generate_report/pdf')
def generate_pdf_report():
    data = load_results()
    if "error" in data:
        return jsonify({"error": data["error"]})

    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join("reports", filename)
    
    os.makedirs("reports", exist_ok=True)

    # Create PDF
    pdf = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    title = Paragraph("Security Scan Report", styles['Title'])
    elements.append(title)

    # Add a subtitle with the current date
    subtitle = Paragraph(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Heading2'])
    elements.append(subtitle)

    # Add a spacer
    elements.append(Spacer(1, 12))

    # Add a summary section
    summary_title = Paragraph("Summary", styles['Heading2'])
    elements.append(summary_title)

    # Calculate summary statistics
    total_alerts = len(data["alerts"])
    critical_alerts = len([alert for alert in data["alerts"] if alert["severity"] == "Critical"])
    high_alerts = len([alert for alert in data["alerts"] if alert["severity"] == "High"])
    medium_alerts = len([alert for alert in data["alerts"] if alert["severity"] == "Medium"])
    low_alerts = len([alert for alert in data["alerts"] if alert["severity"] == "Low"])

    summary_text = f"""
    Total Alerts: {total_alerts}
    Critical Alerts: {critical_alerts}
    High Alerts: {high_alerts}
    Medium Alerts: {medium_alerts}
    Low Alerts: {low_alerts}
    """
    summary_paragraph = Paragraph(summary_text, styles['BodyText'])
    elements.append(summary_paragraph)

    # Add a spacer
    elements.append(Spacer(1, 12))

    # Add a detailed findings section
    findings_title = Paragraph("Detailed Findings", styles['Heading2'])
    elements.append(findings_title)

    # Add findings in paragraph format
    for alert in data["alerts"]:
        alert_text = f"""
        <b>Alert:</b> {alert.get("alert", "Unknown")}<br/>
        <b>Severity:</b> {alert["severity"]}<br/>
        <b>Risk Score:</b> {alert["risk_score"]}<br/>
        <b>Description:</b> {alert.get("description", "N/A")}<br/>
        <b>URL:</b> {alert.get("url", "N/A")}<br/>
        <b>Solution:</b> {alert.get("solution", "N/A")}<br/>
        """
        alert_paragraph = Paragraph(alert_text, styles['BodyText'])
        elements.append(alert_paragraph)
        elements.append(Spacer(1, 12))  # Add space between alerts

    # Add a footer
    footer = Paragraph("Confidential - For internal use only", styles['Normal'])
    elements.append(Spacer(1, 12))
    elements.append(footer)

    # Build PDF
    pdf.build(elements)

    return send_file(filepath, as_attachment=True)

# Home route (for frontend)
@app.route('/')
def home():
    return render_template('security_dashboard.html')

# Run Flask app
if __name__ == '__main__':
    app.run(debug=True)
