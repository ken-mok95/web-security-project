# Manual for Running the Web Security Framework

## Overview

This project provides a framework for identifying, understanding, and prioritizing web security risks using OWASP Juice Shop,
 OWASP ZAP, and Flask. It automates vulnerability scanning and visualizes results through an interactive dashboard.

## Prerequisites

- A Linux-based system (Ubuntu recommended)
- Docker
- Python 3.x
- Java (for OWASP ZAP)

## 1. Start OWASP Juice Shop

Ensure that the OWASP Juice Shop application is running. You can do this by starting the Docker container if it is not already running.

sudo docker start $(sudo docker ps -aq --filter ancestor=bkimminich/juice-shop)

## 2. Start OWASP ZAP

Launch OWASP ZAP in daemon mode. This will allow it to run in the background and accept API requests.

zap.sh -daemon -port 8080

## 3. Run the OWASP ZAP Scan

1. **Execute the Scan Script**: 
 Run the Python script (`vulnerability_scanner.py`) to initiate the vulnerability scan against the Juice Shop application.
 This script will connect to the ZAP API, perform the scan, and save the results in JSON format.

2. **Monitor the Scan Progress**: 
 The script will output the progress of the scan in the terminal. Wait until the scan is complete.

## 4. To Start the Flask Backend

Run the Flask application (`VulnScoreApp.py`). This will start the web server that processes the scan results and serves
them to the dashboard.

## 5. Access the Dashboard

Open your web browser and navigate to (http://127.0.0.1:5000). This will display the dashboard where the scan results are visualiazed.

## 6. View Scan Results

- The dashboard will show interactive charts for vulnerability counts and total risk scores.
- You can also view detailed information about each vulnerability in the provided table.

## 7. Export Reports

If needed, use the export functionality in the dashboard to download the scan results as a PDF report.
Ensure you have the necessary libraries installed (like Flask, plotly and ReportLab) to run the application.
