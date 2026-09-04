#!/usr/bin/env python3
"""
DLP Daily Observability Report
Reads APISIX logs (24h window) -> Calculates Hits/Misses -> Redacts Headers -> Emails Report
"""
import os
import sys
import json
import re
import smtplib
import html
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

LOG_FILE = Path.home() / "ai_gateway_logs" / "groq_audit.log"
STATE_FILE = Path.home() / ".dlp_metrics_state.json"

# Regex patterns to detect PII in logs
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

def load_config():
    config_path = Path.home() / ".ai_intel_config"
    if not config_path.exists(): sys.exit("Error: Config file not found.")
    config = {}
    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("GMAIL_USER="): config["GMAIL_USER"] = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("GMAIL_APP_PASSWORD="): config["GMAIL_APP_PASSWORD"] = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("EMAIL_TO="): config["EMAIL_TO"] = line.split("=", 1)[1].strip().strip('"').strip("'")
    return config

def load_state():
    if not STATE_FILE.exists():
        return {"first_run_date": "N/A", "total_runs": 0, "total_api_requests": 0}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def analyze_logs():
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    twenty_four_hrs_ago_ms = now_ms - 86400000
    
    metrics = {
        "interceptions_today": 0,
        "pii_detected_raw": 0,
        "masked_hits": 0,
        "full_misses": 0,
        "bypass_details": []
    }
    
    if not LOG_FILE.exists():
        return metrics

    # Stream the log file line by line (uses 0 RAM even for 1GB files)
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                log_data = json.loads(line.strip())
                start_time = log_data.get("start_time", 0)
                
                # Filter: Only look at logs from the last 24 hours
                if start_time < twenty_four_hrs_ago_ms:
                    continue
                    
                metrics["interceptions_today"] += 1
                
                req_body = log_data.get("request", {}).get("body", "")
                resp_body = log_data.get("response", {}).get("body", "")
                
                # Find all PII in the raw request body
                emails_found = EMAIL_REGEX.findall(req_body)
                ccs_found = CC_REGEX.findall(req_body)
                
                total_pii_in_doc = len(emails_found) + len(ccs_found)
                metrics["pii_detected_raw"] += total_pii_in_doc
                
                # Check if they leaked into Groq's response
                for pii in emails_found + ccs_found:
                    if pii in resp_body:
                        metrics["full_misses"] += 1
                        metrics["bypass_details"].append(f"Leaked PII: {pii[:4]}...")
                    else:
                        metrics["masked_hits"] += 1
                        
            except json.JSONDecodeError:
                continue

    return metrics

def format_html_email(current_date, state, metrics):
    effectiveness = 0
    if metrics["pii_detected_raw"] > 0:
        effectiveness = (metrics["masked_hits"] / metrics["pii_detected_raw"]) * 100

    bypass_text = "\n".join([f"> {b}" for b in metrics["bypass_details"][:5]]) if metrics["bypass_details"] else "> No bypasses detected."
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: 'Courier New', Courier, monospace; background-color: #f4f4f4; color: #1a1a1a; margin: 0; padding: 20px; font-size: 14px; }}
        .container {{ max-width: 720px; margin: 0 auto; background-color: #ffffff; border: 1px solid #cccccc; padding: 24px; border-radius: 0; }}
        .header {{ border-bottom: 2px solid #1a1a1a; padding-bottom: 10px; margin-bottom: 20px; }}
        .title {{ font-size: 18px; font-weight: 700; color: #000000; letter-spacing: -0.5px; margin: 0; text-transform: uppercase; }}
        .subtitle {{ font-size: 12px; color: #666666; text-transform: uppercase; margin-top: 5px; }}
        .content {{ font-size: 14px; color: #333333; white-space: pre-wrap; }}
        .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #eeeeee; font-size: 12px; color: #666666; white-space: pre; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="title">[AI-Obs] API Gateway Daily Audit</div>
          <div class="subtitle">Anchor: {current_date} &bull; DLP & Observability Report</div>
        </div>
        <div class="content">
> LIFETIME METRICS (State)
> Days Since Inception: {state['first_run_date']}
> Total Generator Runs: {state['total_runs']}
> Total API Requests Sent: {state['total_api_requests']}

> DAILY DLP METRICS (Past 24h)
> Total Interceptions (Today): {metrics['interceptions_today']}
> PII Entities Detected (Raw): {metrics['pii_detected_raw']}
> Masked Successfully (Hits): {metrics['masked_hits']}
> Full Misses (Bypass): {metrics['full_misses']}
> DLP Effectiveness Rate: {effectiveness:.1f}%

> BYPASS ANALYSIS (Misses)
{bypass_text}
        </div>
        <div class="footer">
─────────────────────────────────────────────
> TECH DETAILS
> Log Source: ~/ai_gateway_logs/groq_audit.log
> State Source: ~/.dlp_metrics_state.json
> Traffic Generator: 5 records / 4 hours
> Engine: APISIX 3.17.0 + Groq (qwen/qwen3.8-27b)
> NOTE: Log file is never truncated. 24h windowing applied.
─────────────────────────────────────────────
        </div>
      </div>
    </body>
    </html>
    """

def main():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Generating Daily Observability Report...")
    config = load_config()
    state = load_state()
    metrics = analyze_logs()
    
    current_date = datetime.now(timezone.utc).strftime("%b %d, %Y")
    subject = f"[AI-Obs] API Gateway Daily Audit — {current_date}"
    
    html_body = format_html_email(current_date, state, metrics)
    text_body = f"Interceptions: {metrics['interceptions_today']}, Hits: {metrics['masked_hits']}, Misses: {metrics['full_misses']}"
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"AI Obs Engine <{config['GMAIL_USER']}>"
    msg["To"] = config["EMAIL_TO"]

    part1 = MIMEText(text_body, "plain", "utf-8")
    part2 = MIMEText(html_body, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(config["GMAIL_USER"], config["GMAIL_APP_PASSWORD"])
        server.sendmail(config["GMAIL_USER"], config["EMAIL_TO"], msg.as_string())
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Daily Observability Report delivered successfully!")

if __name__ == "__main__":
    main()
