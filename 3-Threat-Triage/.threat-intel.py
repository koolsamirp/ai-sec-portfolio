#!/usr/bin/env python3
"""
[AI-SecOps] Threat Intel Triage Engine
NVD JSON API (7d) -> Local Rules Filter -> DB Deduplication -> Groq Architectural Audit -> Gmail SMTP
"""

import os
import smtplib
import urllib.request
import json
import html
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from groq import Groq

# Config & DB Paths
RULES_FILE = Path.home() / ".ai-cve-bot-rules.txt"
CACHE_FILE = Path.home() / ".threat_intel_cache.txt"
ARCHIVE_DIR = Path.home() / ".threat_intel_archive"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000"

# Hardcoded Architectural Profile for Groq Context
TARGET_ARCHITECTURE_PROFILE = """
Target Environment: Immutable Docker containers. 
Hosts are ephemeral and redeployed on every cycle. 
No direct internet ingress (behind Nginx reverse proxy). 
Requires SSH key authentication. 
No GUI interfaces or interactive user sessions.
"""

def load_config():
    config_path = Path.home() / ".ai_intel_config"
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found at {config_path}")
    config = {}
    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip().strip('"').strip("'")
    return config

def load_rules():
    if not RULES_FILE.exists():
        raise FileNotFoundError(f"Rules file not found at {RULES_FILE}. Please create it first.")
    min_cvss = 9.0
    keywords = []
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("MIN_CVSS_SCORE="):
                try:
                    min_cvss = float(line.split("=")[1])
                except Exception:
                    pass
            elif "=" not in line:
                keywords.append(line.lower())
    return min_cvss, keywords

def get_cache_metrics():
    file_size_bytes = CACHE_FILE.stat().st_size if CACHE_FILE.exists() else 0
    total_cve_count = 0
    running_since_date = "N/A"
    seen_cves = set()
    
    if CACHE_FILE.exists():
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            total_cve_count = len(lines)
            if lines:
                try:
                    ts_str = lines[0].strip().split(',', 1)[0]
                    dt = datetime.fromisoformat(ts_str)
                    running_since_date = dt.strftime("%b %d, %Y")
                except Exception:
                    pass
            for line in lines:
                line = line.strip()
                if ',' in line:
                    seen_cves.add(line.split(',', 1)[1])

    if file_size_bytes < 1024 * 1024:
        cache_size_str = f"{file_size_bytes / 1024:.1f} KB"
    else:
        cache_size_str = f"{file_size_bytes / (1024 * 1024):.1f} MB"
        
    return seen_cves, cache_size_str, total_cve_count, running_since_date

def truncate_cache_if_needed():
    if CACHE_FILE.exists() and CACHE_FILE.stat().st_size > 50 * 1024 * 1024:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Cache exceeds 50MB. Truncating oldest 25%...")
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        keep_lines = lines[int(len(lines) * 0.25):]
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.writelines(keep_lines)

def extract_highest_cvss(metrics):
    highest_score = 0.0
    version_str = "N/A"
    
    # Check CVSS v4.0 first
    if "cvssMetricV40" in metrics:
        for m in metrics["cvssMetricV40"]:
            score = m.get("cvssData", {}).get("baseScore", 0.0)
            if score > highest_score:
                highest_score = score
                version_str = "4.0"
                
    # Check CVSS v3.1 (often higher than v4.0 for the same vuln)
    if "cvssMetricV31" in metrics:
        for m in metrics["cvssMetricV31"]:
            score = m.get("cvssData", {}).get("baseScore", 0.0)
            if score > highest_score:
                highest_score = score
                version_str = "3.1"
                
    # Fallback to v2 if nothing else exists
    if highest_score == 0.0 and "cvssMetricV2" in metrics:
        for m in metrics["cvssMetricV2"]:
            score = m.get("cvssData", {}).get("baseScore", 0.0)
            if score > highest_score:
                highest_score = score
                version_str = "2.0"
                
    return highest_score, version_str

def fetch_and_filter_cves(seen_cves, min_cvss, keywords):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Ingesting NIST NVD JSON API (7 days)...")
    
    # NVD API requires exact milliseconds in ISO 8601 format
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=7)
    s_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    e_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    url = NVD_API_URL.format(start=s_date, end=e_date)
    
    collected_cves = []
    api_status = "Operational"
    new_cves_to_cache = []
    
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"Notice: NVD API skipped ({e})")
        api_status = f"Failed ({str(e)[:20]})"
        return [], api_status, 0, 0

    total_analyzed = data.get("totalResults", 0)
    vulnerabilities = data.get("vulnerabilities", [])
    filtered_noise = 0

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Extract English description
        desc_text = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
                
        # Filter 1: Keyword Match
        search_text = (cve_id + " " + desc_text).lower()
        matched_keywords = [kw for kw in keywords if kw in search_text]
        if not matched_keywords:
            filtered_noise += 1
            continue
            
        # Filter 2: CVSS Threshold
        metrics = cve.get("metrics", {})
        highest_cvss, cvss_version = extract_highest_cvss(metrics)
        if highest_cvss < min_cvss:
            filtered_noise += 1
            continue
            
        # Filter 3: Deduplication
        if cve_id in seen_cves:
            continue
            
        # If it passes all filters, keep it
        cve_data = {
            "id": cve_id,
            "cvss": highest_cvss,
            "cvss_version": cvss_version,
            "matched_tech": ", ".join(matched_keywords),
            "desc": desc_text[:400].replace("\n", " ")
        }
        collected_cves.append(cve_data)
        if cve_id not in seen_cves:
            new_cves_to_cache.append(cve_id)

    # Append new CVEs to cache DB
    if new_cves_to_cache:
        with open(CACHE_FILE, "a", encoding="utf-8") as f:
            current_ts = datetime.now(timezone.utc).isoformat()
            for cve_id in new_cves_to_cache:
                f.write(f"{current_ts},{cve_id}\n")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Total Analyzed: {total_analyzed} | Filtered Noise: {filtered_noise} | Target Matches: {len(collected_cves)}")
    return collected_cves, api_status, total_analyzed, filtered_noise

def generate_triage_report(groq_api_key, cve_batch):
    client = Groq(api_key=groq_api_key)
    
    cve_payload = ""
    for i, cve in enumerate(cve_batch):
        cve_payload += f"TARGET {i+1}: {cve['id']} [CVSS: {cve['cvss']} (v{cve['cvss_version']})] [MATCHED: {cve['matched_tech']}]\nDescription: {cve['desc']}\n\n"

    prompt = f"""
PROMPT: RISK-BASED VULNERABILITY TRIAGE – EMPIRICAL VALIDATION ENGINE

ROLE:
You are a senior SecOps engineer. Your job is risk-based prioritization over CVSS-default patching. You have zero tolerance for theoretical noise.

TARGET ARCHITECTURE:
{TARGET_ARCHITECTURE_PROFILE}

VULNERABILITY DATA:
{cve_payload}

ANALYTICAL DISCIPLINE & FORMATTING (CRITICAL):
For EACH of the vulnerabilities provided above, you must output exactly 3-4 lines of dense, analytical prose.
1. Line 1 MUST start exactly with: `> TARGET X: [CVE-ID] [CVSS: X.X (vX.X)] [MATCHED TARGET: X]`
2. Line 2: Ruthlessly audit the vulnerability's exploit chain against the Target Architecture. State if the architecture breaks the exploit chain (e.g., requires local access but hosts are immutable) or if the risk remains.
3. Line 3: Assign a "True Resilience Risk: HIGH/MEDIUM/LOW" based STRICTLY on the architectural impact, dropping the base CVSS as the primary metric.
4. Line 4: Provide a 30-day empirical validation step to test or isolate this vulnerability in the specific target environment.
5. After the prose for each target, you MUST insert a line of dashes: `----------------------------------------`
6. DO NOT output vulnerabilities that were not provided in the payload.
"""

    completion = client.chat.completions.create(
        model="qwen/qwen3.8-27b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.5,
        max_completion_tokens=2048,
        top_p=0.95,
        reasoning_effort="default",
        stream=True,
        stop=None
    )

    report_chunks = []
    try:
        for chunk in completion:
            if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                text = chunk.choices[0].delta.content or ""
                report_chunks.append(text)
    except Exception as e:
        report_chunks.append(f"\n\n[STREAM INTERRUPTION]: Partial report generated. Error: {e}")
        
    return "".join(report_chunks)

def update_local_archive(current_html, current_text):
    ARCHIVE_DIR.mkdir(exist_ok=True)
    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_filename = f"{run_timestamp}_Threat_Brief"
    
    with open(ARCHIVE_DIR / f"{base_filename}.html", "w", encoding="utf-8") as f:
        f.write(current_html)
    with open(ARCHIVE_DIR / f"{base_filename}.txt", "w", encoding="utf-8") as f:
        f.write(current_text)
        
    all_files = list(ARCHIVE_DIR.glob("*.*"))
    if len(all_files) > 500:
        all_files.sort(key=os.path.getmtime)
        for old_file in all_files[:len(all_files)-500]:
            try:
                old_file.unlink()
            except Exception:
                pass
                
    txt_files = sorted(ARCHIVE_DIR.glob("*.txt"), key=os.path.getmtime, reverse=True)
    history_block = ""
    if len(txt_files) > 1:
        history_lines = ["─────────────────────────────────────────────\n> HISTORICAL CONTEXT (LAST 2 RUNS)\n"]
        runs_added = 0
        for txt_file in txt_files[1:]:
            if runs_added >= 2:
                break
            try:
                file_time = datetime.fromtimestamp(os.path.getmtime(txt_file)).strftime("%b %d, %Y")
                content = txt_file.read_text(encoding="utf-8").strip()
                history_lines.append(f"\n> RUN -{runs_added + 1} ({file_time}):\n{content}\n")
                runs_added += 1
            except Exception:
                continue
        if runs_added > 0:
            history_lines.append("─────────────────────────────────────────────")
            history_block = "\n".join(history_lines)
            
    return history_block

def format_html_email(report_text, current_date, api_status, total_analyzed, filtered_noise, target_matches, processed_count, batch_count, cache_size_str, total_cve_count, running_since_date, min_cvss, keywords_str, is_heartbeat):
    
    if is_heartbeat:
        final_formatted_body = f"<p style='margin: 0 0 16px 0; line-height: 1.5; white-space: pre-wrap;'>{html.escape(report_text)}</p>"
    else:
        all_paragraphs = [p.strip() for p in report_text.strip().split("\n\n") if p.strip()]
        final_formatted_body = "".join(
            f"<p style='margin: 0 0 16px 0; line-height: 1.5; white-space: pre-wrap;'>{html.escape(p)}</p>" 
            for p in all_paragraphs
        )

    subtitle_text = "Pipeline Healthy" if is_heartbeat else "Risk-Based Prioritization Engine"

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
        .content {{ font-size: 14px; color: #333333; }}
        .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #eeeeee; font-size: 12px; color: #666666; white-space: pre; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="title">[AI-SecOps] Threat Intel Triage</div>
          <div class="subtitle">Anchor: {current_date} &bull; {subtitle_text}</div>
        </div>
        <div class="content">
          {final_formatted_body}
        </div>
        <div class="footer">
─────────────────────────────────────────────
> TECH DETAILS
> Source: NIST NVD JSON API (7d)
> Feed Status: {api_status}
> Active Rules: MIN_CVSS={min_cvss} | Target Stack Loaded from ~/.ai-cve-bot-rules.txt
> Tracking: {keywords_str}
> Total CVEs Analyzed (Feed): {total_analyzed}
> Filtered Noise (Unmatched/Low CVSS): {filtered_noise}
> Target Matches: {target_matches}
> CVEs Processed (Max 20/Run): {processed_count}
> Batch Logic: {batch_count} Batches of 5 sent to Groq
> Total CVEs Tracked (DB): {total_cve_count}
> Cache State: {cache_size_str} (50 MB limit)
> Running Since: {running_since_date}
> Engine: Groq (qwen/qwen3.8-27b)
> CONTEXT: POC Execution - Target Tracker is simulated for portfolio demonstration.
─────────────────────────────────────────────
        </div>
      </div>
    </body>
    </html>
    """

def send_email(config, report_text, api_status, total_analyzed, filtered_noise, target_matches, processed_count, batch_count, cache_size_str, total_cve_count, running_since_date, min_cvss, keywords_str, is_heartbeat):
    current_date = datetime.now(timezone.utc).strftime("%b %d, %Y")
    
    html_version_no_history = format_html_email(report_text, current_date, api_status, total_analyzed, filtered_noise, target_matches, processed_count, batch_count, cache_size_str, total_cve_count, running_since_date, min_cvss, keywords_str, is_heartbeat)
    history_block = update_local_archive(html_version_no_history, report_text)
    
    if history_block:
        report_text += "\n\n" + history_block
        html_with_history = format_html_email(report_text, current_date, api_status, total_analyzed, filtered_noise, target_matches, processed_count, batch_count, cache_size_str, total_cve_count, running_since_date, min_cvss, keywords_str, is_heartbeat)
    else:
        html_with_history = html_version_no_history

    if is_heartbeat:
        subject = f"[AI-SecOps] Threat Intel Brief — {current_date} (No New Target Matches)"
    else:
        subject = f"[AI-SecOps] Threat Intel Brief — {current_date}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"AI SecOps Engine <{config['GMAIL_USER']}>"
    msg["To"] = config["EMAIL_TO"]

    part1 = MIMEText(report_text, "plain", "utf-8")
    part2 = MIMEText(html_with_history, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Dispatching Threat Intel Brief to {config['EMAIL_TO']}...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(config["GMAIL_USER"], config["GMAIL_APP_PASSWORD"])
        server.sendmail(config["GMAIL_USER"], config["EMAIL_TO"], msg.as_string())
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Threat Intel Brief delivered successfully!")

def main():
    config = load_config()
    if "GROQ_API_KEY" not in config:
        raise KeyError("GROQ_API_KEY not found in ~/.ai_intel_config")

    min_cvss, keywords = load_rules()
    keywords_str = ", ".join(keywords)
    
    seen_cves, cache_size_str, total_cve_count, running_since_date = get_cache_metrics()
    
    collected_cves, api_status, total_analyzed, filtered_noise = fetch_and_filter_cves(seen_cves, min_cvss, keywords)
    
    truncate_cache_if_needed()
    if collected_cves:
        _, cache_size_str, total_cve_count, running_since_date = get_cache_metrics()
        
    target_matches = len(collected_cves)
    
    if target_matches == 0:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] No new high-risk target matches detected. Generating heartbeat email...")
        heartbeat_text = f"Pipeline executed successfully at {datetime.now().strftime('%H:%M:%S')} CEST. No new vulnerabilities detected matching the target architecture stack."
        send_email(config, heartbeat_text, api_status, total_analyzed, filtered_noise, 0, 0, 0, cache_size_str, total_cve_count, running_since_date, min_cvss, keywords_str, is_heartbeat=True)
        return
        
    # Sort by CVSS descending, take top 20
    collected_cves.sort(key=lambda x: x["cvss"], reverse=True)
    top_cves = collected_cves[:20]
    processed_count = len(top_cves)
    
    # Batch processing (chunks of 5)
    batch_count = (processed_count + 4) // 5
    final_report_chunks = []
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Hard limit per run: 20. Processing {processed_count} CVEs in {batch_count} batches of 5.")
    
    for i in range(0, processed_count, 5):
        batch_num = (i // 5) + 1
        batch = top_cves[i:i+5]
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending Batch {batch_num} ({len(batch)} CVEs) to Groq...")
        batch_report = generate_triage_report(config["GROQ_API_KEY"], batch)
        final_report_chunks.append(batch_report)
        
    final_report = "\n\n".join(final_report_chunks)
    
    send_email(config, final_report, api_status, total_analyzed, filtered_noise, target_matches, processed_count, batch_count, cache_size_str, total_cve_count, running_since_date, min_cvss, keywords_str, is_heartbeat=False)

if __name__ == "__main__":
    main()
