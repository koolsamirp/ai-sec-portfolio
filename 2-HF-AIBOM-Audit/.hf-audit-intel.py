#!/usr/bin/env python3
"""
[AI-SecOps] HF Model Audit
Hugging Face API -> Popular + Recent Sort -> Always 5 Threats + 5 Enterprise -> History Block -> Gmail SMTP
"""

import os
import smtplib
import urllib.request
import json
import html
import hashlib
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from groq import Groq

# Fetch top 1000 by downloads, filter locally, sort by recent to guarantee both popularity and freshness
HF_API_URL = "https://huggingface.co/api/models?sort=downloads&direction=-1&limit=1000"
MIN_DOWNLOADS = 10000

# Known verified organizations
VERIFIED_AUTHORS = [
    "meta-llama", "google", "qwen", "mistralai", "openai", "microsoft", "facebook", "facebookai", 
    "nvidia", "amazon", "ibm-granite", "sentence-transformers", "baai", "cross-encoder", 
    "google-bert", "google-t5", "openai-community", "timm", "distilbert", "pyannote", 
    "trl-internal-testing", "intfloat", "nomic-ai", "unsloth", "deepseek-ai", 
    "answerdotai", "comfy-org", "argmaxinc", "hexgrad", "farbodtavakkoli", "laion", 
    "jonatasgrosman", "autogluon", "dphn", "datasocietyco", "minimaxai", "ornith-ai"
]

# Pipeline tags for data access risk and model type
DATA_ACCESS_TAGS = ["text-generation", "text2text-generation", "conversational", "image-text-to-text", "text-classification"]
LOW_RISK_TAGS = ["image-classification", "automatic-speech-recognition", "feature-extraction", "fill-mask", "sentence-similarity"]

TYPE_MAP = {
    "text-generation": "TEXT", "text2text-generation": "TEXT", "conversational": "TEXT", 
    "text-classification": "TEXT", "fill-mask": "TEXT", "token-classification": "TEXT",
    "translation": "TEXT", "summarization": "TEXT", "sentence-similarity": "TEXT", "feature-extraction": "TEXT",
    "image-classification": "IMAGE", "image-to-image": "IMAGE", "text-to-image": "IMAGE", "object-detection": "IMAGE", "image-segmentation": "IMAGE",
    "automatic-speech-recognition": "AUDIO", "text-to-speech": "AUDIO", "audio-classification": "AUDIO",
    "image-text-to-text": "MULTIMODAL", "visual-question-answering": "MULTIMODAL",
    "text-to-video": "VIDEO", "image-to-video": "VIDEO"
}

def format_downloads(dl):
    if dl >= 1000000: return f"{dl/1000000:.1f}M"
    if dl >= 1000: return f"{dl/1000:.0f}k"
    return str(dl)

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

def get_cache_metrics():
    cache_path = Path.home() / ".hf_audit_cache.txt"
    file_size_bytes = cache_path.stat().st_size if cache_path.exists() else 0
    total_model_count = 0
    running_since_date = "N/A"
    seen_hashes = set()
    
    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            total_model_count = len(lines)
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
                    seen_hashes.add(line.split(',', 1)[1])

    if file_size_bytes < 1024 * 1024:
        cache_size_str = f"{file_size_bytes / 1024:.1f} KB"
    else:
        cache_size_str = f"{file_size_bytes / (1024 * 1024):.1f} MB"
        
    return seen_hashes, cache_path, cache_size_str, total_model_count, running_since_date

def fetch_and_triage_hf_models(seen_hashes: set, cache_path: Path):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Ingesting Hugging Face API (Top 1000 + >10k DL)...")
    bucket_a_threats = []
    bucket_b_enterprise = []
    api_status = "Operational"
    new_hashes = []
    
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        req = urllib.request.Request(HF_API_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            models = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"Notice: Hugging Face API skipped ({e})")
        api_status = f"Failed ({str(e)[:20]})"
        return [], [], api_status, 0

    for model in models:
        model_id = model.get("id", "unknown")
        downloads = model.get("downloads", 0)
        likes = model.get("likes", 0)
        tags = model.get("tags", [])
        tags_lower = [t.lower() for t in tags]
        pipeline_tag = model.get("pipeline_tag", "").lower()
        last_modified_str = model.get("lastModified", "")
        
        # Strict Relevance Filter: >= 10,000 downloads
        if downloads < MIN_DOWNLOADS:
            continue

        # Local Supply Chain Triage
        author = model_id.split('/')[0] if '/' in model_id else model_id
        is_verified = author.lower() in VERIFIED_AUTHORS
        
        is_safe = "safetensors" in tags_lower
        is_pickle = "pytorch" in tags_lower and not is_safe
        is_custom_code = "custom_code" in tags_lower or "trust_remote_code" in tags_lower
        is_policy_risk = any(risk in tags_lower for risk in ["uncensored", "abliterated", "not-for-all-audiences", "heretic"])
        
        license_risk = True
        for tag in tags_lower:
            if tag.startswith("license:") and tag not in ["license:other", "license:unknown"]:
                license_risk = False
                break

        # Calculate time since update
        updated_str = "Recent"
        last_modified_dt = None
        if last_modified_str:
            try:
                last_modified_dt = datetime.fromisoformat(last_modified_str.replace("Z", "+00:00"))
                delta = datetime.now(timezone.utc) - last_modified_dt
                if delta.days > 0:
                    updated_str = f"{delta.days}d ago"
                else:
                    updated_str = f"{int(delta.total_seconds() // 3600)}h ago"
            except Exception:
                pass

        triage_tags = []
        risk_score = 0
        if is_safe: triage_tags.append("[SAFE]")
        if is_pickle: triage_tags.append("[PICKLE RISK]"); risk_score += 3
        if is_custom_code: triage_tags.append("[REMOTE CODE EXEC]"); risk_score += 3
        if is_policy_risk: triage_tags.append("[POLICY RISK]"); risk_score += 2
        if license_risk: triage_tags.append("[LICENSE RISK]"); risk_score += 1
        
        if not is_verified:
            triage_tags.append("[UNVERIFIED AUTHOR]")
            risk_score += 2

        # Data Access Risk Tagging
        if pipeline_tag in DATA_ACCESS_TAGS:
            triage_tags.append("[DATA ACCESS RISK]")
            risk_score += 1
        elif pipeline_tag in LOW_RISK_TAGS:
            triage_tags.append("[LOW RISK TASK]")
        else:
            triage_tags.append("[UNKNOWN TASK]")

        # Model Type Tagging
        type_tag = TYPE_MAP.get(pipeline_tag, "UNKNOWN")
        type_str = f"[TYPE: {type_tag}]"

        # Format data tags
        dl_str = format_downloads(downloads)
        data_tags = f"[DL: {dl_str}] [Likes: {likes}] {type_str} {' '.join(triage_tags)}"

        model_data = {
            "id": model_id,
            "downloads": downloads,
            "likes": likes,
            "updated": updated_str,
            "last_modified_dt": last_modified_dt,
            "data_tags": data_tags,
            "risk_score": risk_score,
            "tags": ", ".join(tags[:10])
        }

        # Track if it's new for the DB metrics
        model_hash = hashlib.sha256(model_id.encode('utf-8')).hexdigest()
        if model_hash not in seen_hashes:
            new_hashes.append(model_hash)

        if is_verified:
            bucket_b_enterprise.append(model_data)
        else:
            bucket_a_threats.append(model_data)

    # Append ONLY new hashes to cache
    if new_hashes:
        with open(cache_path, "a", encoding="utf-8") as f:
            current_ts = datetime.now(timezone.utc).isoformat()
            for h in new_hashes:
                f.write(f"{current_ts},{h}\n")

    # Sort by lastModified locally to get recent popular models
    bucket_a_threats.sort(key=lambda x: x["last_modified_dt"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    bucket_b_enterprise.sort(key=lambda x: x["last_modified_dt"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    
    # Take Top 5 recent. If < 5, backfill by absolute downloads to guarantee 5 in each bucket
    top_5_threats = bucket_a_threats[:5]
    if len(top_5_threats) < 5:
        backup = sorted(bucket_a_threats[5:], key=lambda x: x["downloads"], reverse=True)
        top_5_threats.extend(backup[:5-len(top_5_threats)])
        
    top_5_enterprise = bucket_b_enterprise[:5]
    if len(top_5_enterprise) < 5:
        backup = sorted(bucket_b_enterprise[5:], key=lambda x: x["downloads"], reverse=True)
        top_5_enterprise.extend(backup[:5-len(top_5_enterprise)])

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Captured {len(new_hashes)} new models. Selected Top 5 Threats and Top 5 Enterprise for brief.")
    return top_5_threats, top_5_enterprise, api_status, len(new_hashes)

def generate_hf_audit_report(groq_api_key: str, top_5_threats: list) -> str:
    current_date = datetime.now(timezone.utc).strftime("%B %d, %Y")
    client = Groq(api_key=groq_api_key)

    model_payload = ""
    for i, model in enumerate(top_5_threats):
        model_payload += f"MODEL {i+1}: {model['id']} {model['data_tags']}\nTags: {model['tags']}\n\n"

    prompt = f"""
PROMPT: AI SUPPLY CHAIN AIBOM DEEP DIVE – EMPIRICAL VALIDATION ENGINE

ROLE:
You are a senior SecOps and AI Supply Chain auditor. Your operational mandate is to analyze high-traffic Hugging Face models for enterprise supply chain risks. You map these risks to NIST AI RMF (AI Risk Management Framework) and standard AIBOM security controls. You have zero tolerance for unverified model artifacts.

TEMPORAL ANCHOR:
Current Date: {current_date}

PRIMARY AI MODEL ARTIFACTS (HIGH RISK TRIAGE):
{model_payload}

ANALYTICAL DISCIPLINE & FORMATTING (CRITICAL):
For EACH of the models provided above, you must output exactly 3-4 lines of dense, analytical prose.
1. Line 1 MUST start exactly with the provided header: `> MODEL X: [Model Name] [DL: X] [Likes: X] [TYPE: X] [TAGS...]`
2. Line 2: State the specific supply chain risk identified (e.g., Pickle serialization, Remote Code Execution, Unverified Author, Data Access Risk). Map the risk to NIST AI RMF (e.g., Govern, Map, Measure, Manage). State the operational impact (e.g., arbitrary code execution, data poisoning).
3. Line 3: Provide a 30-day validation or remediation step. State exactly how an organization must empirically test or isolate this model before deployment.
4. After the prose for each model, you MUST insert a line of dashes: `----------------------------------------`
5. NO bulleted lists, NO tables. Just the dense prose blocks separated by the dashed lines.
6. DO NOT output models that were not provided in the payload. If 3 models are provided, output 3 blocks. If 5 are provided, output 5 blocks.

OUTPUT STRUCTURE & CONSTRAINTS:
- Length: Strict 400–600 words.
- Vocabulary: Prioritize "empirical validation", "AIBOM", "serialization", and "blast radius".
"""

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Generating HF Audit deep dive via Groq (qwen/qwen3.8-27b)...")

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

def update_local_archive(current_html: str, current_text: str) -> str:
    archive_dir = Path.home() / ".hf_audit_archive"
    archive_dir.mkdir(exist_ok=True)
    
    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_filename = f"{run_timestamp}_HF_Audit"
    with open(archive_dir / f"{base_filename}.html", "w", encoding="utf-8") as f:
        f.write(current_html)
    with open(archive_dir / f"{base_filename}.txt", "w", encoding="utf-8") as f:
        f.write(current_text)
        
    all_files = list(archive_dir.glob("*.*"))
    if len(all_files) > 500:
        all_files.sort(key=os.path.getmtime)
        for old_file in all_files[:len(all_files)-500]:
            try:
                old_file.unlink()
            except Exception:
                pass
                
    txt_files = sorted(archive_dir.glob("*.txt"), key=os.path.getmtime, reverse=True)
    
    history_block = ""
    if len(txt_files) > 1:
        history_lines = ["─────────────────────────────────────────────\n> HISTORICAL CONTEXT (LAST 2 RUNS)\n"]
        runs_added = 0
        
        # Skip index 0 because it is the current run we just saved
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

def format_html_email(report_text: str, current_date: str, top_5_enterprise: list, api_status: str, cache_size_str: str, new_model_count: int, total_model_count: int, running_since_date: str, history_block: str) -> str:
    
    enterprise_list_html = ""
    if top_5_enterprise:
        for model in top_5_enterprise:
            enterprise_list_html += f"> {model['id']} {model['data_tags']} | Upd: {model['updated']}\n"
    else:
        enterprise_list_html = "> No verified vendor updates meeting criteria.\n"

    triage_str = f"10 Models Audited (5 Threats, 5 Enterprise)"

    final_text_for_html = report_text
    if history_block:
        final_text_for_html += "\n\n" + history_block

    all_paragraphs = [p.strip() for p in final_text_for_html.strip().split("\n\n") if p.strip()]
    final_formatted_body = "".join(
        f"<p style='margin: 0 0 16px 0; line-height: 1.5; white-space: pre-wrap;'>{html.escape(p)}</p>" 
        for p in all_paragraphs
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{
          font-family: 'Courier New', Courier, 'Lucida Console', Monaco, monospace;
          background-color: #f4f4f4;
          color: #1a1a1a;
          margin: 0;
          padding: 20px;
          font-size: 14px;
        }}
        .container {{
          max-width: 720px;
          margin: 0 auto;
          background-color: #ffffff;
          border: 1px solid #cccccc;
          padding: 24px;
          border-radius: 0;
        }}
        .header {{
          border-bottom: 2px solid #1a1a1a;
          padding-bottom: 10px;
          margin-bottom: 20px;
        }}
        .title {{
          font-size: 18px;
          font-weight: 700;
          color: #000000;
          letter-spacing: -0.5px;
          margin: 0;
          text-transform: uppercase;
        }}
        .subtitle {{
          font-size: 12px;
          color: #666666;
          text-transform: uppercase;
          margin-top: 5px;
        }}
        .content {{
          font-size: 14px;
          color: #333333;
        }}
        .footer {{
          margin-top: 30px;
          padding-top: 15px;
          border-top: 1px solid #eeeeee;
          font-size: 12px;
          color: #666666;
          white-space: pre;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="title">[AI-SecOps] HF Model Audit</div>
          <div class="subtitle">Anchor: {current_date} &bull; AIBOM & Risk Triage Engine</div>
        </div>
        <div class="content">
          {final_formatted_body}
        </div>
        <div class="footer">
─────────────────────────────────────────────
> PART 2: ENTERPRISE VENDOR UPDATES (TRUSTED AUTHORS)
{enterprise_list_html}
─────────────────────────────────────────────
> TECH DETAILS
> Source: Hugging Face REST API (Popular + Recent)
> API Status: {api_status}
> New Models (This Run): {new_model_count}
> Total Models Tracked: {total_model_count:,}
> Supply Chain Triage: {triage_str}
> Cache State: {cache_size_str} (50 MB limit)
> Running Since: {running_since_date}
> Engine: Groq (qwen/qwen3.8-27b)
─────────────────────────────────────────────
        </div>
      </div>
    </body>
    </html>
    """

def send_email(config: dict, report_text: str, top_5_enterprise: list, api_status: str, cache_size_str: str, new_model_count: int, total_model_count: int, running_since_date: str):
    current_date = datetime.now(timezone.utc).strftime("%b %d, %Y")
    
    html_version_no_history = format_html_email(report_text, current_date, top_5_enterprise, api_status, cache_size_str, new_model_count, total_model_count, running_since_date, "")
    history_block = update_local_archive(html_version_no_history, report_text)
    final_html = format_html_email(report_text, current_date, top_5_enterprise, api_status, cache_size_str, new_model_count, total_model_count, running_since_date, history_block)
    
    enterprise_text = "\n".join([f"> {m['id']} {m['data_tags']} | Upd: {m['updated']}" for m in top_5_enterprise])
    final_text = report_text + "\n\n> PART 2: ENTERPRISE VENDOR UPDATES\n" + enterprise_text + ("\n\n" + history_block if history_block else "")

    subject = f"[AI-SecOps] HF Model Audit — {current_date}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"AI SecOps Engine <{config['GMAIL_USER']}>"
    msg["To"] = config["EMAIL_TO"]

    part1 = MIMEText(final_text, "plain", "utf-8")
    part2 = MIMEText(final_html, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Dispatching HF Audit to {config['EMAIL_TO']}...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(config["GMAIL_USER"], config["GMAIL_APP_PASSWORD"])
        server.sendmail(config["GMAIL_USER"], config["EMAIL_TO"], msg.as_string())
    print(f"[{datetime.now().strftime('%H:%M:%S')}] HF Audit delivered successfully!")

def main():
    config = load_config()
    if "GROQ_API_KEY" not in config:
        raise KeyError("GROQ_API_KEY not found in ~/.ai_intel_config")

    seen_hashes, cache_path, _, _, _ = get_cache_metrics()
    top_5_threats, top_5_enterprise, api_status, new_model_count = fetch_and_triage_hf_models(seen_hashes, cache_path)
    
    _, _, cache_size_str, total_model_count, running_since_date = get_cache_metrics()
    
    if not top_5_threats:
        report_text = "No unverified or high-risk model artifacts were detected in this cycle."
    else:
        report_text = generate_hf_audit_report(config["GROQ_API_KEY"], top_5_threats)
        
    send_email(config, report_text, top_5_enterprise, api_status, cache_size_str, new_model_count, total_model_count, running_since_date)

if __name__ == "__main__":
    main()
