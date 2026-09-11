#!/usr/bin/env python3
"""
[AI-GRC] Deutschland Bot Summary
RSS Feed Ingestion -> Stateful 50MB Cache -> Local Archiving -> Groq (qwen/qwen3.8-27b) -> Gmail SMTP
Includes Daily Heartbeat fail-safe logic.
"""

import os
import smtplib
import urllib.request
import defusedxml.ElementTree as ET  # hardened parser for untrusted remote XML (XXE-safe)
import html
import hashlib
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime
from pathlib import Path
from groq import Groq

# Verified German & EU GRC RSS Feeds
NEWS_FEEDS = [
    {"source": "BfDI (Data Protection)", "url": "https://www.bfdi.bund.de/SiteGlobals/Functions/RSSFeed/Allgemein/rssnewsfeed.xml"},
    {"source": "BSI Press", "url": "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Presse_Veranstaltungen.xml"},
    {"source": "BSI ACS", "url": "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/ACS_RSSNewsfeed.xml"},
    {"source": "BSI BITS", "url": "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_CSW.xml"},
    {"source": "CERT-Bund Advisories", "url": "https://wid.cert-bund.de/content/public/securityAdvisory/rss"},
    {"source": "BaFin Circulars", "url": "https://www.bafin.de/DE/service/rss/_function/RSS_Rundschreiben.xml"}
]

# Strict GRC & Resilience keywords (English & German)
KEYWORDS = [
    "dora", "nis2", "nis 2", "directive", "regulation", "compliance", "governance",
    "resilience", "operational", "supply chain", "third-party", "vendor", "risk",
    "audit", "control", "policy", "incident response", "continuity", "authentication",
    "encryption", "mfa", "zero trust", "vulnerability", "patch", "mandate",
    "rundschreiben", "datenschutz", "dsgvo", "schwachstelle", "it-sicherheit", "bfdi", "bsi", "bafin"
]

def load_config():
    """Load config from ~/.ai_intel_config"""
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
    """Calculate cache metrics without modifying the file."""
    cache_path = Path.home() / ".grc_intel_cache.txt"
    file_size_bytes = cache_path.stat().st_size if cache_path.exists() else 0
    total_article_count = 0
    running_since_date = "N/A"
    seen_hashes = set()
    
    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            total_article_count = len(lines)
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

    # Format file size
    if file_size_bytes < 1024 * 1024:
        cache_size_str = f"{file_size_bytes / 1024:.1f} KB"
    else:
        cache_size_str = f"{file_size_bytes / (1024 * 1024):.1f} MB"
        
    return seen_hashes, cache_path, cache_size_str, total_article_count, running_since_date

def truncate_cache_if_needed(cache_path: Path):
    """Maintain 50MB hard limit."""
    if cache_path.exists() and cache_path.stat().st_size > 50 * 1024 * 1024:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Cache exceeds 50MB. Truncating oldest 25%...")
        with open(cache_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        keep_lines = lines[int(len(lines) * 0.25):]
        with open(cache_path, "w", encoding="utf-8") as f:
            f.writelines(keep_lines)

def fetch_grc_news(seen_hashes: set, cache_path: Path):
    """Fetch and filter GRC articles, strictly avoiding duplicates."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Ingesting GRC & regulatory feeds...")
    collected_articles = []
    successful_feeds = []
    failed_feeds = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    new_hashes = []

    for feed in NEWS_FEEDS:
        try:
            req = urllib.request.Request(feed["url"], headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                xml_data = resp.read()
                root = ET.fromstring(xml_data)

                items = root.findall(".//item")
                is_atom = False
                if not items:
                    ns = {"atom": "http://www.w3.org/2005/Atom"}
                    items = root.findall(".//atom:entry", ns) or root.findall(".//entry")
                    is_atom = True

                for item in items[:25]:
                    if is_atom:
                        title_elem = item.find("{http://www.w3.org/2005/Atom}title") or item.find("title")
                        link_elem = item.find("{http://www.w3.org/2005/Atom}link") or item.find("link")
                        summary_elem = item.find("{http://www.w3.org/2005/Atom}summary") or item.find("summary") or item.find("content")
                        pub_elem = item.find("{http://www.w3.org/2005/Atom}updated") or item.find("updated")

                        title = title_elem.text.strip() if title_elem is not None and title_elem.text else ""
                        link = link_elem.attrib.get("href", "") if link_elem is not None and "href" in link_elem.attrib else (link_elem.text if link_elem is not None else "")
                        desc = summary_elem.text.strip() if summary_elem is not None and summary_elem.text else ""
                        pub_date = pub_elem.text.strip() if pub_elem is not None and pub_elem.text else "Recent"
                    else:
                        title_elem = item.find("title")
                        link_elem = item.find("link")
                        desc_elem = item.find("description")
                        pub_elem = item.find("pubDate")

                        title = title_elem.text.strip() if title_elem is not None and title_elem.text else ""
                        link = link_elem.text.strip() if link_elem is not None and link_elem.text else ""
                        desc = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""
                        pub_date = pub_elem.text.strip() if pub_elem is not None and pub_elem.text else "Recent"

                    # Deduplication Hashing
                    article_hash = hashlib.sha256(f"{title}|{pub_date}".encode('utf-8')).hexdigest()
                    if article_hash in seen_hashes:
                        continue

                    # 7-Day Date Filter
                    if pub_date and pub_date != "Recent":
                        try:
                            dt = parsedate_to_datetime(pub_date)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            if dt < one_week_ago:
                                continue
                        except Exception:
                            pass

                    clean_desc = desc.replace("<p>", "").replace("</p>", " ").replace("<br>", " ")
                    clean_desc = " ".join(clean_desc.split())[:350]

                    # Local Severity Tagging (Pre-Processing)
                    title_lower = title.lower()
                    severity_tag = ""
                    if "[kritisch]" in title_lower or "[critical]" in title_lower:
                        severity_tag = "[CRITICAL] "
                    elif "[hoch]" in title_lower or "[high]" in title_lower:
                        severity_tag = "[HIGH] "

                    search_text = (title + " " + clean_desc).lower()
                    if any(kw in search_text for kw in KEYWORDS):
                        collected_articles.append(
                            f"Source: {feed['source']}\n"
                            f"Date: {pub_date}\n"
                            f"Title: {severity_tag}{title}\n"
                            f"Link: {link}\n"
                            f"Summary: {clean_desc}\n"
                        )
                        new_hashes.append(article_hash)
                        
            successful_feeds.append(feed['source'])
        except Exception as e:
            print(f"Notice: Feed {feed['source']} skipped ({e})")
            failed_feeds.append(f"{feed['source']} ({str(e)[:20]})")
            continue

    # Append new hashes to cache
    if new_hashes:
        with open(cache_path, "a", encoding="utf-8") as f:
            current_ts = datetime.now(timezone.utc).isoformat()
            for h in new_hashes:
                f.write(f"{current_ts},{h}\n")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Captured {len(collected_articles)} new GRC artifacts.")
    return collected_articles[:15], successful_feeds, failed_feeds, len(new_hashes)

def generate_grc_report(groq_api_key: str, news_data: str) -> str:
    """Run GRC translation and control extraction via Groq."""
    current_date = datetime.now(timezone.utc).strftime("%B %d, %Y")
    client = Groq(api_key=groq_api_key)

    prompt = f"""
PROMPT: DORA & NIS2 CONTROL GAP AUTOMATOR – EMPIRICAL VALIDATION ENGINE

ROLE:
You are a senior GRC Engineer and SecOps integrator. Your operational mandate is to translate dense regulatory and compliance announcements into actionable engineering requirements. Your core philosophy is "resilience" (tested recovery) over "compliance" (documentation only). You have zero tolerance for checkbox language.

TEMPORAL ANCHOR:
Current Date: {current_date}

PRIMARY REGULATORY & ADVISORY DISCLOSURES:
{news_data}

ANALYTICAL DISCIPLINE:
1. Extract explicit technical control mandates from the supplied text. Note: Sources may be in German. Analyze and output the report strictly in English.
2. Map identified mandates to standard security frameworks (e.g., NIST CSF, CIS Controls, ISO 27001, BSI IT-Grundschutz) where applicable.
3. Clearly distinguish between "policy-configured" (documentation) and "genuinely write-protected" (empirical enforcement).
4. If a mandate lacks empirical validation criteria, flag it as a "Documentation Gap".
5. Avoid theoretical claims; focus strictly on what the text requires infrastructure or teams to prove.

OUTPUT STRUCTURE & CONSTRAINTS:
- Length: Strict 400–600 words across exactly 4 prose sections.
- Format: Dense, analytical prose. NO bulleted lists, NO tables.
- Attribution: Every mandate must reference the source: [Source / Article Title / URL].
- Vocabulary: Prioritize "risk" and "enforcement" over "compliance" and "policy".

SECTIONS:
1. REGULATORY MANDATE EXTRACTION (100–150 words)
2. CONTROL MAPPING & ENFORCEMENT CRITERIA (100–150 words)
3. THIRD-PARTY & SUPPLY CHAIN RISK (100–150 words)
4. 30-DAY VALIDATION FORECAST (100–150 words)

TERMINAL METRIC:
Conclude with exactly one standalone line:
"Documentation Risk: [High/Medium/Low] | Enforcement Gap: [One-phrase missing technical control] | Primary Mandate: [Source Citation]."
"""

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Generating GRC enforcement report via Groq (qwen/qwen3.8-27b)...")

    completion = client.chat.completions.create(
        model="qwen/qwen3.8-27b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
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

def update_local_archive(current_html: str, current_text: str, is_heartbeat: bool) -> str:
    """Save current run to local archive, prune to 500 files, return historical context."""
    archive_dir = Path.home() / ".grc_intel_archive"
    archive_dir.mkdir(exist_ok=True)
    
    # Only save actual intelligence runs, not heartbeats
    if not is_heartbeat:
        run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_filename = f"{run_timestamp}_GRC_Brief"
        with open(archive_dir / f"{base_filename}.html", "w", encoding="utf-8") as f:
            f.write(current_html)
        with open(archive_dir / f"{base_filename}.txt", "w", encoding="utf-8") as f:
            f.write(current_text)
        
    # Prune old files (Keep newest 500)
    all_files = list(archive_dir.glob("*.*"))
    if len(all_files) > 500:
        all_files.sort(key=os.path.getmtime)
        for old_file in all_files[:len(all_files)-500]:
            try:
                old_file.unlink()
            except Exception:
                pass
                
    # Get last 3 runs for historical context (skips current run automatically if normal, takes top 3 if heartbeat)
    txt_files = sorted(archive_dir.glob("*.txt"), key=os.path.getmtime, reverse=True)
    
    history_block = ""
    if len(txt_files) > 0:
        history_lines = ["─────────────────────────────────────────────\n> HISTORICAL CONTEXT (LAST 3 RUNS)\n"]
        runs_added = 0
        # If normal run, skip index 0 (current). If heartbeat, start at 0.
        start_idx = 1 if not is_heartbeat else 0
        
        for txt_file in txt_files[start_idx:]:
            if runs_added >= 3:
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

def format_html_email(report_text: str, current_date: str, successful_feeds: list, failed_feeds: list, cache_size_str: str, new_article_count: int, total_article_count: int, running_since_date: str, history_block: str, is_heartbeat: bool) -> str:
    paragraphs = [p.strip() for p in report_text.strip().split("\n\n") if p.strip()]
    formatted_body = "".join(
        f"<p style='margin: 0 0 16px 0; line-height: 1.5; white-space: pre-wrap;'>{html.escape(p)}</p>" 
        for p in paragraphs
    )
    
    feeds_str = ", ".join(successful_feeds) if successful_feeds else "None"
    
    total_feeds = len(NEWS_FEEDS)
    op_count = len(successful_feeds)
    fail_count = len(failed_feeds)
    fail_str = ", ".join(failed_feeds) if failed_feeds else "None"
    feed_status_str = f"{op_count} Operational, {fail_count} Failed (Total {total_feeds}) - [Failed: {fail_str}]" if failed_feeds else f"{op_count} Operational, {fail_count} Failed (Total {total_feeds})"

    final_text_for_html = report_text
    if history_block:
        final_text_for_html += "\n\n" + history_block

    all_paragraphs = [p.strip() for p in final_text_for_html.strip().split("\n\n") if p.strip()]
    final_formatted_body = "".join(
        f"<p style='margin: 0 0 16px 0; line-height: 1.5; white-space: pre-wrap;'>{html.escape(p)}</p>" 
        for p in all_paragraphs
    )
    
    subtitle_text = "Pipeline Healthy" if is_heartbeat else "Empirical Validation Engine"

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
          <div class="title">[AI-GRC] Deutschland Bot Summary</div>
          <div class="subtitle">Anchor: {current_date} &bull; {subtitle_text}</div>
        </div>
        <div class="content">
          {final_formatted_body}
        </div>
        <div class="footer">
─────────────────────────────────────────────
> TECH DETAILS
> Sources Parsed: {feeds_str}
> Feed Status: {feed_status_str}
> New Articles (This Run): {new_article_count}
> Total Articles Tracked: {total_article_count:,}
> Cache State: {cache_size_str} (50 MB limit)
> Running Since: {running_since_date}
> Engine: Groq (qwen/qwen3.8-27b)
─────────────────────────────────────────────
        </div>
      </div>
    </body>
    </html>
    """

def send_email(config: dict, report_text: str, successful_feeds: list, failed_feeds: list, cache_size_str: str, new_article_count: int, total_article_count: int, running_since_date: str, is_heartbeat: bool):
    current_date = datetime.now(timezone.utc).strftime("%b %d, %Y")
    
    html_version_no_history = format_html_email(report_text, current_date, successful_feeds, failed_feeds, cache_size_str, new_article_count, total_article_count, running_since_date, "", is_heartbeat)
    history_block = update_local_archive(html_version_no_history, report_text, is_heartbeat)
    final_html = format_html_email(report_text, current_date, successful_feeds, failed_feeds, cache_size_str, new_article_count, total_article_count, running_since_date, history_block, is_heartbeat)
    
    final_text = report_text + ("\n\n" + history_block if history_block else "")

    if is_heartbeat:
        subject = f"[AI-GRC] Deutschland Bot Summary — {current_date} (No New Alerts)"
    else:
        subject = f"[AI-GRC] Deutschland Bot Summary — {current_date}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"GRC Intel Engine <{config['GMAIL_USER']}>"
    msg["To"] = config["EMAIL_TO"]

    part1 = MIMEText(final_text, "plain", "utf-8")
    part2 = MIMEText(final_html, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Dispatching GRC briefing to {config['EMAIL_TO']}...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(config["GMAIL_USER"], config["GMAIL_APP_PASSWORD"])
        server.sendmail(config["GMAIL_USER"], config["EMAIL_TO"], msg.as_string())
    print(f"[{datetime.now().strftime('%H:%M:%S')}] GRC Briefing delivered successfully!")

def main():
    config = load_config()
    if "GROQ_API_KEY" not in config:
        raise KeyError("GROQ_API_KEY not found in ~/.ai_intel_config")

    seen_hashes, cache_path, _, _, _ = get_cache_metrics()
    collected_articles, successful_feeds, failed_feeds, new_article_count = fetch_grc_news(seen_hashes, cache_path)
    
    truncate_cache_if_needed(cache_path)
    
    # Re-calculate metrics AFTER adding new articles to get accurate counts
    _, _, cache_size_str, total_article_count, running_since_date = get_cache_metrics()
    
    if not collected_articles:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] No new GRC feeds detected. Generating heartbeat email...")
        heartbeat_text = f"Pipeline executed successfully at {datetime.now().strftime('%H:%M:%S')} CEST. No new regulatory mandates detected from BSI, BaFin, or CERT-Bund in the last 24 hours."
        send_email(config, heartbeat_text, successful_feeds, failed_feeds, cache_size_str, 0, total_article_count, running_since_date, is_heartbeat=True)
        return

    news_data = "\n---\n".join(collected_articles)
    report = generate_grc_report(config["GROQ_API_KEY"], news_data)
    send_email(config, report, successful_feeds, failed_feeds, cache_size_str, new_article_count, total_article_count, running_since_date, is_heartbeat=False)

if __name__ == "__main__":
    main()
