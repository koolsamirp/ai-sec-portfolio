import os
import json
import logging
import smtplib
import requests
import duckdb
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==========================================
# MODULE 1: Config Loader
# ==========================================
class ConfigLoader:
    @staticmethod
    def load():
        config_path = Path.home() / ".ai_intel_config"
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found at {config_path}")
        config = {}
        with open(config_path, "r") as f:
            for line in f:
                if "=" in line:
                    key, val = line.strip().split("=", 1)
                    config[key.strip()] = val.strip().strip('"').strip("'")
        return config

# ==========================================
# MODULE 2: Watchlist Loader (BSI Alias Collapse)
# ==========================================
class WatchlistLoader:
    @staticmethod
    def load():
        watchlist_path = Path.home() / ".otx-engine" / "watchlist.json"
        if not watchlist_path.exists():
            raise FileNotFoundError(f"Watchlist not found at {watchlist_path}")
        with open(watchlist_path, "r") as f:
            return json.load(f)

# ==========================================
# MODULE 3: OTX Client (Pagination Cap & Resilient Fallback)
# ==========================================
class OTXClient:
    def __init__(self, api_key):
        self.session = requests.Session()
        self.session.headers.update({"X-OTX-API-KEY": api_key})
        # Increased backoff to handle OTX 504s better
        retry = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _paginate(self, url, max_pages=5):
        results = []
        next_url = url
        page_count = 0
        
        while next_url and page_count < max_pages:
            try:
                resp = self.session.get(next_url)
                resp.raise_for_status()
                data = resp.json()
                results.extend(data.get("results", []))
                next_url = data.get("next")
                page_count += 1
            except requests.exceptions.RequestException as e:
                logging.warning(f"[OTXClient] Timeout/Error on page {page_count + 1} for {url}: {e}. Returning partial results.")
                break
                
        return results

    def get_indicators_for_alias(self, alias):
        logging.info(f"[OTXClient] Fetching pulses for alias: {alias}")
        pulses = self._paginate(f"https://otx.alienvault.com/api/v1/search/pulses?q={alias}&limit=20", max_pages=2)
        indicators = []
        for pulse in pulses:
            pulse_id = pulse["id"]
            # Cap at 5 pages of 500 (2500 IOCs max per pulse)
            inds = self._paginate(f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators?limit=500", max_pages=5)
            for ind in inds:
                indicators.append({
                    "value": ind["indicator"],
                    "type": ind["type"],
                    "pulse_id": pulse_id
                })
        return indicators

# ==========================================
# MODULE 4: DB Layer (Composite Key & Accurate Counts)
# ==========================================
class DBLayer:
    def __init__(self):
        db_path = str(Path.home() / ".otx-engine" / "threat_intel.duckdb")
        self.con = duckdb.connect(db_path)
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                value VARCHAR,
                type VARCHAR,
                actor VARCHAR,
                pulse_id VARCHAR,
                first_seen TIMESTAMP,
                PRIMARY KEY(value, actor)
            )
        """)

    def insert_indicators(self, indicators, canonical_actor):
        new_count = 0
        historical_count = 0
        for ind in indicators:
            exists = self.con.execute(
                "SELECT COUNT(*) FROM indicators WHERE value = ? AND actor = ?", 
                [ind["value"], canonical_actor]
            ).fetchone()[0]
            
            if exists == 0:
                self.con.execute(
                    "INSERT INTO indicators VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(value, actor) DO NOTHING",
                    [ind["value"], ind["type"], canonical_actor, ind["pulse_id"]]
                )
                new_count += 1
            else:
                historical_count += 1
        return new_count, historical_count

    def get_24h_trends(self):
        total_links = self.con.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        distinct_iocs = self.con.execute("SELECT COUNT(DISTINCT value) FROM indicators").fetchone()[0]
        
        trends = self.con.execute("""
            SELECT actor, type, COUNT(*) 
            FROM indicators 
            WHERE first_seen >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
            GROUP BY actor, type
        """).fetchall()
        
        return {
            "total_links": total_links,
            "distinct_iocs": distinct_iocs,
            "trends": trends
        }

# ==========================================
# MODULE 5: LLM Synth (Batching & Retry)
# ==========================================
class LLMSynth:
    def __init__(self, api_key):
        self.url = "https://api.groq.com/openai/v1/chat/completions"
        self.headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retry = Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def generate_summary(self, stats, ioc_sample):
        prompt = f"""You are a Senior Threat Intelligence Analyst. 
Based on the following 24h IOC statistics from AlienVault OTX, write a 3-sentence executive summary assessing the threat trends.
If a sample of IOCs is provided, mention any patterns (e.g., file extensions, domain TLDs).
Statistics: {json.dumps(stats)}
IOC Sample (max 50): {json.dumps(ioc_sample[:50])}
"""
        payload = {
            "model": "qwen/qwen3.8-27b",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.5
        }
        resp = self.session.post(self.url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "Analysis failed.")

# ==========================================
# MODULE 6: Report Builder (HTML Assembly)
# ==========================================
class ReportBuilder:
    @staticmethod
    def build_html(stats, summary):
        type_mapping = {
            "IPv4": ("C2 Infrastructure (IPs)", "#ef4444"),
            "domain": ("Malicious Domains", "#3b82f6"),
            "URL": ("Phishing/Payload URLs", "#8b5cf6"),
            "FileHash-MD5": ("Malware Payloads (Hashes)", "#10b981"),
            "FileHash-SHA1": ("Malware Payloads (Hashes)", "#10b981"),
            "FileHash-SHA256": ("Malware Payloads (Hashes)", "#10b981")
        }
        
        new_24h = sum(c for _, _, c in stats["trends"])
        actor_stats = {}
        type_counts = {}
        
        for actor, ind_type, count in stats["trends"]:
            actor_stats[actor] = actor_stats.get(actor, 0) + count
            display_name, color = type_mapping.get(ind_type, ("Other IOCs", "#6b7280"))
            if display_name not in type_counts:
                type_counts[display_name] = {"count": 0, "color": color}
            type_counts[display_name]["count"] += count

        css_bars = ""
        for display_name, data in type_counts.items():
            pct = (data["count"] / new_24h) * 100 if new_24h > 0 else 0
            css_bars += f"""
            <div style="font-family: monospace; margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; font-size: 12px;">
                <span>{display_name} ({pct:.0f}%)</span> <span>{data["count"]} New</span>
              </div>
              <div style="background-color: #eee; width: 100%; height: 10px; border-radius: 5px; margin-top: 4px;">
                <div style="background-color: {data["color"]}; width: {pct:.0f}%; height: 10px; border-radius: 5px;"></div>
              </div>
            </div>
            """

        actor_text = " | ".join([f"{k}: {v} new" for k, v in actor_stats.items()])

        return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
          <h2 style="color: #333;">BSI Threat Intelligence Digest</h2>
          <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #3b82f6; margin-bottom: 20px;">
            <strong>Executive Summary (AI Synthesis):</strong><br>
            {summary}
          </div>
          
          <h3 style="color: #333;">24h Threat Landscape</h3>
          <p style="font-size: 14px;">
            <strong>Distinct IOCs Tracked:</strong> {stats['distinct_iocs']} | 
            <strong>Total Actor Links:</strong> {stats['total_links']} | 
            <strong>New Today:</strong> {new_24h}
          </p>
          <p style="font-size: 14px;"><strong>Actor Activity (24h):</strong> {actor_text}</p>
          {css_bars}
          
          <div style="margin-top: 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 10px;">
            <p>Source: AlienVault OTX API (BSI 10-Actor Watchlist)</p>
            <p>Engine: Python + DuckDB (Composite Key) + Groq (qwen/qwen3.8-27b)</p>
          </div>
        </div>
        """

# ==========================================
# MODULE 7: Mailer
# ==========================================
class Mailer:
    @staticmethod
    def send(config, html_body):
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[CTI Digest] BSI Threat Intelligence Brief"
        msg["From"] = f"CTI Engine <{config['GMAIL_USER']}>"
        msg["To"] = config["EMAIL_TO"]
        msg.attach(MIMEText(html_body, "html"))
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(config["GMAIL_USER"], config["GMAIL_APP_PASSWORD"])
            server.sendmail(config["GMAIL_USER"], config["EMAIL_TO"], msg.as_string())

# ==========================================
# MODULE 8: Orchestrator (No business logic)
# ==========================================
def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        config = ConfigLoader.load()
        watchlist = WatchlistLoader.load()
        
        otx_client = OTXClient(config["OTX_API_KEY"])
        db = DBLayer()
        llm = LLMSynth(config["GROQ_API_KEY"])
        
        new_iocs_list = []
        
        for item in watchlist:
            canonical = item["canonical"]
            aliases = item["aliases"]
            
            for alias in aliases:
                indicators = otx_client.get_indicators_for_alias(alias)
                new_count, hist_count = db.insert_indicators(indicators, canonical)
                logging.info(f"[DB] {canonical} ({alias}): {new_count} New, {hist_count} Historical")
                
                for ind in indicators[:new_count]:
                    new_iocs_list.append({"actor": canonical, "type": ind["type"], "value": ind["value"]})
        
        stats = db.get_24h_trends()
        
        if not new_iocs_list:
            logging.info("[Orchestrator] No new IOCs detected. Skipping email.")
            return
            
        summary = llm.generate_summary(stats, new_iocs_list)
        
        html = ReportBuilder.build_html(stats, summary)
        Mailer.send(config, html)
        logging.info("[Orchestrator] Email dispatched successfully!")
        
    except Exception as e:
        logging.error(f"[Orchestrator] Pipeline failed: {e}")

if __name__ == "__main__":
    main()
