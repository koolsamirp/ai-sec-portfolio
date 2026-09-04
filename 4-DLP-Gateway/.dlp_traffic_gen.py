#!/usr/bin/env python3
"""
DLP Traffic Generator
Pulls 5 random financial documents -> Sends through APISIX Gateway -> Updates State JSON
"""
import os
import sys
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from datasets import load_from_disk
from groq import Groq

DATASET_PATH = Path.home() / "pii_finance_dataset"
STATE_FILE = Path.home() / ".dlp_metrics_state.json"

def load_api_key():
    config_path = Path.home() / ".ai_intel_config"
    if not config_path.exists(): sys.exit("Error: Config file not found.")
    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("GROQ_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    sys.exit("Error: GROQ_API_KEY not found.")

def update_state_file():
    state = {}
    if STATE_FILE.exists():
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
            
    if "first_run_date" not in state:
        state["first_run_date"] = datetime.now(timezone.utc).strftime("%b %d, %Y")
        state["total_runs"] = 0
        state["total_api_requests"] = 0
        
    state["total_runs"] += 1
    state["total_api_requests"] += 5
    state["last_run_timestamp"] = datetime.now(timezone.utc).isoformat()
    
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)
        
    return state

def main():
    api_key = load_api_key()
    # Routing through APISIX DLP Gateway
    client = Groq(api_key=api_key, base_url="http://127.0.0.1:9080")
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Loading local PII dataset...")
    dataset = load_from_disk(str(DATASET_PATH))
    
    # Pick 5 random documents
    indices = random.sample(range(len(dataset['test'])), 5)
    docs = [dataset['test'][i] for i in indices]
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting DLP Traffic Generation (5 requests)...")
    
    for i, doc in enumerate(docs):
        text = doc.get('generated_text', '')
        lang = doc.get('language', 'Unknown')
        
        # Ask Groq to analyze the document
        prompt = f"Analyze this financial document and provide a 1-sentence summary.\n\nDOCUMENT:\n{text}"
        
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending Doc {i+1} ({lang}) to Gateway...")
            completion = client.chat.completions.create(
                model="qwen/qwen3.8-27b",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_completion_tokens=50,
                stream=False
            )
            print(f"  -> Groq Response: {completion.choices[0].message.content}")
        except Exception as e:
            print(f"  -> Error sending request: {e}")
            
    state = update_state_file()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Cycle complete. State file updated (Total Runs: {state['total_runs']}).")

if __name__ == "__main__":
    main()
