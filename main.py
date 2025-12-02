import os
import json
import asyncio
from typing import Any, Dict, Optional, List
from openai import AsyncOpenAI
from datetime import datetime, UTC
import threading
import logging
import json as json_module
import httpx
import aiohttp

# === Konfiguration ===
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#security-alerts")

# Grok API (xAI) - OpenAI kompatibel
client = AsyncOpenAI(
    api_key=os.getenv("XAI_API_KEY"),
    base_url="https://api.x.ai/v1"
)

# Alternativ: Gemini (falls gewünscht)
# from google import generativeai as genai
# GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
# genai.configure(api_key=GOOGLE_API_KEY)
# MODEL_NAME = "gemini-1.5-pro"

# === Usage Tracker (optional, aber nützlich) ===
class UsageTracker:
    def __init__(self):
        self.main_agent_usage = []
        self.start_time = datetime.now(UTC)

    def log_main_agent_usage(self, usage_data, target_url=""):
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "target_url": target_url,
            "agent_type": "main_agent",
            "usage": usage_data
        }
        self.main_agent_usage.append(entry)
        logging.info(f"Main Agent Usage - Target: {target_url}, Usage: {usage_data}")

    def get_summary(self):
        return {
            "scan_duration": str(datetime.now(UTC) - self.start_time),
            "main_agent_calls": len(self.main_agent_usage),
            "total_calls": len(self.main_agent_usage),
            "main_agent_usage": self.main_agent_usage
        }

    def save_to_file(self, filename_prefix=""):
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}usage_log_{timestamp}.json"
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(self.get_summary(), f, indent=2, default=str)
        logging.info(f"Usage data saved to {filename}")
        return filename

_thread_local = threading.local()
def get_current_usage_tracker():
    return getattr(_thread_local, 'usage_tracker', None)
def set_current_usage_tracker(tracker):
    _thread_local.usage_tracker = tracker

# === Mail.tm Tools ===
email_token_store = {}

async def get_registered_emails():
    return json_module.dumps(list(email_token_store.keys()))

async def list_account_messages(email: str, limit: int = 50):
    jwt = email_token_store.get(email)
    if not jwt:
        return f"No JWT token stored for {email}."
    headers = {"Authorization": f"Bearer {jwt}"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get("https://api.mail.tm/messages", headers=headers)
            if resp.status_code != 200:
                return f"Failed: {resp.status_code}"
            data = resp.json()
            messages = data.get("hydra:member", [])[:limit]
            return json_module.dumps([{
                "id": m.get("id"),
                "subject": m.get("subject"),
                "from": (m.get("from") or {}).get("address", ""),
                "intro": m.get("intro", ""),
                "seen": m.get("seen", False),
                "createdAt": m.get("createdAt", "")
            } for m in messages])
    except Exception as e:
        return f"Error: {e}"

async def get_message_by_id(email: str, message_id: str):
    jwt = email_token_store.get(email)
    if not jwt:
        return f"No JWT token for {email}."
    headers = {"Authorization": f"Bearer {jwt}"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"https://api.mail.tm/messages/{message_id}", headers=headers)
            if resp.status_code != 200:
                return f"Failed: {resp.status_code}"
            msg = resp.json()
            sender = msg.get("from") or {}
            return json_module.dumps({
                "id": msg.get("id"),
                "subject": msg.get("subject"),
                "from": sender.get("address") or sender.get("name", ""),
                "text": msg.get("text", ""),
                "html": msg.get("html", "")
            })
    except Exception as e:
        return f"Error: {e}"

# === Slack Tools ===
async def send_slack_security_alert(
    vulnerability_type: str, severity: str, target_url: str,
    description: str, evidence: Optional[str] = None,
    recommendation: Optional[str] = None, thread_ts: Optional[str] = None
):
    if not SLACK_WEBHOOK_URL:
        return json_module.dumps({"success": False, "error": "No Slack webhook"})

    severity_colors = {"Critical": "#FF0000", "High": "#FF6600", "Medium": "#FFB84D", "Low": "#FFCC00", "Info": "#0099FF"}
    severity_emojis = {"Critical": "🚨", "High": "⚠️", "Medium": "⚡", "Low": "📝", "Info": "ℹ️"}
    color = severity_colors.get(severity, "#808080")
    emoji = severity_emojis.get(severity, "📌")

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {vulnerability_type} Detected"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
            {"type": "mrkdwn", "text": f"*Target:*\n<{target_url}|{target_url}>"}
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"}}
    ]
    if evidence:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Evidence:*\n```{evidence[:500]}```"}})
    if recommendation:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Fix:*\n{recommendation}"}})

    payload = {
        "channel": SLACK_CHANNEL,
        "username": "Security Bot",
        "icon_emoji": ":shield:",
        "blocks": blocks
    }
    if thread_ts:
        payload["thread_ts"] = thread_ts

    async with aiohttp.ClientSession() as session:
        async with session.post(SLACK_WEBHOOK_URL, json=payload) as resp:
            return json_module.dumps({"success": resp.status == 200})

async def send_slack_scan_summary(target_url: str, total_findings: int, **counts):
    if not SLACK_WEBHOOK_URL:
        return json_module.dumps({"success": False, "error": "No Slack webhook"})

    # (Hier gleiche Logik wie vorher – gekürzt für Lesbarkeit)
    # ... du kannst die volle Version aus deinem Original übernehmen

# === Tool Registry ===
tools = [
    {
        "type": "function",
        "function": {
            "name": "send_slack_security_alert",
            "description": "Send a vulnerability alert to Slack",
            "parameters": {
                "type": "object",
                "properties": {
                    "vulnerability_type": {"type": "string"},
                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                    "target_url": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "thread_ts": {"type": "string"}
                },
                "required": ["vulnerability_type", "severity", "target_url", "description"]
            }
        }
    },
    # + weitere Tools wie list_account_messages, etc. falls benötigt
]

async def execute_tool(call):
    name = call.function.name
    args = json.loads(call.function.arguments)

    if name == "send_slack_security_alert":
        return await send_slack_security_alert(**args)
    # weitere Tools hier ergänzen

    return json_module.dumps({"error": "Unknown tool"})

# === Haupt-Scan-Loop (ohne Sandbox) ===
async def run_scan(target_url: str, user_prompt: str, system_prompt: str):
    usage_tracker = UsageTracker()
    set_current_usage_tracker(usage_tracker)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt.format(target_url=target_url)}
    ]

    while True:
        response = await client.chat.completions.create(
            model="grok-beta",  # oder "grok-2-1212" je nach Verfügbarkeit
            messages=messages,
            tools=tools,
            tool_choice="auto"
        )

        message = response.choices[0].message
        messages.append(message)

        if not message.tool_calls:
            result = message.content
            print(f"\n=== FINAL RESULT FOR {target_url} ===\n{result}\n")
            return result

        print(f"Executing {len(message.tool_calls)} tool calls...")
        for tool_call in message.tool_calls:
            result = await execute_tool(tool_call)
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "name": tool_call.function.name,
                "content": result
            })

# === Start ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    system_prompt = os.getenv("SYSTEM_PROMPT", "You are an elite security researcher...")
    base_prompt = """Perform a full security audit of {target_url}.
Find real, exploitable vulnerabilities only. For each: provide type, severity, description, PoC, remediation.
Use tools only when needed (e.g. Slack alerts)."""

    targets = ["https://example.com"]  # oder aus targets.txt laden

    async def main():
        tasks = [run_scan(url, base_prompt, system_prompt) for url in targets]
        await asyncio.gather(*tasks)

    asyncio.run(main())