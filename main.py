import os
import json
import asyncio
import logging
from datetime import datetime, UTC
import google.generativeai as genai
from google.generativeai.types import Tool, GenerationConfig
import aiohttp
import httpx

# === Konfiguration ===
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    raise ValueError("Setze GOOGLE_API_KEY als Umgebungsvariable!")

genai.configure(api_key=GOOGLE_API_KEY)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#security-alerts")

# Wähle dein Modell (empfohlen: gemini-1.5-pro oder gemini-1.5-flash)
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

# === Logging & Usage Tracking ===
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class UsageTracker:
    def __init__(self):
        self.calls = []
        self.start_time = datetime.now(UTC)

    def log(self, prompt_tokens=None, completion_tokens=None):
        self.calls.append({
            "timestamp": datetime.now(UTC).isoformat(),
            "prompt_tokens": prompt_tokens or 0,
            "completion_tokens": completion_tokens or 0
        })

    def save(self, target_url):
        summary = {
            "target": target_url,
            "scan_duration": str(datetime.now(UTC) - self.start_time),
            "total_calls": len(self.calls),
            "total_tokens": sum(c["prompt_tokens"] + c["completion_tokens"] for c in self.calls),
            "calls": self.calls
        }
        filename = f"usage_{target_url.replace('https://', '').replace('/', '_')}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        logging.info(f"Usage gespeichert: {filename}")
        return filename

# === Slack Alert Tool ===
async def send_slack_security_alert(
    vulnerability_type: str,
    severity: str,
    target_url: str,
    description: str,
    evidence: str | None = None,
    recommendation: str | None = None
):
    if not SLACK_WEBHOOK_URL:
        return "Error: SLACK_WEBHOOK_URL nicht gesetzt"

    colors = {"Critical": "#FF0000", "High": "#FF6600", "Medium": "#FFB84D", "Low": "#CCCC00", "Info": "#0099FF"}
    emojis = {"Critical": "Critical", "High": "Warning", "Medium": "Medium", "Low": "Low", "Info": "Info"}

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{emojis.get(severity, 'Warning')} {vulnerability_type} gefunden!"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
            {"type": "mrkdwn", "text": f"*Target:* <{target_url}|{target_url}>"}
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Beschreibung:*\n{description}"}}
    ]
    if evidence:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*PoC/Evidence:*\n```{evidence[:1500]}```"}})
    if recommendation:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Empfehlung:*\n{recommendation}"}})

    payload = {
        "channel": SLACK_CHANNEL,
        "username": "Gemini Security Scanner",
        "icon_emoji": ":detective:",
        "blocks": blocks
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(SLACK_WEBHOOK_URL, json=payload) as resp:
            return "Slack Alert gesendet!" if resp.status == 200 else f"Slack Fehler: {resp.status}"

# === Tools Definition für Gemini ===
tools = [
    {
        "function_declarations": [
            {
                "name": "send_slack_security_alert",
                "description": "Sendet eine gefundene Schwachstelle als Alert an Slack",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vulnerability_type": {"type": "string"},
                        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                        "target_url": {"type": "string"},
                        "description": {"type": "string"},
                        "evidence": {"type": "string"},
                        "recommendation": {"type": "string"}
                    },
                    "required": ["vulnerability_type", "severity", "target_url", "description"]
                }
            }
        ]
    }
]

# === Haupt-Scan-Funktion ===
async def scan_target(target_url: str):
    print(f"\nStarting scan: {target_url}")
    tracker = UsageTracker()

    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        tools=tools,
        generation_config=GenerationConfig(
            temperature=0.3,
            max_output_tokens=8192,
            response_mime_type="text/plain"
        )
    )

    chat = model.start_chat()

    prompt = f"""
Du bist ein weltklasse Security Researcher und Pentester.
Führe einen vollständigen Sicherheitsaudit von dieser Webseite durch: {target_url}

Deine Aufgabe:
- Finde nur echte, ausnutzbare Schwachstellen (keine theoretischen)
- Priorisiere: Critical > High > Medium
- Für jede gefundene Lücke:
    → Typ, Severity, Beschreibung, vollständiger PoC, Angriffspfad, Remediation
- Nutze das Tool 'send_slack_security_alert' für jede kritische oder hohe Lücke
- Antworte strukturiert in Markdown
- Sei extrem kritisch und detailliert

Beginne jetzt mit der Analyse von: {target_url}
"""

    response = chat.send_message(prompt)
    tracker.log(response.usage_metadata.prompt_token_count, response.usage_metadata.candidates_token_count)

    result_text = ""

    while True:
        if response.candidates[0].content.parts:
            for part in response.candidates[0].content.parts:
                if part.text:
                    result_text += part.text + "\n"
                if part.function_call:
                    func_name = part.function_call.name
                    args = part.function_call.args

                    print(f"Tool wird aufgerufen: {func_name}")

                    if func_name == "send_slack_security_alert":
                        alert_result = await send_slack_security_alert(
                            vulnerability_type=args.get("vulnerability_type"),
                            severity=args.get("severity"),
                            target_url=target_url,
                            description=args.get("description"),
                            evidence=args.get("evidence"),
                            recommendation=args.get("recommendation")
                        )
                        response = chat.send_message(
                            genai.protos.Content(
                                role="user",
                                parts=[genai.protos.Part(
                                    function_response=genai.protos.FunctionResponse(
                                        name="send_slack_security_alert",
                                        response={"result": alert_result}
                                    )
                                )]
                            )
                        )
                        tracker.log(response.usage_metadata.prompt_token_count, response.usage_metadata.candidates_token_count)

        # Prüfe, ob Antwort fertig ist
        if not any(part.function_call for part in response.candidates[0].content.parts if hasattr(part, 'function_call')):
            break

        # Nächste Runde
        response = chat.send_message("Fortfahren mit der Analyse...")

    # Speichere Ergebnis
    safe_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
    filename = f"report_{safe_name}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Security Scan Report\n**Target:** {target_url}\n**Datum:** {datetime.now(UTC)}\n\n")
        f.write(result_text)

    usage_file = tracker.save(safe_name)

    print(f"\nScan abgeschlossen: {target_url}")
    print(f"Report gespeichert → {filename}")
    print(f"Usage gespeichert → {usage_file}\n")

# === Targets laden ===
def load_targets():
    if os.path.exists("targets.txt"):
        with open("targets.txt") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return ["https://example.com"]  # fallback

# === Start ===
if __name__ == "__main__":
    targets = load_targets()
    print(f"Starte Gemini Security Scanner für {len(targets)} Ziele mit {MODEL_NAME}...\n")

    async def main():
        tasks = [scan_target(url) for url in targets]
        await asyncio.gather(*tasks)

    asyncio.run(main())
    print("Alle Scans abgeschlossen!")