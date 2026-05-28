import httpx
from app.core.config import settings

class NotificationService:
    @staticmethod
    async def send_alert(category: str, target: str, verdict: str, score: float, details: str = ""):
        if not settings.ALERTS_ENABLED or not settings.WEBHOOK_URL:
            print(f"📡 Internal Alert: {verdict} on {target} (Score: {score})")
            return

        if score < settings.THREAT_THRESHOLD and verdict.lower() not in ["malicious", "threat"]:
            return

        payload = {
            "text": f"🚨 *AICDS THREAT ALERT* 🚨\n"
                    f"*Category:* {category}\n"
                    f"*Target:* {target}\n"
                    f"*Verdict:* {verdict}\n"
                    f"*Confidence:* {score:.2f}\n"
                    f"*Details:* {details[:200]}..."
        }

        async with httpx.AsyncClient() as client:
            try:
                await client.post(settings.WEBHOOK_URL, json=payload, timeout=5.0)
            except Exception as e:
                print(f"❌ Webhook failed: {e}")