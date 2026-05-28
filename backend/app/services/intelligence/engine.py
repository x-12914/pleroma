import httpx
import json
import asyncio
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.core.config import settings
from app.db.database import SessionLocal
from app.db.models import ThreatMemory
from app.services.intelligence.embeddings import EmbeddingService
from app.services.notification_service import NotificationService

TRUSTED_DOMAINS = ["google.com", "microsoft.com", "apple.com", "wikipedia.org", "openai.com"]
TRUSTED_SUFFIXES = [".edu", ".gov", ".edu.ng", ".gov.ng"]


def _is_whitelisted(url: str) -> bool:
    """Check whether the URL's actual hostname matches a trusted domain.

    Uses parsed hostname (not substring match) so attacker-controlled
    domains like `google.com.evil.tld` cannot impersonate the whitelist.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if any(host == d or host.endswith(f".{d}") for d in TRUSTED_DOMAINS):
        return True
    if any(host == s.lstrip(".") or host.endswith(s) for s in TRUSTED_SUFFIXES):
        return True
    return False


class IntelligenceEngine:
    def __init__(self):
        self.groq_key = settings.GROQ_API_KEY
        self.serper_key = settings.SERPER_API_KEY
        self.headers = {"Content-Type": "application/json"}

    def _parse_llm_json(self, raw_content: str):
        """Robustly cleans and parses JSON from LLM responses."""
        try:
            clean_content = raw_content.replace("```json", "").replace("```", "").strip()
            return json.loads(clean_content)
        except Exception as e:
            print(f"❌ JSON Parse Error: {e}")
            return None

    async def analyze_url(self, url: str):
        print(f"🔍 Intelligence Layer: Investigating {url}")

        # 1. HEURISTIC WHITELIST (hostname-based, not substring)
        if _is_whitelisted(url):
            return {
                "verdict": "Safe",
                "confidence": 100,
                "reason": "Whitelisted high-reputation domain.",
                "status": "whitelisted"
            }

        # 2. DATA GATHERING (Parallel OSINT & Scraping)
        # We run these at the same time to save time
        reputation_task = self._check_google_reputation(url)
        scrape_task = self._scrape_url(url)
        query_vector_task = EmbeddingService.get_embedding(f"Scan request: {url}")

        reputation, page_content, query_vector = await asyncio.gather(
            reputation_task, scrape_task, query_vector_task
        )

        # 3. RAG LAYER: Check Memory (only if a close match actually exists)
        # Cosine distance range is 0 (identical) → 2 (opposite). Threshold of
        # 0.3 means cosine similarity > 0.7 — i.e. only genuinely similar past
        # threats inform the verdict, instead of any random nearest neighbor.
        past_context = ""
        if query_vector:
            with SessionLocal() as db:
                distance_col = ThreatMemory.embedding.cosine_distance(query_vector).label("distance")
                row = (
                    db.query(ThreatMemory, distance_col)
                    .order_by(distance_col)
                    .limit(1)
                    .first()
                )
                if row and row[1] is not None and row[1] < 0.3:
                    similar, distance = row
                    similarity = 1.0 - float(distance)
                    past_context = (
                        f"PREVIOUS FINDING (similarity {similarity:.2f}): {similar.content}"
                    )

        # 4. THE AI VERDICT (Using Groq 70B for the "Final Word")
        # Since we removed OpenRouter, we go straight to the strongest available model on Groq
        final_report = await self._get_ai_analysis(url, page_content, reputation, past_context)

        # --- IMPORTANT: ALWAYS ATTACH RAW DATA FOR THE ANALYST ---
        final_report["osint_data"] = reputation
        final_report["scrape_data"] = page_content

        # 5. ACTION LAYER (Alerts & Memory)
        try:
            await NotificationService.send_alert(
                category="URL_SCAN",
                target=url,
                verdict=final_report.get("verdict", "Unknown"),
                score=float(final_report.get("confidence", 0)) / 100.0,
                details=final_report.get("reason", "")
            )

            if final_report.get("verdict") == "Malicious" and query_vector:
                with SessionLocal() as db:
                    new_memory = ThreatMemory(
                        content=f"Threat on {url}. {final_report.get('reason')}",
                        embedding=query_vector,
                        metadata_info={"url": url}
                    )
                    db.add(new_memory)
                    db.commit()
        except Exception as e:
            print(f"⚠️ Action Layer error: {e}")

        return final_report

    async def _get_ai_analysis(self, url: str, content: dict, reputation: list, context: str):
        """Uses Llama-3.3-70B-Versatile for high-quality single-pass analysis."""
        prompt = f"""
        Analyze this URL for Cyber Threats/Phishing.
        URL: {url}
        Google OSINT: {reputation}
        Page Content: {content}
        {context}

        Return ONLY a JSON object:
        {{ "verdict": "Safe" | "Malicious" | "Suspicious", "confidence": 0-100, "reason": "Detailed explanation" }}
        """

        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }

        headers = {**self.headers, "Authorization": f"Bearer {self.groq_key}"}

        async with httpx.AsyncClient() as client:
            try:
                # Increased timeout to 25s because 70B takes longer to think
                res = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload, timeout=25.0)
                if res.status_code == 200:
                    parsed = self._parse_llm_json(res.json()["choices"][0]["message"]["content"])
                    if parsed is not None:
                        return parsed
                    print("⚠️ AI returned malformed JSON. Falling back to heuristics.")
            except Exception as e:
                print(f"⚠️ AI Primary failed: {e}. Trying fast recovery...")

        # FINAL FALLBACK (Heuristic) — guaranteed dict return
        return {
            "verdict": "Suspicious" if len(reputation) > 0 or "Scrape failed" in str(content) else "Safe",
            "confidence": 40,
            "reason": "AI Service Timeout. Verdict based on OSINT/Scrape heuristics."
        }

    async def _check_google_reputation(self, url: str):
        if not self.serper_key: return []
        payload = json.dumps({"q": f'"{url}" phishing report'})
        headers = {**self.headers, "X-API-KEY": self.serper_key}
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post("https://google.serper.dev/search", headers=headers, data=payload, timeout=10.0)
                return res.json().get("organic", [])[:3]
            except: return []

    async def _scrape_url(self, url: str):
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (AICDS-Bot)"})
                soup = BeautifulSoup(resp.text, "html.parser")
                for s in soup(["script", "style"]): s.decompose()
                return {"text": soup.get_text()[:1500], "title": soup.title.string if soup.title else "N/A"}
        except Exception as e:
            return {"error": f"Scrape failed: {str(e)}"}