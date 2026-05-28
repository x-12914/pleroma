import httpx
from app.core.config import settings

class EmbeddingService:
    # This model produces 384-dimensional vectors
    HF_URL = "https://api-inference.huggingface.co/models/sentence-transformers/all-MiniLM-L6-v2"

    @classmethod
    async def get_embedding(cls, text: str):
        if not settings.HF_API_KEY:
            return None
        
        headers = {"Authorization": f"Bearer {settings.HF_API_KEY}"}
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(cls.HF_URL, headers=headers, json={"inputs": text}, timeout=10.0)
                if response.status_code == 200:
                    return response.json()
                return None
            except Exception:
                return None