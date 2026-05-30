import asyncio
import uuid
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.db.models import AnalysisTask # <--- New Import
from app.services.log_service import LogService
from app.services.intelligence.engine import IntelligenceEngine
from app.services.network.engine import NetworkEngine

# Instantiate engines once (Singleton)
intel_engine = IntelligenceEngine()
network_engine = NetworkEngine()

class AnalysisService:

    @staticmethod
    def create_task(db: Session, category: str, target: str, user_id: int):
        """Creates a persistent task record in Neon."""
        task_id = str(uuid.uuid4())
        new_task = AnalysisTask(
            id=task_id,
            user_id=user_id,
            category=category,  # <--- SAVE CATEGORY
            target=target,      # <--- SAVE TARGET
            status="pending"
        )
        db.add(new_task)
        db.commit()
        return task_id

    # ... (rest of the service remains the same)

    @classmethod
    def schedule_url_analysis(cls, task_id: str, url: str, user_id: int):
        # We don't need a loop check usually in FastAPI, BackgroundTasks handles it.
        # But keeping your pattern for safety:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(cls._run_url_analysis(task_id, url, user_id))
        except RuntimeError:
            asyncio.run(cls._run_url_analysis(task_id, url, user_id))

    @classmethod
    def schedule_network_analysis(cls, task_id: str, record, user_id: int):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(cls._run_network_analysis(task_id, record, user_id))
        except RuntimeError:
            asyncio.run(cls._run_network_analysis(task_id, record, user_id))

    @classmethod
    async def _run_url_analysis(cls, task_id: str, url: str, user_id: int):
        # Use SessionLocal for background database operations
        with SessionLocal() as db:
            # 1. Mark task as processing
            task = db.query(AnalysisTask).filter(AnalysisTask.id == task_id).first()
            if task:
                task.status = "processing"
                db.commit()

            try:
                # 2. Run Intelligence Engine
                report = await intel_engine.analyze_url(url)
                
                verdict = report.get("verdict", "Unknown")
                confidence = report.get("confidence", 0)
                score = float(confidence) / 100.0 if isinstance(confidence, (int, float)) else 0.0
                
                # 3. Create Permanent Log
                LogService.create_log(db, user_id, "URL_SCAN", url, verdict, score, report)
                
                # 4. Update Task Status to Completed
                task.status = "completed"
                task.result = report
                db.commit()
                print(f"✅ URL Task {task_id} Completed: {verdict}")

            except Exception as exc:
                print(f"❌ URL Task {task_id} Failed: {str(exc)}")
                task.status = "failed"
                task.result = {"error": str(exc)}
                db.commit()

    @classmethod
    async def _run_network_analysis(cls, task_id: str, record, user_id: int):
        with SessionLocal() as db:
            task = db.query(AnalysisTask).filter(AnalysisTask.id == task_id).first()
            if task:
                task.status = "processing"
                db.commit()

            try:
                # 1. Run ML Prediction (now returns 3-tuple under CIC schema)
                loop = asyncio.get_running_loop()
                ml_verdict, ml_confidence, ml_raw_class = await loop.run_in_executor(
                    None, network_engine.predict, record
                )

                # 2. LLM interpretation — sees the raw CIC class for context
                ai_reason = await network_engine.get_ai_interpretation(
                    record, ml_verdict, ml_confidence, ml_raw_class
                )

                report = {
                    "model_verdict": ml_verdict,
                    "confidence": ml_confidence,
                    "raw_class": ml_raw_class,
                    "reason": ai_reason,
                    "raw_input": record,
                }

                # 3. Log to DB
                LogService.create_log(db, user_id, "NETWORK_TRAFFIC", "Internal Network", ml_verdict, ml_confidence, report)
                
                # 4. Finalize Task
                task.status = "completed"
                task.result = report
                db.commit()
            except Exception as e:
                print(f"❌ Network Task {task_id} Failed: {str(e)}")
                task.status = "failed"
                task.result = {"error": str(e)}
                db.commit()