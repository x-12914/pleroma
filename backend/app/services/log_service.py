from sqlalchemy.orm import Session
from app.db.models import DetectionLog, Feedback

class LogService:
    @staticmethod
    def create_log(db: Session, user_id: int, category: str, target: str, verdict: str, score: float, report: dict):
        db_log = DetectionLog(
            user_id=user_id,
            category=category,
            target=target,
            verdict=verdict,
            score=score,
            report_data=report
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log

    @staticmethod
    def get_user_logs(db: Session, user_id: int, limit: int = 100, offset: int = 0):
        return (
            db.query(DetectionLog)
            .filter(DetectionLog.user_id == user_id)
            .order_by(DetectionLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_stats(db: Session, user_id: int):
        logs = db.query(DetectionLog).filter(DetectionLog.user_id == user_id).all()
        total = len(logs)

        # Count threats: Malicious, Neptune, Satan, Ipsweep
        threats = len([l for l in logs if l.verdict.lower() in ['malicious', 'neptune', 'satan', 'ipsweep']])

        # Count suspicious: Suspicious verdicts
        suspicious = len([l for l in logs if l.verdict.lower() == 'suspicious'])

        # "Safe" is total minus threats and suspicious (includes Normal, Safe, etc.)
        safe = total - threats - suspicious

        return {
            "total_scans": total,
            "threats_detected": threats,
            "clean_scans": safe  # Now includes all non-dangerous verdicts
        }

    @staticmethod
    def create_feedback(db: Session, log_id: int, feedback_data, user_id: int):
        feedback = Feedback(
            log_id=log_id,
            is_correct=feedback_data.is_correct,
            corrected_verdict=feedback_data.corrected_verdict,
            user_id=user_id,
        )
        db.add(feedback)
        db.commit()
        db.refresh(feedback)
        return feedback