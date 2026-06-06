from sqlalchemy import case, func
from sqlalchemy.orm import Session
from app.db.models import DetectionLog, Feedback


# Verdict labels treated as malicious-tier in the stat tallies.
# Kept lowercase; we compare against `lower(verdict)` in the query.
_MALICIOUS_VERDICTS = ('malicious', 'neptune', 'satan', 'ipsweep')


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
        """Aggregate verdict counts in the database, not in Python.

        Previous impl pulled every row (including the JSONB report_data
        column, which carries the full feature vector / OSINT blobs) into
        memory and counted with list comprehensions. At ~120k rows the
        single endpoint took ~19s and saturated the connection pool, so
        subsequent calls timed out.

        This version runs a single COUNT + two SUM(CASE...) in Postgres
        and returns three integers — typically sub-10ms regardless of
        row count.
        """
        lower_verdict = func.lower(DetectionLog.verdict)

        threat_sum = func.sum(
            case((lower_verdict.in_(_MALICIOUS_VERDICTS), 1), else_=0)
        )
        suspicious_sum = func.sum(
            case((lower_verdict == 'suspicious', 1), else_=0)
        )

        row = (
            db.query(
                func.count().label('total'),
                threat_sum.label('threats'),
                suspicious_sum.label('suspicious'),
            )
            .filter(DetectionLog.user_id == user_id)
            .one()
        )

        total = int(row.total or 0)
        threats = int(row.threats or 0)
        suspicious = int(row.suspicious or 0)
        safe = max(total - threats - suspicious, 0)

        return {
            "total_scans": total,
            "threats_detected": threats,
            "clean_scans": safe,
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