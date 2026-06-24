from sqlalchemy import case, func, text
from sqlalchemy.orm import Session
from app.db.models import DetectionLog, Feedback


# Verdict labels treated as malicious-tier in the stat tallies.
# Kept lowercase; we compare against `lower(verdict)` in the query.
_MALICIOUS_VERDICTS = ('malicious', 'neptune', 'satan', 'ipsweep')

# Severity ordering for collapsing a source's many verdicts into one "worst".
_VERDICT_SEVERITY = {"malicious": 3, "suspicious": 2, "error": 1, "normal": 0, "safe": 0}


def _worst_verdict(verdicts: list[str]) -> str:
    """Pick the most severe verdict from a source's detections."""
    best, label = -1, "Unknown"
    for v in verdicts:
        rank = _VERDICT_SEVERITY.get((v or "").lower(), 0)
        if rank > best:
            best, label = rank, v
    return label


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
    def get_scan_sources(db: Session, user_id: int, hours: int = 24, limit: int = 100):
        """Aggregate network detections by source IP into 'scan campaigns'.

        On a public box a single scanner produces dozens of near-identical rows;
        grouping by src_ip collapses that into one line per source (how many
        detections, which threat classes, how many distinct ports it hit, the
        worst verdict, and the time span) so the dashboard stays readable.

        Grouped in Postgres (JSONB extraction + aggregates), not in Python, so it
        stays fast over large detection_logs.
        """
        sql = text(
            """
            SELECT report_data->>'src_ip'                       AS src_ip,
                   count(*)                                      AS detections,
                   array_agg(DISTINCT report_data->>'raw_class') AS classes,
                   count(DISTINCT report_data->'raw_input'->>'Dst Port') AS ports,
                   array_agg(DISTINCT verdict)                   AS verdicts,
                   min(timestamp)                                AS first_seen,
                   max(timestamp)                                AS last_seen
            FROM detection_logs
            WHERE category = 'NETWORK_TRAFFIC'
              AND user_id = :uid
              AND report_data->>'src_ip' IS NOT NULL
              AND timestamp > now() - make_interval(hours => :hours)
            GROUP BY report_data->>'src_ip'
            ORDER BY detections DESC
            LIMIT :limit
            """
        )
        rows = db.execute(sql, {"uid": user_id, "hours": hours, "limit": limit}).fetchall()
        result = []
        for r in rows:
            classes = [c for c in (r.classes or []) if c]
            verdicts = [v for v in (r.verdicts or []) if v]
            result.append({
                "src_ip": r.src_ip,
                "detections": int(r.detections),
                "classes": classes,
                "ports": int(r.ports or 0),
                "verdict": _worst_verdict(verdicts),
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
            })
        return result

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