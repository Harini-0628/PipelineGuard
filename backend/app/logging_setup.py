import json
import logging
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": datetime.now(UTC).isoformat(), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        for k in ("request_id", "method", "path", "status", "duration_ms"):
            if hasattr(record, k):
                data[k] = getattr(record, k)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data)


def configure_logging() -> None:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").disabled = True  # replaced by structured request log
