"""Production server settings (gunicorn managing uvicorn workers). No auto-reload."""
import multiprocessing
import os

bind = os.environ.get("PG_BIND", "0.0.0.0:8000")
worker_class = "app.workers.PipelineGuardWorker"
workers = int(os.environ.get("PG_WORKERS", max(2, min(4, multiprocessing.cpu_count()))))
timeout = 60
graceful_timeout = 30
keepalive = 5
max_requests = 2000
max_requests_jitter = 200
accesslog = None          # structured request logging is done by the application middleware
errorlog = "-"
forwarded_allow_ips = os.environ.get("PG_FORWARDED_ALLOW_IPS", "127.0.0.1")
limit_request_line = 4094
limit_request_fields = 50
