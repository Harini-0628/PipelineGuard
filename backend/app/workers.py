from uvicorn.workers import UvicornWorker


class PipelineGuardWorker(UvicornWorker):
    """Uvicorn worker that does not advertise the server software in a `Server` header."""
    CONFIG_KWARGS = {"loop": "auto", "http": "auto", "server_header": False}
