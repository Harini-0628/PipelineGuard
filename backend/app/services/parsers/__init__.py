from collections.abc import Callable
from typing import Any

from app.services.normalize import ParsedReport, ParseError
from app.services.parsers import semgrep, trivy

PARSERS: dict[str, Callable[[Any], ParsedReport]] = {"semgrep": semgrep.parse, "trivy": trivy.parse, "trivy-image": trivy.parse}


def parse_report(scanner: str, raw: Any) -> ParsedReport:
    try:
        return PARSERS[scanner](raw)
    except KeyError as e:
        raise ParseError(f"unsupported scanner '{scanner}'") from e
