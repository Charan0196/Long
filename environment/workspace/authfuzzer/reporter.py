from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any
from authfuzzer.models import FuzzReport


class FuzzReporter:
    """Serializes and deserializes structured fuzzing reports."""

    @staticmethod
    def to_json(report: FuzzReport, indent: int = 2) -> str:
        """Format a FuzzReport as deterministic JSON string."""
        data = report.to_dict()
        return json.dumps(data, indent=indent, sort_keys=True)

    @staticmethod
    def save(report: FuzzReport, path: str | Path) -> None:
        """Write report to file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(FuzzReporter.to_json(report), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> Dict[str, Any]:
        """Read report dictionary from file."""
        p = Path(path)
        return json.loads(p.read_text(encoding="utf-8"))
