"""
Frost Gate Spear Observability

Logging, metrics, and tracing infrastructure.
"""

import logging
import logging.handlers
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional
from uuid import UUID, uuid4

from ..core.config import Config


# Structured logging formatter
class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields
        if hasattr(record, "mission_id"):
            log_data["mission_id"] = record.mission_id
        if hasattr(record, "action_id"):
            log_data["action_id"] = record.action_id
        if hasattr(record, "classification"):
            log_data["classification"] = record.classification
        if hasattr(record, "trace_id"):
            log_data["trace_id"] = record.trace_id
        if hasattr(record, "span_id"):
            log_data["span_id"] = record.span_id

        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


def setup_logging(
    level: str = "INFO",
    json_format: bool = True,
    log_file: Optional[str] = None,
) -> None:
    """
    Configure application logging.

    Args:
        level: Log level
        json_format: Use JSON formatting
        log_file: Optional log file path
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Create formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10,
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


# Metrics collection
@dataclass
class MetricValue:
    """Single metric value."""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """
    Metrics collector for Prometheus-style metrics.
    """

    def __init__(self):
        """Initialize metrics collector."""
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._labels: Dict[str, Dict[str, str]] = {}

    def counter_inc(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """Increment a counter."""
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value
        if labels:
            self._labels[key] = labels

    def gauge_set(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """Set a gauge value."""
        key = self._make_key(name, labels)
        self._gauges[key] = value
        if labels:
            self._labels[key] = labels

    def histogram_observe(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """Observe a histogram value."""
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)
        if labels:
            self._labels[key] = labels

    @contextmanager
    def timer(
        self,
        name: str,
        labels: Optional[Dict[str, str]] = None,
    ) -> Generator[None, None, None]:
        """Context manager for timing operations."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.histogram_observe(name, duration, labels)

    def _make_key(
        self,
        name: str,
        labels: Optional[Dict[str, str]],
    ) -> str:
        """Create metric key with labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics as dictionary."""
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                k: {
                    "count": len(v),
                    "sum": sum(v),
                    "avg": sum(v) / len(v) if v else 0,
                    "min": min(v) if v else 0,
                    "max": max(v) if v else 0,
                }
                for k, v in self._histograms.items()
            },
        }

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []

        for key, value in self._counters.items():
            lines.append(f"# TYPE {key.split('{')[0]} counter")
            lines.append(f"{key} {value}")

        for key, value in self._gauges.items():
            lines.append(f"# TYPE {key.split('{')[0]} gauge")
            lines.append(f"{key} {value}")

        for key, values in self._histograms.items():
            base_name = key.split("{")[0]
            count = len(values)
            total = sum(values)
            lines.append(f"# TYPE {base_name} histogram")
            lines.append(f"{key}_count {count}")
            lines.append(f"{key}_sum {total}")

        return "\n".join(lines)


# Distributed tracing
@dataclass
class Span:
    """Tracing span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "OK"

    def finish(self, status: str = "OK") -> None:
        """Finish the span."""
        self.end_time = datetime.utcnow()
        self.status = status

    def log(self, message: str, **kwargs: Any) -> None:
        """Add log entry to span."""
        self.logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
            **kwargs,
        })

    def set_tag(self, key: str, value: str) -> None:
        """Set span tag."""
        self.tags[key] = value

    def duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return None


class Tracer:
    """
    Distributed tracer for request tracking.
    """

    def __init__(self, service_name: str):
        """Initialize tracer."""
        self.service_name = service_name
        self._spans: Dict[str, Span] = {}
        self._active_span: Optional[Span] = None

    def start_span(
        self,
        operation_name: str,
        parent: Optional[Span] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> Span:
        """Start a new span."""
        trace_id = parent.trace_id if parent else str(uuid4())
        parent_span_id = parent.span_id if parent else None

        span = Span(
            trace_id=trace_id,
            span_id=str(uuid4()),
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.utcnow(),
            tags=tags or {},
        )

        span.tags["service"] = self.service_name
        self._spans[span.span_id] = span
        self._active_span = span

        return span

    @contextmanager
    def span(
        self,
        operation_name: str,
        tags: Optional[Dict[str, str]] = None,
    ) -> Generator[Span, None, None]:
        """Context manager for spans."""
        span = self.start_span(
            operation_name,
            parent=self._active_span,
            tags=tags,
        )
        try:
            yield span
        except Exception as e:
            span.status = "ERROR"
            span.set_tag("error", str(e))
            raise
        finally:
            span.finish()

    def get_trace(self, trace_id: str) -> List[Span]:
        """Get all spans for a trace."""
        return [s for s in self._spans.values() if s.trace_id == trace_id]

    def export_spans(self) -> List[Dict[str, Any]]:
        """Export spans for external tracing system."""
        return [
            {
                "trace_id": s.trace_id,
                "span_id": s.span_id,
                "parent_span_id": s.parent_span_id,
                "operation_name": s.operation_name,
                "start_time": s.start_time.isoformat(),
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "duration_ms": s.duration_ms(),
                "tags": s.tags,
                "logs": s.logs,
                "status": s.status,
            }
            for s in self._spans.values()
        ]


# Global instances
_metrics = MetricsCollector()
_tracer: Optional[Tracer] = None


def get_metrics() -> MetricsCollector:
    """Get global metrics collector."""
    return _metrics


def get_tracer(service_name: str = "frostgate-spear") -> Tracer:
    """Get or create global tracer."""
    global _tracer
    if _tracer is None:
        _tracer = Tracer(service_name)
    return _tracer


# Pre-defined metrics for Frost Gate Spear
class FrostGateMetrics:
    """Pre-defined metrics for the platform."""

    @staticmethod
    def mission_created(classification: str) -> None:
        """Record mission creation."""
        _metrics.counter_inc(
            "frostgate_missions_created_total",
            labels={"classification": classification},
        )

    @staticmethod
    def mission_completed(classification: str, success: bool) -> None:
        """Record mission completion."""
        _metrics.counter_inc(
            "frostgate_missions_completed_total",
            labels={"classification": classification, "success": str(success).lower()},
        )

    @staticmethod
    def action_executed(action_type: str, status: str) -> None:
        """Record action execution."""
        _metrics.counter_inc(
            "frostgate_actions_total",
            labels={"type": action_type, "status": status},
        )

    @staticmethod
    def action_duration(action_type: str, duration_seconds: float) -> None:
        """Record action duration."""
        _metrics.histogram_observe(
            "frostgate_action_duration_seconds",
            duration_seconds,
            labels={"type": action_type},
        )

    @staticmethod
    def policy_violation(violation_type: str) -> None:
        """Record policy violation."""
        _metrics.counter_inc(
            "frostgate_policy_violations_total",
            labels={"type": violation_type},
        )

    @staticmethod
    def forensic_completeness(mission_id: str, completeness: float) -> None:
        """Record forensic completeness."""
        _metrics.gauge_set(
            "frostgate_forensic_completeness",
            completeness,
            labels={"mission_id": mission_id},
        )

    @staticmethod
    def active_missions(count: int) -> None:
        """Record active mission count."""
        _metrics.gauge_set("frostgate_active_missions", count)

    @staticmethod
    def fl_round_completed(ring: str, participants: int) -> None:
        """Record FL round completion."""
        _metrics.counter_inc(
            "frostgate_fl_rounds_total",
            labels={"ring": ring},
        )
        _metrics.gauge_set(
            "frostgate_fl_participants",
            participants,
            labels={"ring": ring},
        )
