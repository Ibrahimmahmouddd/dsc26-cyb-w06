"""Checking the model's reply before an analyst sees it. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .normalize import detect_injection  # noqa: F401  (used by triage)

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
NEXT_STEPS = {"escalate_to_analyst", "request_more_context", "monitor", "open_incident"}
ALLOWED_LINK_HOSTS = {"attack.mitre.org", "hisn.local"}


class Rejected(Exception):
    """Raised by parse_model_output / triage when the reply cannot be accepted. Keeps .reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class TriageResult:
    severity: str
    summary_html: str
    next_step: str
    related_alert_ids: list[str]
    flags: list[str] = field(default_factory=list)


_FENCE = re.compile(r"^```(?:json)?[^\n]*\n(.*)\n```$", re.S)
_FORBIDDEN_KEYS = {"action", "actions", "tool_call", "tool_calls", "function_call"}
_TENANT_REF = re.compile(r"TEN-[0-9]{3}")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]*)\)")
_BARE = re.compile(r"https?://[^\s<>)\]]+")


def _host_ok(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return parts.scheme in ("http", "https") and parts.hostname in ALLOWED_LINK_HOSTS
    except ValueError:
        return False


def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Parse, validate and clean one model reply."""
    text = raw.strip()
    m = _FENCE.match(text)
    if m:
        text = m.group(1)
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        raise Rejected("not_json")
    if not isinstance(obj, dict):
        raise Rejected("not_json")

    step = obj.get("next_step")
    if any(k in obj for k in _FORBIDDEN_KEYS) or (isinstance(step, str) and "close" in step):
        raise Rejected("forbidden_action")

    severity = obj.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise Rejected("bad_severity")
    if not isinstance(step, str) or step not in NEXT_STEPS:
        raise Rejected("bad_next_step")
    summary = obj.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary.strip()) > 600:
        raise Rejected("bad_summary")
    related = obj.get("related_alert_ids", [])
    if not isinstance(related, list) or not all(isinstance(i, str) for i in related):
        raise Rejected("bad_related_alert_ids")

    if any(t != tenant_id for t in _TENANT_REF.findall(summary)):
        raise Rejected("cross_tenant_reference")

    flags = set()
    seen, ids = set(), []
    for i in related:
        if i in seen:
            continue
        seen.add(i)
        if i in known_alert_ids:
            ids.append(i)
        else:
            flags.add("unknown_alert_id")

    summary = summary.strip()
    if _IMAGE.search(summary):
        summary = _IMAGE.sub("[image removed]", summary)
        flags.add("image_removed")

    kept = []

    def link_sub(mt):
        if _host_ok(mt.group(2)):
            kept.append(mt.group(0))
            return "\x00%d\x00" % (len(kept) - 1)
        flags.add("link_removed")
        return mt.group(1)

    summary = _LINK.sub(link_sub, summary)

    def bare_sub(mt):
        if _host_ok(mt.group(0)):
            return mt.group(0)
        flags.add("link_removed")
        return "[link removed]"

    summary = _BARE.sub(bare_sub, summary)
    for n, original in enumerate(kept):
        summary = summary.replace("\x00%d\x00" % n, original)

    summary = html.escape(summary, quote=True)
    return TriageResult(severity, summary, step, ids, sorted(flags))


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Run detect_injection over every string in `alert`, then parse_model_output."""
    result = parse_model_output(raw_output, tenant_id=tenant_id, known_alert_ids=known_alert_ids)
    codes = set()
    for s in _strings(alert):
        codes.update(detect_injection(s))
    if codes:
        flags = set(result.flags) | {"possible_injection"} | {f"signal:{c}" for c in codes}
        result.flags = sorted(flags)
        if SEVERITIES.index(result.severity) < SEVERITIES.index("high"):
            result.severity = "high"
        if result.next_step == "monitor":
            result.next_step = "escalate_to_analyst"
    return result