import re
import math
import yaml
import os

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "patterns.yaml"
)


def _load_config():
    with open(_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * __import__("math").log2(p) for p in prob)


def _get_text_sources(collector_output: dict) -> list:
    """Extract (source_url, text) pairs from collector output."""
    sources = []
    target = collector_output.get("target", "unknown")

    if collector_output.get("homepage_html"):
        sources.append((target, collector_output["homepage_html"]))

    for bundle in collector_output.get("js_bundles", []):
        if bundle.get("content"):
            sources.append((bundle["url"], bundle["content"]))

    for endpoint in collector_output.get("ai_endpoints", []):
        if endpoint.get("body_preview"):
            sources.append((endpoint["url"], endpoint["body_preview"]))

    for sf in collector_output.get("sensitive_files", []):
        if sf.get("body_preview"):
            sources.append((sf["url"], sf["body_preview"]))

    if collector_output.get("robots_txt"):
        sources.append((target + "/robots.txt", collector_output["robots_txt"]))

    return sources


def scan(collector_output: dict) -> list:
    """
    Scan all collected text content for credential patterns.

    Returns a list of finding dicts:
        source_url, credential_name, confidence, redacted_sample, description
    """
    config = _load_config()
    credentials = config.get("credentials", [])
    text_sources = _get_text_sources(collector_output)

    findings = []
    seen = set()  # Deduplicate by (url, name, redacted)

    for cred in credentials:
        name = cred.get("name", "Unknown")
        pattern = cred.get("regex", "")
        confidence = cred.get("confidence", "low")
        description = cred.get("description", "").strip()

        try:
            compiled = re.compile(pattern)
        except re.error:
            continue

        for source_url, text in text_sources:
            try:
                for match in compiled.finditer(text):
                    matched_str = match.group(0)

                    # For medium confidence: apply entropy check on the value portion
                    if confidence == "medium":
                        # Use last capturing group if present (usually the actual value)
                        check_str = (
                            match.group(match.lastindex)
                            if match.lastindex
                            else matched_str
                        )
                        if entropy(check_str) <= 4.5:
                            continue

                    # Redact: show first 6 chars only
                    redacted = (matched_str[:6] + "****") if len(matched_str) > 6 else "******"

                    key = (source_url, name, redacted)
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(
                        {
                            "source_url": source_url,
                            "credential_name": name,
                            "confidence": confidence,
                            "redacted_sample": redacted,
                            "description": description,
                        }
                    )
            except Exception:
                continue

    return findings
