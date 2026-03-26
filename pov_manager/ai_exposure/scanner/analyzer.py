import re
import yaml
import os
from bs4 import BeautifulSoup

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "patterns.yaml"
)


def _load_config():
    with open(_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def _extract_snippet(text: str, needle: str, radius: int = 80) -> str:
    if not text or not needle:
        return ""
    lower_text = text.lower()
    lower_needle = needle.lower()
    idx = lower_text.find(lower_needle)
    if idx == -1:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    return snippet[:220]


def _classify_finding(ftype: str) -> tuple[str, str]:
    category_map = {
        "ai_fingerprint": ("technology", "ai_sdk"),
        "chatbot_fingerprint": ("technology", "chatbot"),
        "mcp_exposed": ("exposure", "mcp"),
        "prompt_leakage": ("exposure", "prompt_leakage"),
        "vector_exposed": ("exposure", "vector_db"),
        "embedding_exposed": ("exposure", "embedding_endpoint"),
        "agent_framework_exposed": ("technology", "agent_framework"),
        "plugin_manifest_exposed": ("exposure", "plugin_manifest"),
        "trace_log_exposed": ("exposure", "trace_log"),
        "inference_api_exposed": ("exposure", "inference_api"),
        "admin_playground_exposed": ("exposure", "ai_admin_surface"),
        "missing_auth": ("control_gap", "missing_auth"),
        "missing_rate_limiting": ("control_gap", "missing_rate_limit"),
        "missing_csrf": ("control_gap", "missing_csrf"),
        "open_api_docs": ("exposure", "api_docs"),
        "source_map_exposed": ("exposure", "source_map"),
        "open_storage_bucket": ("exposure", "storage"),
    }
    return category_map.get(ftype, ("other", ftype))


def analyze(collector_output: dict) -> list:
    """
    Analyze collector output for AI fingerprints and vulnerability signals.

    Returns a list of finding dicts:
        type, name, source_url, description, evidence, confidence, category, subtype, evidence_snippet, matched_indicators
    """
    config = _load_config()
    findings = []

    target = collector_output.get("target", "unknown")
    homepage_html = collector_output.get("homepage_html", "") or ""
    js_bundles = collector_output.get("js_bundles", [])
    ai_endpoints = collector_output.get("ai_endpoints", [])
    sensitive_files = collector_output.get("sensitive_files", [])

    # All text sources: (url, text)
    all_sources = [(target, homepage_html)]
    for bundle in js_bundles:
        all_sources.append((bundle["url"], bundle.get("content", "")))
    for sf in sensitive_files:
        all_sources.append((sf["url"], sf.get("body_preview", "")))

    # ── AI SDK fingerprints ───────────────────────────────────────────────────
    # Gate logic:
    #   If `strong_patterns` are defined for a fingerprint, at least one must
    #   match before flagging — this prevents bare keyword hits on integration
    #   platform UI bundles (e.g. n8n listing "openai" as a node name).
    #   If no `strong_patterns` are defined, require at least 2 `patterns` hits.
    for fp in config.get("ai_fingerprints", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_strong = fp.get("strong_patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break

            # Collect strong-pattern hits
            strong_hits = []
            for pat in fp_strong:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        strong_hits.append(pat)
                except re.error:
                    pass

            # Collect weak-pattern hits
            weak_hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        weak_hits.append(pat)
                except re.error:
                    pass

            # Decide whether to flag
            if fp_strong:
                # Strong patterns defined: require at least one strong hit
                if not strong_hits:
                    continue
                evidence_hits = strong_hits[:3]
                # Append any additional weak hits to enrich evidence
                extra = [h for h in weak_hits if h not in evidence_hits]
                evidence_hits += extra[:2]
            else:
                # No strong patterns: require at least 2 weak hits
                if len(weak_hits) < 2:
                    continue
                evidence_hits = weak_hits[:3]

            findings.append(
                {
                    "type": "ai_fingerprint",
                    "name": fp_name,
                    "source_url": source_url,
                    "description": fp_desc,
                    "evidence": f"Matched: {', '.join(evidence_hits)}",
                    "confidence": fp_confidence,
                }
            )
            matched = True

    # ── MCP fingerprints ──────────────────────────────────────────────────────
    for fp in config.get("mcp_fingerprints", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if hits:
                findings.append(
                    {
                        "type": "mcp_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:3])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Prompt / instruction leakage ──────────────────────────────────────────
    for fp in config.get("prompt_leakage_patterns", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "prompt_leakage",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Vector DB fingerprints ────────────────────────────────────────────────
    for fp in config.get("vector_fingerprints", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if hits:
                findings.append(
                    {
                        "type": "vector_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:3])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Embedding / retrieval exposure ────────────────────────────────────────
    for fp in config.get("embedding_patterns", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "embedding_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Agent framework fingerprints ──────────────────────────────────────────
    for fp in config.get("agent_framework_fingerprints", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "agent_framework_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Plugin / manifest exposure ───────────────────────────────────────────
    for fp in config.get("plugin_manifest_patterns", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "plugin_manifest_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Trace / eval / transcript exposure ───────────────────────────────────
    for fp in config.get("trace_log_patterns", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "trace_log_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Inference / model API exposure ───────────────────────────────────────
    for fp in config.get("inference_fingerprints", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "inference_api_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── AI admin / playground / debug exposure ───────────────────────────────
    for fp in config.get("admin_playground_patterns", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_confidence = fp.get("confidence", "medium")
        fp_desc = fp.get("description", "")

        matched = False
        for source_url, text in all_sources:
            if matched:
                break
            hits = []
            for pat in fp_patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                except re.error:
                    pass
            if len(hits) >= 2:
                findings.append(
                    {
                        "type": "admin_playground_exposed",
                        "name": fp_name,
                        "source_url": source_url,
                        "description": fp_desc,
                        "evidence": f"Matched: {', '.join(hits[:4])}",
                        "confidence": fp_confidence,
                    }
                )
                matched = True

    # ── Chatbot fingerprints (HTML only) ──────────────────────────────────────
    for fp in config.get("chatbot_fingerprints", []):
        fp_name = fp["name"]
        fp_patterns = fp.get("patterns", [])
        fp_desc = fp.get("description", "")

        hits = []
        for pat in fp_patterns:
            try:
                if re.search(pat, homepage_html, re.IGNORECASE):
                    hits.append(pat)
            except re.error:
                pass
        if hits:
            findings.append(
                {
                    "type": "chatbot_fingerprint",
                    "name": fp_name,
                    "source_url": target,
                    "description": fp_desc,
                    "evidence": f"Matched: {', '.join(hits[:3])}",
                    "confidence": "medium",
                }
            )

    # ── Vulnerability signals ─────────────────────────────────────────────────
    vuln = config.get("vulnerability_signals", {})

    # Missing auth + rate limiting on 200 AI endpoints
    auth_cfg = vuln.get("missing_auth_indicators", {})
    auth_absence_headers = [h.lower() for h in auth_cfg.get("absence_of_headers", [])]
    auth_absence_body = [p.lower() for p in auth_cfg.get("absence_of_body_patterns", [])]

    rl_cfg = vuln.get("missing_rate_limit_headers", {})
    rl_absence_headers = [h.lower() for h in rl_cfg.get("absence_of_headers", [])]

    for ep in ai_endpoints:
        if ep.get("status_code") != 200:
            continue
        url = ep["url"]
        headers_lower = {k.lower(): v for k, v in ep.get("headers", {}).items()}
        body_lower = (ep.get("body_preview", "") or "").lower()

        # Gate: skip responses that don't look like real AI endpoints.
        # Require JSON content-type plus either AI keywords or common OpenAI-style
        # response structure markers to reduce false positives from generic APIs.
        content_type = headers_lower.get("content-type", "")
        is_json_response = "json" in content_type
        ai_response_keywords = ["model", "tokens", "completion", "embedding", "inference"]
        matched_keywords = [kw for kw in ai_response_keywords if kw in body_lower]
        ai_response_markers = [
            '"choices"',
            '"usage"',
            '"object":"model"',
            '"object": "model"',
            '"data":',
            '"embedding"',
            '"model"',
        ]
        matched_markers = [m for m in ai_response_markers if m in body_lower]

        if not is_json_response:
            continue
        if not matched_keywords and not matched_markers:
            continue

        evidence_parts = []
        if matched_keywords:
            evidence_parts.append(f"keywords: {', '.join(matched_keywords)}")
        if matched_markers:
            evidence_parts.append(f"markers: {', '.join(matched_markers[:3])}")
        evidence_detail = f"JSON response with AI content — Content-Type: {content_type}; {'; '.join(evidence_parts)}"

        # Check missing auth
        has_auth_header = any(h in headers_lower for h in auth_absence_headers)
        has_auth_body = any(p in body_lower for p in auth_absence_body)
        if not has_auth_header and not has_auth_body:
            findings.append(
                {
                    "type": "missing_auth",
                    "name": "Unauthenticated AI Endpoint",
                    "source_url": url,
                    "description": auth_cfg.get("description", "").strip(),
                    "evidence": f"HTTP 200 with no auth indicators — {evidence_detail}",
                    "confidence": "high",
                }
            )

        # Check missing rate limiting (same gate — only real AI endpoints)
        has_rate_limit = any(h in headers_lower for h in rl_absence_headers)
        if not has_rate_limit:
            findings.append(
                {
                    "type": "missing_rate_limiting",
                    "name": "No Rate Limiting on AI Endpoint",
                    "source_url": url,
                    "description": rl_cfg.get("description", "").strip(),
                    "evidence": (
                        f"No rate limit headers — {evidence_detail}"
                    ),
                    "confidence": "medium",
                }
            )

    # Open API docs
    api_cfg = vuln.get("open_api_docs", {})
    api_body_patterns = [p.lower() for p in api_cfg.get("response_body_patterns", [])]
    for sf in sensitive_files:
        if sf.get("status_code") == 200:
            body_lower = (sf.get("body_preview", "") or "").lower()
            hits = [p for p in api_body_patterns if p in body_lower]
            if hits:
                findings.append(
                    {
                        "type": "open_api_docs",
                        "name": "Open API Documentation",
                        "source_url": sf["url"],
                        "description": api_cfg.get("description", "").strip(),
                        "evidence": f"API doc patterns found: {', '.join(hits[:3])}",
                        "confidence": "high",
                    }
                )

    # Exposed source maps
    sm_cfg = vuln.get("exposed_source_maps", {})
    inline_pattern = sm_cfg.get("inline_pattern", "")
    sm_extensions = sm_cfg.get("file_extensions", [])

    for bundle in js_bundles:
        content = bundle.get("content", "")
        if inline_pattern and inline_pattern in content:
            findings.append(
                {
                    "type": "source_map_exposed",
                    "name": "JavaScript Source Map Reference Exposed",
                    "source_url": bundle["url"],
                    "description": sm_cfg.get("description", "").strip(),
                    "evidence": f"Found '{inline_pattern}' in bundle",
                    "confidence": "high",
                }
            )

    for sf in sensitive_files:
        if sf.get("status_code") == 200:
            for ext in sm_extensions:
                if sf["url"].endswith(ext):
                    findings.append(
                        {
                            "type": "source_map_exposed",
                            "name": "Source Map File Accessible",
                            "source_url": sf["url"],
                            "description": sm_cfg.get("description", "").strip(),
                            "evidence": f"Source map accessible at {sf['url']}",
                            "confidence": "high",
                        }
                    )

    # Missing CSRF on AI-related forms
    csrf_cfg = vuln.get("missing_csrf", {})
    csrf_absence = [p.lower() for p in csrf_cfg.get("absence_of_input_patterns", [])]

    if homepage_html:
        soup = BeautifulSoup(homepage_html, "html.parser")
        for form in soup.find_all("form"):
            action = (form.get("action") or "").lower()
            form_html = str(form).lower()
            # "query" and "ask" removed — too broad, fire on any search form
            ai_keywords = ["chat", "ai", "completion", "generate", "predict"]
            ai_related = any(kw in action or kw in form_html for kw in ai_keywords)
            if ai_related:
                has_csrf = any(p in form_html for p in csrf_absence)
                if not has_csrf:
                    findings.append(
                        {
                            "type": "missing_csrf",
                            "name": "Missing CSRF Token on AI Form",
                            "source_url": target,
                            "description": csrf_cfg.get("description", "").strip(),
                            "evidence": (
                                f"AI form (action='{form.get('action', '')}') "
                                f"has no CSRF token input"
                            ),
                            "confidence": "medium",
                        }
                    )

    # Open storage buckets
    storage_cfg = vuln.get("open_storage_buckets", {})
    storage_patterns = storage_cfg.get("url_patterns", [])

    all_text = homepage_html + " ".join(b.get("content", "") for b in js_bundles)
    seen_storage = set()

    # Extract all URLs from content, then test against patterns
    url_candidates = re.findall(r'https?://[^\s"\'<>]+', all_text)
    for candidate in url_candidates:
        for pat in storage_patterns:
            try:
                if re.search(pat, candidate, re.IGNORECASE):
                    key = (pat, candidate[:60])
                    if key not in seen_storage:
                        seen_storage.add(key)
                        findings.append(
                            {
                                "type": "open_storage_bucket",
                                "name": "Potential Open Cloud Storage URL",
                                "source_url": target,
                                "description": storage_cfg.get("description", "").strip(),
                                "evidence": f"Storage URL found: {candidate[:120]}",
                                "confidence": "medium",
                            }
                        )
            except re.error:
                pass

    return findings
