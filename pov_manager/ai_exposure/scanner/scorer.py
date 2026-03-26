import yaml
import os

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "patterns.yaml"
)


def _load_config():
    with open(_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def score(findings: list, secrets: list) -> dict:
    """
    Calculate a risk score from analyzer findings and secret detections.

    Returns a dict with:
        total_score, risk_level, risk_label, risk_color,
        score_breakdown, finding_count
    """
    config = _load_config()
    weights = config["scoring"]["weights"]
    thresholds = config["scoring"]["thresholds"]

    total = 0
    breakdown = []

    # Score secrets
    for secret in secrets:
        confidence = secret.get("confidence", "low")
        name = secret.get("credential_name", "")
        ai_providers = ["openai", "anthropic", "hugging face", "cohere", "mistral", "replicate"]

        if confidence == "high":
            if any(p in name.lower() for p in ai_providers):
                w = weights["exposed_ai_key_high"]
                label = f"Exposed AI key (high): {name}"
            else:
                w = weights["exposed_cloud_key_high"]
                label = f"Exposed cloud key (high): {name}"
        elif confidence == "medium":
            w = weights["exposed_key_medium"]
            label = f"Exposed key (medium): {name}"
        else:
            w = weights["exposed_key_low"]
            label = f"Exposed key (low): {name}"

        total += w
        breakdown.append({"item": label, "score": w})

    # Score analyzer findings
    type_map = {
        "missing_auth": ("public_ai_endpoint_no_auth", "Unauthenticated AI endpoint"),
        "open_api_docs": ("open_api_docs_ai_routes", "Open API docs"),
        "open_storage_bucket": ("open_storage_bucket", "Open storage bucket"),
        "source_map_exposed": ("source_map_exposed", "Exposed source map"),
        "ai_fingerprint": ("ai_sdk_in_public_bundle", "AI SDK in public bundle"),
        "chatbot_fingerprint": ("chatbot_detected_no_validation", "Chatbot detected"),
        "missing_rate_limiting": ("no_rate_limiting_on_ai_endpoint", "No rate limiting"),
        "missing_csrf": ("missing_csrf_on_ai_form", "Missing CSRF on AI form"),
        "mcp_exposed": ("mcp_exposed", "MCP exposure"),
        "prompt_leakage": ("prompt_leakage", "Prompt leakage"),
        "vector_exposed": ("vector_exposed", "Vector DB exposure"),
        "embedding_exposed": ("embedding_exposed", "Embedding / retrieval exposure"),
        "agent_framework_exposed": ("agent_framework_exposed", "Agent framework exposure"),
        "plugin_manifest_exposed": ("plugin_manifest_exposed", "Plugin / manifest exposure"),
        "trace_log_exposed": ("trace_log_exposed", "Trace / log exposure"),
        "inference_api_exposed": ("inference_api_exposed", "Inference / model API exposure"),
        "admin_playground_exposed": ("admin_playground_exposed", "AI admin / playground exposure"),
    }

    for finding in findings:
        ftype = finding.get("type", "")
        if ftype in type_map:
            weight_key, label_prefix = type_map[ftype]
            w = weights.get(weight_key, 0)
            total += w
            label = f"{label_prefix}: {finding.get('source_url', '')}"
            breakdown.append({"item": label, "score": w})

    # Determine risk level (highest matching threshold)
    risk_level = "low"
    risk_cfg = thresholds["low"]
    for level, cfg in sorted(thresholds.items(), key=lambda x: x[1]["min"]):
        if total >= cfg["min"]:
            risk_level = level
            risk_cfg = cfg

    return {
        "total_score": total,
        "risk_level": risk_level,
        "risk_label": risk_cfg["label"],
        "risk_color": risk_cfg["hex"],
        "score_breakdown": breakdown,
        "finding_count": len(findings) + len(secrets),
    }


def combined_score(asset_scores: list) -> dict:
    """
    Aggregate per-asset scores into a combined summary.

    Risk level is driven by the highest-risk individual asset, not the sum —
    a single critical asset should not be diluted by clean ones.
    """
    if not asset_scores:
        config = _load_config()
        cfg = config["scoring"]["thresholds"]["low"]
        return {
            "total_score": 0,
            "risk_level": "low",
            "risk_label": cfg["label"],
            "risk_color": cfg["hex"],
            "finding_count": 0,
            "asset_count": 0,
        }

    config = _load_config()
    thresholds = config["scoring"]["thresholds"]

    total = sum(s["total_score"] for s in asset_scores)
    finding_count = sum(s["finding_count"] for s in asset_scores)

    # Highest individual asset risk level determines the overall label
    _level_order = {"low": 0, "moderate": 1, "high": 2}
    highest = max(asset_scores, key=lambda s: _level_order.get(s["risk_level"], 0))
    risk_level = highest["risk_level"]
    risk_cfg = thresholds.get(risk_level, thresholds["low"])

    return {
        "total_score": total,
        "risk_level": risk_level,
        "risk_label": risk_cfg["label"],
        "risk_color": risk_cfg["hex"],
        "finding_count": finding_count,
        "asset_count": len(asset_scores),
    }
