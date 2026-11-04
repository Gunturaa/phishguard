import logging
import os
from typing import Any, Dict

import requests

logger = logging.getLogger("phishguard.notifications")


def notify_discord(event: str, result: Dict[str, Any]) -> None:
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook:
        return
    content = (
        f"PHISHGUARD {event}\n"
        f"Target: {result.get('target') or result.get('url', 'Unavailable')}\n"
        f"Status: {result.get('status') or result.get('final_status', 'Unavailable')}\n"
        f"Risk: {result.get('risk_score', 'Unavailable')}"
    )
    try:
        response = requests.post(webhook, json={"content": content[:1900]}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("Discord notification failed: %s", exc)
