"""
Feature Extractor — shared utilities for pre-processing inputs
before they reach the individual detectors.
"""

import re
from email import message_from_string


def parse_email(raw_email: str) -> dict:
    """
    Parse a raw RFC-2822 email string into structured components.
    Returns headers, body text, HTML content, and embedded URLs.
    """
    try:
        msg = message_from_string(raw_email)
    except Exception:
        # If parsing fails, treat entire content as body text
        return {
            "subject": "",
            "from": "",
            "to": "",
            "body_text": raw_email,
            "body_html": "",
            "urls": extract_urls(raw_email),
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
        }

    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                body_text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
            elif ct == "text/html":
                body_html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode("utf-8", errors="ignore")

    # Extract authentication results from headers
    auth_results = msg.get("Authentication-Results", "").lower()

    return {
        "subject":  msg.get("Subject", ""),
        "from":     msg.get("From", ""),
        "to":       msg.get("To", ""),
        "body_text": body_text,
        "body_html": body_html,
        "urls":     extract_urls(body_text + body_html),
        "spf":      "pass" if "spf=pass" in auth_results else
                    "fail" if "spf=fail" in auth_results else "unknown",
        "dkim":     "pass" if "dkim=pass" in auth_results else
                    "fail" if "dkim=fail" in auth_results else "unknown",
        "dmarc":    "pass" if "dmarc=pass" in auth_results else
                    "fail" if "dmarc=fail" in auth_results else "unknown",
    }


def extract_urls(text: str) -> list:
    """Extract all URLs from a block of text."""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text)))


def clean_text(text: str) -> str:
    """Normalise text for NLP input: strip HTML tags, decode entities."""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Decode common HTML entities
    replacements = {"&amp;": "&", "&lt;": "<", "&gt;": ">",
                    "&nbsp;": " ", "&quot;": '"', "&#39;": "'"}
    for ent, char in replacements.items():
        text = text.replace(ent, char)
    # Collapse whitespace
    return re.sub(r'\s+', ' ', text).strip()


def truncate_for_model(text: str, max_chars: int = 512) -> str:
    """Truncate text to fit model input limits."""
    return text[:max_chars] if len(text) > max_chars else text
