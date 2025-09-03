"""
Input validation and sanitization utilities

Security-focused validation functions for API inputs including
text safety checks, XSS prevention, and prompt injection detection preprocessing.
"""
import re
import html
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()


class ValidationError(Exception):
    """Custom validation error for security issues"""
    pass


def validate_text_safety(text: str, max_length: int = 10000) -> str:
    """
    Validate text for basic safety and security
    
    Args:
        text: Input text to validate
        max_length: Maximum allowed text length
        
    Returns:
        Cleaned and validated text
        
    Raises:
        ValidationError: If text fails security checks
    """
    if not isinstance(text, str):
        raise ValidationError("Text must be a string")
    
    # Check length
    if len(text) > max_length:
        raise ValidationError(f"Text length exceeds maximum of {max_length} characters")
    
    if len(text.strip()) == 0:
        raise ValidationError("Text cannot be empty or only whitespace")
    
    # Check for null bytes
    if '\x00' in text:
        raise ValidationError("Text cannot contain null bytes")
    
    # Check for excessive control characters (but allow common ones)
    allowed_control_chars = {'\t', '\n', '\r'}
    control_char_count = sum(
        1 for c in text 
        if ord(c) < 32 and c not in allowed_control_chars
    )
    
    if control_char_count > 10:
        raise ValidationError("Text contains too many control characters")
    
    # Check for potential binary data
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        raise ValidationError("Text contains invalid Unicode characters")
    
    # Detect potential script injection attempts
    if _detect_script_injection(text):
        logger.warning("Potential script injection detected in input", text_length=len(text))
        # Don't block but log for monitoring
    
    return text.strip()


def _detect_script_injection(text: str) -> bool:
    """Detect potential script injection patterns"""
    # Common script injection patterns
    script_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'data:text/html',
        r'vbscript:',
        r'on\w+\s*=',  # Event handlers like onclick=
        r'eval\s*\(',
        r'document\.',
        r'window\.',
        r'alert\s*\(',
        r'confirm\s*\(',
        r'prompt\s*\(',
    ]
    
    text_lower = text.lower()
    for pattern in script_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True
    
    return False


def sanitize_html_input(text: str) -> str:
    """Sanitize HTML entities in input text"""
    # Escape HTML entities
    sanitized = html.escape(text, quote=True)
    
    # Additional escaping for common injection vectors
    sanitized = sanitized.replace('&lt;script', '&amp;lt;script')
    sanitized = sanitized.replace('javascript:', 'javascript&#58;')
    
    return sanitized


def validate_webhook_url(url: str) -> str:
    """
    Validate webhook URL for security
    
    Args:
        url: Webhook URL to validate
        
    Returns:
        Validated URL
        
    Raises:
        ValidationError: If URL is invalid or unsafe
    """
    if not url:
        raise ValidationError("Webhook URL cannot be empty")
    
    if len(url) > 500:
        raise ValidationError("Webhook URL too long (max 500 characters)")
    
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError("Invalid URL format")
    
    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        raise ValidationError("Webhook URL must use HTTP or HTTPS")
    
    # Check for hostname
    if not parsed.hostname:
        raise ValidationError("Webhook URL must have a valid hostname")
    
    # Block localhost/private IPs in production
    hostname = parsed.hostname.lower()
    
    # Block obvious internal addresses
    blocked_hosts = [
        'localhost', 
        '127.0.0.1', 
        '0.0.0.0',
        '::1',
        '169.254.169.254',  # AWS metadata service
        'metadata.google.internal'  # GCP metadata service
    ]
    
    if hostname in blocked_hosts:
        logger.warning("Blocked webhook to internal address", hostname=hostname)
        raise ValidationError("Webhook URL cannot point to internal addresses")
    
    # Block private IP ranges (basic check)
    if (hostname.startswith('10.') or 
        hostname.startswith('192.168.') or 
        hostname.startswith('172.')):
        logger.warning("Blocked webhook to private IP", hostname=hostname)
        raise ValidationError("Webhook URL cannot point to private IP addresses")
    
    return url


def validate_api_key_name(name: str) -> str:
    """Validate API key name"""
    if not name or not name.strip():
        raise ValidationError("API key name cannot be empty")
    
    name = name.strip()
    
    if len(name) > 100:
        raise ValidationError("API key name too long (max 100 characters)")
    
    # Allow alphanumeric, spaces, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', name):
        raise ValidationError("API key name contains invalid characters")
    
    return name


def validate_rate_limits(per_minute: Optional[int], per_day: Optional[int]) -> tuple[int, int]:
    """Validate rate limit values"""
    # Default values
    default_per_minute = 60
    default_per_day = 10000
    
    # Validate per-minute limit
    if per_minute is None:
        per_minute = default_per_minute
    elif not isinstance(per_minute, int) or per_minute < 1 or per_minute > 1000:
        raise ValidationError("Rate limit per minute must be between 1 and 1000")
    
    # Validate per-day limit
    if per_day is None:
        per_day = default_per_day
    elif not isinstance(per_day, int) or per_day < 1 or per_day > 100000:
        raise ValidationError("Rate limit per day must be between 1 and 100000")
    
    # Ensure daily limit is reasonable compared to per-minute limit
    max_daily_from_minute = per_minute * 60 * 24  # If hitting per-minute limit constantly
    if per_day > max_daily_from_minute:
        per_day = max_daily_from_minute
        logger.info("Adjusted daily rate limit to be consistent with per-minute limit")
    
    return per_minute, per_day


def validate_webhook_events(events: List[str]) -> List[str]:
    """Validate webhook event subscriptions"""
    if not events:
        return ["detection_complete"]  # Default event
    
    valid_events = [
        "detection_complete",
        "batch_complete", 
        "detection_failed",
        "rate_limit_exceeded"
    ]
    
    validated_events = []
    for event in events:
        if not isinstance(event, str):
            raise ValidationError(f"Event must be a string: {event}")
        
        event = event.strip()
        if event not in valid_events:
            raise ValidationError(f"Invalid event type: {event}. Valid types: {valid_events}")
        
        if event not in validated_events:  # Avoid duplicates
            validated_events.append(event)
    
    return validated_events


def validate_confidence_threshold(threshold: Optional[float]) -> float:
    """Validate confidence threshold value"""
    if threshold is None:
        return 0.6  # Default
    
    if not isinstance(threshold, (int, float)):
        raise ValidationError("Confidence threshold must be a number")
    
    threshold = float(threshold)
    
    if threshold < 0.0 or threshold > 1.0:
        raise ValidationError("Confidence threshold must be between 0.0 and 1.0")
    
    return threshold


def validate_metadata(metadata: Optional[Dict[str, Any]], max_size_kb: int = 1) -> Optional[Dict[str, Any]]:
    """Validate metadata size and content"""
    if metadata is None:
        return None
    
    if not isinstance(metadata, dict):
        raise ValidationError("Metadata must be a dictionary")
    
    # Check size by serializing
    import json
    try:
        serialized = json.dumps(metadata)
        size_kb = len(serialized.encode('utf-8')) / 1024
        
        if size_kb > max_size_kb:
            raise ValidationError(f"Metadata size ({size_kb:.1f}KB) exceeds limit ({max_size_kb}KB)")
    
    except (TypeError, ValueError) as e:
        raise ValidationError(f"Metadata must be JSON serializable: {e}")
    
    return metadata


def extract_text_features(text: str) -> Dict[str, Any]:
    """Extract features from text for analytics (non-blocking)"""
    try:
        features = {
            "length": len(text),
            "word_count": len(text.split()),
            "line_count": text.count('\n') + 1,
            "has_code_patterns": bool(re.search(r'[\{\}\[\]();]', text)),
            "has_urls": bool(re.search(r'https?://', text)),
            "has_email": bool(re.search(r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)),
            "uppercase_ratio": sum(1 for c in text if c.isupper()) / len(text) if text else 0,
            "special_char_count": len(re.findall(r'[^a-zA-Z0-9\s]', text))
        }
        
        return features
        
    except Exception as e:
        logger.warning("Failed to extract text features", error=str(e))
        return {"length": len(text) if text else 0}