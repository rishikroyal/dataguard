"""
Redactor
Data masking and redaction module.
Creates sanitized versions of documents with sensitive data replaced.
"""

import re
import logging
from typing import List, Dict, Tuple
from core.detection_engine import Detection, SensitiveDataType

logger = logging.getLogger(__name__)

# Redaction placeholder templates
REDACTION_LABELS = {
    SensitiveDataType.AADHAAR:       "[AADHAAR REDACTED]",
    SensitiveDataType.PAN:           "[PAN REDACTED]",
    SensitiveDataType.EMAIL:         "[EMAIL REDACTED]",
    SensitiveDataType.PHONE:         "[PHONE REDACTED]",
    SensitiveDataType.CREDIT_CARD:   "[CARD REDACTED]",
    SensitiveDataType.BANK_ACCOUNT:  "[BANK ACCOUNT REDACTED]",
    SensitiveDataType.IFSC:          "[IFSC REDACTED]",
    SensitiveDataType.API_KEY:       "[API KEY REDACTED]",
    SensitiveDataType.PASSWORD:      "[PASSWORD REDACTED]",
    SensitiveDataType.EMPLOYEE_ID:   "[EMP ID REDACTED]",
    SensitiveDataType.PASSPORT:      "[PASSPORT REDACTED]",
    SensitiveDataType.VOTER_ID:      "[VOTER ID REDACTED]",
    SensitiveDataType.DATE_OF_BIRTH: "[DOB REDACTED]",
    SensitiveDataType.GST:           "[GST REDACTED]",
    SensitiveDataType.IP_ADDRESS:    "[IP REDACTED]",
    SensitiveDataType.CONFIDENTIAL:  "[CONFIDENTIAL]",
    SensitiveDataType.UPI_ID:        "[UPI REDACTED]",
    SensitiveDataType.VEHICLE_REG:   "[VEHICLE REG REDACTED]",
    SensitiveDataType.SWIFT_CODE:    "[SWIFT REDACTED]",
    SensitiveDataType.SSN:           "[SSN REDACTED]",
}


class Redactor:
    """
    Applies data masking and redaction to document text.
    Supports multiple redaction modes:
    - full: Complete replacement with label
    - partial: Partial masking (show first/last chars)
    - hash: Replace with MD5 hash for consistency
    """

    def __init__(self, mode: str = "full"):
        """
        Args:
            mode: 'full' | 'partial' | 'hash'
        """
        self.mode = mode

    def redact(self, text: str, detections: List[Detection]) -> Tuple[str, int]:
        """
        Apply redaction to text based on detected sensitive data.
        
        Returns:
            Tuple of (redacted_text, count_of_redactions)
        """
        if not detections:
            return text, 0

        # Sort detections by position (reverse order so replacements don't shift positions)
        sorted_detections = sorted(detections, key=lambda d: d.start_pos, reverse=True)

        redacted_text = text
        count = 0

        for det in sorted_detections:
            replacement = self._get_replacement(det)
            original = det.value

            if self.mode == "full":
                redacted_text = redacted_text[:det.start_pos] + replacement + redacted_text[det.end_pos:]
            elif self.mode == "partial":
                redacted_text = redacted_text[:det.start_pos] + det.masked_value + redacted_text[det.end_pos:]
            else:
                redacted_text = redacted_text[:det.start_pos] + replacement + redacted_text[det.end_pos:]

            count += 1

        return redacted_text, count

    def _get_replacement(self, detection: Detection) -> str:
        """Get the redaction replacement string for a detection."""
        if self.mode == "hash":
            import hashlib
            h = hashlib.md5(detection.value.encode()).hexdigest()[:8].upper()
            label = REDACTION_LABELS.get(detection.data_type, "[REDACTED]")
            return f"{label}#{h}"

        return REDACTION_LABELS.get(detection.data_type, "[REDACTED]")

    def redact_for_display(self, text: str, detections: List[Detection]) -> str:
        """
        Create HTML-highlighted version for UI display.
        Sensitive data is shown in colored highlighted boxes.
        """
        if not detections:
            return self._escape_html(text)

        sorted_detections = sorted(detections, key=lambda d: d.start_pos)

        RISK_COLORS = {
            "CRITICAL": ("rgba(255,45,85,0.2)", "#FF2D55"),
            "HIGH":     ("rgba(255,107,53,0.2)", "#FF6B35"),
            "MEDIUM":   ("rgba(255,215,0,0.15)", "#FFD700"),
            "LOW":      ("rgba(52,199,89,0.15)", "#34C759"),
        }

        result = []
        last_pos = 0

        for det in sorted_detections:
            # Add text before detection
            if det.start_pos > last_pos:
                result.append(self._escape_html(text[last_pos:det.start_pos]))

            # Add highlighted detection
            bg, border = RISK_COLORS.get(det.risk_contribution, ("rgba(128,128,128,0.2)", "#888"))
            tooltip = f"{det.data_type.value} (Confidence: {det.confidence:.0%})"
            result.append(
                f'<mark style="background:{bg}; border-bottom: 2px solid {border}; '
                f'padding: 2px 4px; border-radius: 3px; cursor: help;" '
                f'title="{tooltip}">'
                f'{self._escape_html(det.value)}'
                f'</mark>'
            )

            last_pos = det.end_pos

        # Remaining text
        if last_pos < len(text):
            result.append(self._escape_html(text[last_pos:]))

        return "".join(result)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;")
                .replace("\n", "<br>"))

    def generate_redacted_report(self, filename: str, original_text: str,
                                  redacted_text: str, detections: List[Detection]) -> str:
        """Generate a plain-text redaction report with statistics."""
        lines = [
            "=" * 60,
            "REDACTION REPORT",
            "=" * 60,
            f"Original File: {filename}",
            f"Redaction Mode: {self.mode.upper()}",
            f"Total Redactions Applied: {len(detections)}",
            "",
            "REDACTED DATA TYPES:",
            "-" * 40,
        ]

        by_type: Dict[str, int] = {}
        for det in detections:
            t = det.data_type.value
            by_type[t] = by_type.get(t, 0) + 1

        for dtype, count in sorted(by_type.items()):
            lines.append(f"  {dtype}: {count} instance(s) redacted")

        lines.extend([
            "",
            "=" * 60,
            "REDACTED DOCUMENT CONTENT",
            "=" * 60,
            "",
            redacted_text,
        ])

        return "\n".join(lines)
