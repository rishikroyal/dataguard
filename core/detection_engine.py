"""
Detection Engine
Core module for detecting sensitive/confidential information using
regex patterns + spaCy NLP with confidence scoring.

Detects:
- Aadhaar Numbers (Indian National ID)
- PAN Numbers (Indian Tax ID)
- Email Addresses
- Indian Phone Numbers
- Credit/Debit Card Numbers
- Bank Account Numbers & IFSC Codes
- API Keys & Passwords
- Employee IDs
- Passport Numbers
- Vehicle Registration Numbers
- Confidential Business Information (keyword-based)
- IP Addresses
- Date of Birth patterns
- GST Numbers
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SensitiveDataType(Enum):
    AADHAAR = "Aadhaar Number"
    PAN = "PAN Number"
    EMAIL = "Email Address"
    PHONE = "Phone Number"
    CREDIT_CARD = "Credit/Debit Card Number"
    BANK_ACCOUNT = "Bank Account Number"
    IFSC = "IFSC Code"
    API_KEY = "API Key / Secret"
    PASSWORD = "Password / Credential"
    EMPLOYEE_ID = "Employee ID"
    PASSPORT = "Passport Number"
    VEHICLE_REG = "Vehicle Registration"
    GST = "GST Number"
    CONFIDENTIAL = "Confidential Keyword"
    IP_ADDRESS = "IP Address"
    DATE_OF_BIRTH = "Date of Birth"
    SWIFT_CODE = "SWIFT/BIC Code"
    SSN = "Social Security Number"
    UPI_ID = "UPI ID"
    VOTER_ID = "Voter ID"
    DRIVING_LICENCE = "Driving Licence"
    ENCRYPTION_KEY = "Encryption Key"
    DIGITAL_CERTIFICATE = "Digital Certificate"
    GOVERNMENT_EMPLOYEE_ID = "Government Employee ID"
    CLASSIFIED_MARKING = "Classified Marking"
    MILITARY_DEFENSE = "Military/Defense Document"
    PUBLIC_NOTICE = "Public Notice/Act/Regulation"
    GOV_WEBSITE = "Government Website"
    DEPT_NAME = "Department Name"
    OFFICE_ADDRESS = "Office Address"
    GOV_DOC_REF = "Government Document Reference"
    GOV_EMPLOYEE_DETAIL = "Government Employee Detail"


@dataclass
class Detection:
    """Represents a single detected sensitive data instance."""
    data_type: SensitiveDataType
    value: str                          # Actual matched value
    masked_value: str                   # Partially masked version
    context: str                        # Surrounding text context
    start_pos: int                      # Start position in text
    end_pos: int                        # End position in text
    confidence: float                   # Detection confidence (0.0 - 1.0)
    pattern_name: str                   # Which pattern matched
    risk_contribution: str              # LOW / MEDIUM / HIGH / CRITICAL
    line_number: Optional[int] = None   # Line number in document

    def to_dict(self) -> dict:
        return {
            "type": self.data_type.value,
            "value": self.value,
            "masked_value": self.masked_value,
            "context": self.context,
            "confidence": self.confidence,
            "pattern": self.pattern_name,
            "risk": self.risk_contribution,
            "line_number": self.line_number,
        }


class DetectionEngine:
    """
    Multi-layer sensitive data detection engine.
    Combines regex patterns, validation logic, and optional NLP.
    """

    def __init__(self, use_spacy: bool = True):
        self.use_spacy = use_spacy
        self.nlp = None
        self._load_spacy()
        self._build_patterns()

    def _load_spacy(self):
        """Attempt to load spaCy model for NLP-enhanced detection."""
        if not self.use_spacy:
            return
        try:
            import spacy
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("spaCy model loaded successfully.")
        except Exception as e:
            logger.warning(f"spaCy not available ({e}). Using regex-only mode.")
            self.nlp = None

    def _build_patterns(self):
        """Define all regex detection patterns with metadata."""
        self.patterns = [
            # ── Indian Government IDs ──────────────────────────────────
            {
                "name": "aadhaar",
                "type": SensitiveDataType.AADHAAR,
                "pattern": re.compile(
                    r'(?<![\d])(?:[2-9]\d{3}[\s]\d{4}[\s]\d{4}|[2-9]\d{11})(?![\d])'
                ),
                "confidence": 0.85,
                "risk": "CRITICAL",
                "validator": self._validate_aadhaar,
            },
            {
                "name": "pan",
                "type": SensitiveDataType.PAN,
                "pattern": re.compile(
                    r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'
                ),
                "confidence": 0.92,
                "risk": "HIGH",
                "validator": None,
            },
            {
                "name": "voter_id",
                "type": SensitiveDataType.VOTER_ID,
                "pattern": re.compile(
                    r'\b[A-Z]{3}\d{7}\b'
                ),
                "confidence": 0.70,
                "risk": "HIGH",
                "validator": None,
            },
            {
                "name": "passport",
                "type": SensitiveDataType.PASSPORT,
                "pattern": re.compile(
                    r'\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b'  # Indian passport format
                ),
                "confidence": 0.78,
                "risk": "HIGH",
                "validator": None,
            },

            # ── Contact Information ─────────────────────────────────────
            {
                "name": "email",
                "type": SensitiveDataType.EMAIL,
                "pattern": re.compile(
                    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
                ),
                "confidence": 0.97,
                "risk": "MEDIUM",
                "validator": None,
            },
            {
                "name": "indian_phone",
                "type": SensitiveDataType.PHONE,
                "pattern": re.compile(
                    r'(?<!\d)(\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}(?!\d)'
                ),
                "confidence": 0.88,
                "risk": "MEDIUM",
                "validator": None,
            },
            {
                "name": "intl_phone",
                "type": SensitiveDataType.PHONE,
                "pattern": re.compile(
                    r'\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4}'
                ),
                "confidence": 0.80,
                "risk": "MEDIUM",
                "validator": None,
            },
            {
                "name": "upi_id",
                "type": SensitiveDataType.UPI_ID,
                "pattern": re.compile(
                    r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b'
                ),
                "confidence": 0.72,
                "risk": "HIGH",
                "validator": None,
            },

            # ── Financial Data ──────────────────────────────────────────
            {
                "name": "credit_card_visa_mc",
                "type": SensitiveDataType.CREDIT_CARD,
                "pattern": re.compile(
                    r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14})\b'
                ),
                "confidence": 0.91,
                "risk": "CRITICAL",
                "validator": self._luhn_check,
            },
            {
                "name": "credit_card_amex",
                "type": SensitiveDataType.CREDIT_CARD,
                "pattern": re.compile(
                    r'\b3[47]\d{13}\b'
                ),
                "confidence": 0.90,
                "risk": "CRITICAL",
                "validator": self._luhn_check,
            },
            {
                "name": "credit_card_spaced",
                "type": SensitiveDataType.CREDIT_CARD,
                "pattern": re.compile(
                    r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b'
                ),
                "confidence": 0.85,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "bank_account",
                "type": SensitiveDataType.BANK_ACCOUNT,
                "pattern": re.compile(
                    r'(?i)(?:account\s*(?:no|number|#|num)[:.\s]*|a/c\s*(?:no|number|#)?[:.\s]*)\d{9,18}\b'
                ),
                "confidence": 0.82,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "ifsc",
                "type": SensitiveDataType.IFSC,
                "pattern": re.compile(
                    r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
                ),
                "confidence": 0.88,
                "risk": "HIGH",
                "validator": None,
            },
            {
                "name": "swift",
                "type": SensitiveDataType.SWIFT_CODE,
                "pattern": re.compile(
                    r'\b[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?\b'
                ),
                "confidence": 0.75,
                "risk": "HIGH",
                "validator": self._validate_swift,
            },
            {
                "name": "gst",
                "type": SensitiveDataType.GST,
                "pattern": re.compile(
                    r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b'
                ),
                "confidence": 0.93,
                "risk": "HIGH",
                "validator": None,
            },

            # ── Technical Secrets ───────────────────────────────────────
            {
                "name": "api_key_generic",
                "type": SensitiveDataType.API_KEY,
                "pattern": re.compile(
                    r'(?i)(?:api[_\-\s]?key|apikey|access[_\-]?key|secret[_\-]?key|auth[_\-]?token|bearer[_\-]?token|private[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9\-_/+.]{20,})["\']?'
                ),
                "confidence": 0.90,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "aws_access_key",
                "type": SensitiveDataType.API_KEY,
                "pattern": re.compile(
                    r'\bAKIA[0-9A-Z]{16}\b'
                ),
                "confidence": 0.98,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "password_field",
                "type": SensitiveDataType.PASSWORD,
                "pattern": re.compile(
                    r'(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\']?([^\s"\']{6,})["\']?'
                ),
                "confidence": 0.85,
                "risk": "CRITICAL",
                "validator": None,
            },

            # ── Network / Technical ─────────────────────────────────────
            {
                "name": "ip_address",
                "type": SensitiveDataType.IP_ADDRESS,
                "pattern": re.compile(
                    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
                ),
                "confidence": 0.95,
                "risk": "MEDIUM",
                "validator": None,
            },

            # ── Employee / HR Data ──────────────────────────────────────
            {
                "name": "employee_id",
                "type": SensitiveDataType.EMPLOYEE_ID,
                "pattern": re.compile(
                    r'(?i)(?:emp(?:loyee)?[_\-\s]?(?:id|no|number|code)[:.\s]*)([A-Z]{0,4}\d{4,8})\b'
                ),
                "confidence": 0.80,
                "risk": "MEDIUM",
                "validator": None,
            },
            {
                "name": "date_of_birth",
                "type": SensitiveDataType.DATE_OF_BIRTH,
                "pattern": re.compile(
                    r'(?i)(?:dob|date\s*of\s*birth|birth\s*date)[\s:]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})'
                ),
                "confidence": 0.88,
                "risk": "HIGH",
                "validator": None,
            },

            # ── Vehicle ─────────────────────────────────────────────────
            {
                "name": "vehicle_reg",
                "type": SensitiveDataType.VEHICLE_REG,
                "pattern": re.compile(
                    r'\b[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{4}\b'
                ),
                "confidence": 0.75,
                "risk": "LOW",
                "validator": None,
            },

            {
                "name": "confidential_keyword",
                "type": SensitiveDataType.CONFIDENTIAL,
                "pattern": re.compile(
                    r'(?i)\b(?:proprietary|trade\s+secret|internal\s+only|do\s+not\s+distribute|'
                    r'restricted|nda|non[\s\-]disclosure|privileged|attorney[\s\-]client|'
                    r'private\s+and\s+confidential|internal)\b'
                ),
                "confidence": 0.70,
                "risk": "HIGH",
                "validator": None,
            },
            {
                "name": "driving_licence",
                "type": SensitiveDataType.DRIVING_LICENCE,
                "pattern": re.compile(
                    r'\b[A-Z]{2}\-[0-9]{13}\b|\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b'
                ),
                "confidence": 0.85,
                "risk": "HIGH",
                "validator": None,
            },
            {
                "name": "encryption_key",
                "type": SensitiveDataType.ENCRYPTION_KEY,
                "pattern": re.compile(
                    r'\-\-\-\-\-BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY\-\-\-\-\-'
                ),
                "confidence": 0.99,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "digital_certificate",
                "type": SensitiveDataType.DIGITAL_CERTIFICATE,
                "pattern": re.compile(
                    r'\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-'
                ),
                "confidence": 0.99,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "gov_employee_id",
                "type": SensitiveDataType.GOVERNMENT_EMPLOYEE_ID,
                "pattern": re.compile(
                    r'\b(?:GOV\-EMP\-\d{4,8}|GOV\d{5,8})\b'
                ),
                "confidence": 0.85,
                "risk": "HIGH",
                "validator": None,
            },
            {
                "name": "classified_marking",
                "type": SensitiveDataType.CLASSIFIED_MARKING,
                "pattern": re.compile(
                    r'(?i)\b(?:classified|secret|top\s+secret|classified\s+document)\b'
                ),
                "confidence": 0.85,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "military_defense",
                "type": SensitiveDataType.MILITARY_DEFENSE,
                "pattern": re.compile(
                    r'(?i)\b(?:military|defense\s+procurement|drdo|indian\s+army|indian\s+navy|indian\s+air\s+force|defense\s+forces|weapons\s+system|tactical\s+strategy)\b'
                ),
                "confidence": 0.85,
                "risk": "CRITICAL",
                "validator": None,
            },
            {
                "name": "public_notice",
                "type": SensitiveDataType.PUBLIC_NOTICE,
                "pattern": re.compile(
                    r'(?i)\b(?:Act,\s*19\d{2}|Act,\s*20\d{2}|Regulation\s*\d+|Public\s+Notice|Press\s+Information\s+Bureau|PIB\s+Press\s+Release|Ministry\s+Press\s+Release)\b'
                ),
                "confidence": 0.80,
                "risk": "LOW",
                "validator": None,
            },
            {
                "name": "gov_website",
                "type": SensitiveDataType.GOV_WEBSITE,
                "pattern": re.compile(
                    r'\b(?:[a-zA-Z0-9.-]+\.gov\.in|india\.gov\.in)\b'
                ),
                "confidence": 0.90,
                "risk": "LOW",
                "validator": None,
            },
            {
                "name": "dept_name",
                "type": SensitiveDataType.DEPT_NAME,
                "pattern": re.compile(
                    r'(?i)\b(?:Department\s+of\s+[A-Za-z\s]{3,30}|Ministry\s+of\s+[A-Za-z\s]{3,30})\b'
                ),
                "confidence": 0.80,
                "risk": "MEDIUM",
                "validator": None,
            },
            {
                "name": "office_address",
                "type": SensitiveDataType.OFFICE_ADDRESS,
                "pattern": re.compile(
                    r'(?i)\b(?:New\s+Delhi|Plot\s+No\.\s*\d+|Sector\s*\d+|Building\s+No\.\s*\d+|Sansad\s+Marg|CGO\s+Complex)\b'
                ),
                "confidence": 0.80,
                "risk": "MEDIUM",
                "validator": None,
            },
            {
                "name": "gov_doc_ref",
                "type": SensitiveDataType.GOV_DOC_REF,
                "pattern": re.compile(
                    r'\b(?:F\.\s*No\.|File\s*No\.|F\-\d+\/\d+\/\d+|Letter\s*No\.)\b'
                ),
                "confidence": 0.85,
                "risk": "MEDIUM",
                "validator": None,
            },
        ]

    # ────────────────────────────────────────────────────────────────────
    # Validators
    # ────────────────────────────────────────────────────────────────────

    def _validate_aadhaar(self, value: str) -> bool:
        """Basic Aadhaar validation — 12 digits, doesn't start with 0/1."""
        digits = re.sub(r'\s', '', value)
        return len(digits) == 12 and digits[0] not in ('0', '1')

    def _luhn_check(self, value: str) -> bool:
        """Luhn algorithm validation for credit card numbers."""
        digits = re.sub(r'[\s\-]', '', value)
        if not digits.isdigit():
            return False
        total = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def _validate_swift(self, value: str) -> bool:
        """Validate SWIFT/BIC code country code component."""
        clean_val = re.sub(r'[\s\-]', '', value)
        if len(clean_val) < 8:
            return False
        # The 5th and 6th characters must be a valid country code
        country_code = clean_val[4:6].upper()
        
        valid_countries = {
            "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
            "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
            "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
            "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
            "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
            "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
            "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
            "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
            "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
            "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
            "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
            "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
            "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
            "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
            "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
            "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
        }
        return country_code in valid_countries

    # ────────────────────────────────────────────────────────────────────
    # Main Detection
    # ────────────────────────────────────────────────────────────────────

    def detect(self, text: str) -> List[Detection]:
        """
        Run all detection patterns against the provided text.
        Returns a deduplicated, sorted list of Detection objects.
        """
        detections: List[Detection] = []
        lines = text.split('\n')

        # Build line index for position → line number mapping
        line_starts = []
        pos = 0
        for line in lines:
            line_starts.append(pos)
            pos += len(line) + 1

        for pattern_def in self.patterns:
            pattern = pattern_def["pattern"]
            validator = pattern_def.get("validator")

            for match in pattern.finditer(text):
                value = match.group(0)
                start = match.start()
                end = match.end()

                # Run validator if available
                confidence = pattern_def["confidence"]
                if validator:
                    try:
                        clean_val = re.sub(r'[\s\-]', '', value)
                        is_valid = validator(clean_val)
                        if not is_valid:
                            confidence = 0.0  # Discard if validator checks fail
                    except Exception:
                        pass

                # Skip very low confidence
                if confidence < 0.4:
                    continue

                # Get context window (50 chars each side)
                ctx_start = max(0, start - 50)
                ctx_end = min(len(text), end + 50)
                context = text[ctx_start:ctx_end].replace('\n', ' ')

                # Find line number
                line_num = 1
                for i, ls in enumerate(line_starts):
                    if ls > start:
                        line_num = i
                        break
                    line_num = i + 1

                detection = Detection(
                    data_type=pattern_def["type"],
                    value=value,
                    masked_value=self._mask_value(value, pattern_def["type"]),
                    context=context,
                    start_pos=start,
                    end_pos=end,
                    confidence=confidence,
                    pattern_name=pattern_def["name"],
                    risk_contribution=pattern_def["risk"],
                    line_number=line_num,
                )
                detections.append(detection)

        # NLP enhancement
        if self.nlp:
            detections = self._enhance_with_nlp(text, detections)

        # Deduplicate overlapping matches
        detections = self._deduplicate(detections)

        return sorted(detections, key=lambda d: d.start_pos)

    def _enhance_with_nlp(self, text: str, detections: List[Detection]) -> List[Detection]:
        """Use spaCy NER to detect additional PII (PERSON, ORG, GPE)."""
        try:
            # Process in chunks if text is very long
            max_len = 100000
            text_chunk = text[:max_len]
            doc = self.nlp(text_chunk)

            # Boost confidence for detections near named entities
            for ent in doc.ents:
                if ent.label_ in ("PERSON", "ORG"):
                    for det in detections:
                        if abs(det.start_pos - ent.start_char) < 100:
                            det.confidence = min(1.0, det.confidence + 0.05)
        except Exception as e:
            logger.warning(f"NLP enhancement failed: {e}")

        return detections

    def _deduplicate(self, detections: List[Detection]) -> List[Detection]:
        """Remove overlapping detections, keeping the one with higher confidence."""
        if not detections:
            return detections

        detections = sorted(detections, key=lambda d: (d.start_pos, -d.confidence))
        result = []
        last_end = -1

        for det in detections:
            if det.start_pos >= last_end:
                result.append(det)
                last_end = det.end_pos
            else:
                # Overlapping — keep higher confidence
                if result and det.confidence > result[-1].confidence:
                    result[-1] = det
                    last_end = det.end_pos

        return result

    def _mask_value(self, value: str, data_type: SensitiveDataType) -> str:
        """Generate partially masked version of detected value for display."""
        v = value.strip()

        if data_type == SensitiveDataType.AADHAAR:
            digits = re.sub(r'\s', '', v)
            return f"XXXX XXXX {digits[-4:]}"

        elif data_type == SensitiveDataType.PAN:
            return f"{v[:2]}XXX{v[5:7]}XX{v[-1]}"

        elif data_type == SensitiveDataType.EMAIL:
            parts = v.split('@')
            if len(parts) == 2:
                local = parts[0]
                masked_local = local[0] + "***" + (local[-1] if len(local) > 1 else "")
                return f"{masked_local}@{parts[1]}"
            return v[:3] + "***"

        elif data_type == SensitiveDataType.PHONE:
            digits = re.sub(r'[\s\-\+]', '', v)
            return f"{'*' * (len(digits) - 4)}{digits[-4:]}"

        elif data_type == SensitiveDataType.CREDIT_CARD:
            digits = re.sub(r'[\s\-]', '', v)
            return f"{'*' * (len(digits) - 4)}{digits[-4:]}"

        elif data_type in (SensitiveDataType.API_KEY, SensitiveDataType.PASSWORD):
            return v[:4] + "*" * (len(v) - 6) + v[-2:] if len(v) > 8 else "****"

        elif data_type == SensitiveDataType.BANK_ACCOUNT:
            # Only show last 4 digits of account number
            digits_match = re.search(r'\d{9,18}', v)
            if digits_match:
                account = digits_match.group()
                return v.replace(account, '*' * (len(account) - 4) + account[-4:])
            return "XXXX" + v[-4:]

        else:
            # Generic masking — show first/last char
            if len(v) <= 4:
                return '*' * len(v)
            return v[0] + '*' * (len(v) - 2) + v[-1]

    # ────────────────────────────────────────────────────────────────────
    # Summary Statistics
    # ────────────────────────────────────────────────────────────────────

    def get_summary(self, detections: List[Detection]) -> dict:
        """Generate a statistical summary of all detections."""
        if not detections:
            return {
                "total": 0,
                "by_type": {},
                "by_risk": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "unique_types": [],
                "highest_risk": "LOW",
            }

        by_type: Dict[str, int] = {}
        by_risk: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for det in detections:
            type_name = det.data_type.value
            by_type[type_name] = by_type.get(type_name, 0) + 1
            by_risk[det.risk_contribution] = by_risk.get(det.risk_contribution, 0) + 1

        risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        highest_risk = "LOW"
        for risk in risk_order:
            if by_risk[risk] > 0:
                highest_risk = risk
                break

        return {
            "total": len(detections),
            "by_type": by_type,
            "by_risk": by_risk,
            "unique_types": list(by_type.keys()),
            "highest_risk": highest_risk,
            "avg_confidence": sum(d.confidence for d in detections) / len(detections),
        }
