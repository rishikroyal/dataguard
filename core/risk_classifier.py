"""
Risk Classifier
Classifies documents into risk levels based on detection results.
Maps findings to compliance frameworks (GDPR, India DPDP Act 2023).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from core.detection_engine import Detection, SensitiveDataType


# Risk level constants
RISK_LEVELS = {
    "CRITICAL": {"label": "🔴 Critical", "color": "#FF2D55", "score": 4},
    "HIGH":     {"label": "🟠 High",     "color": "#FF6B35", "score": 3},
    "MEDIUM":   {"label": "🟡 Medium",   "color": "#FFD700", "score": 2},
    "LOW":      {"label": "🟢 Low",      "color": "#34C759", "score": 1},
}

# DPDP Act 2023 (India) & GDPR category mappings
COMPLIANCE_FRAMEWORK = {
    SensitiveDataType.AADHAAR:      {"dpdp": "Section 3 - Personal Data", "gdpr": "Art. 9 - Special Category", "severity": "CRITICAL"},
    SensitiveDataType.PAN:          {"dpdp": "Section 3 - Personal Data", "gdpr": "Art. 9 - Special Category", "severity": "HIGH"},
    SensitiveDataType.EMAIL:        {"dpdp": "Section 3 - Personal Data", "gdpr": "Art. 4 - Personal Data",    "severity": "MEDIUM"},
    SensitiveDataType.PHONE:        {"dpdp": "Section 3 - Personal Data", "gdpr": "Art. 4 - Personal Data",    "severity": "MEDIUM"},
    SensitiveDataType.CREDIT_CARD:  {"dpdp": "Section 3 - Financial Data", "gdpr": "Art. 9 - Special Category","severity": "CRITICAL"},
    SensitiveDataType.BANK_ACCOUNT: {"dpdp": "Section 3 - Financial Data", "gdpr": "Art. 9 - Special Category","severity": "CRITICAL"},
    SensitiveDataType.IFSC:         {"dpdp": "Section 3 - Financial Data", "gdpr": "Art. 4 - Personal Data",   "severity": "HIGH"},
    SensitiveDataType.API_KEY:      {"dpdp": "Section 7 - Data Security",  "gdpr": "Art. 32 - Security",       "severity": "CRITICAL"},
    SensitiveDataType.PASSWORD:     {"dpdp": "Section 7 - Data Security",  "gdpr": "Art. 32 - Security",       "severity": "CRITICAL"},
    SensitiveDataType.EMPLOYEE_ID:  {"dpdp": "Section 3 - Personal Data",  "gdpr": "Art. 4 - Personal Data",   "severity": "MEDIUM"},
    SensitiveDataType.PASSPORT:     {"dpdp": "Section 3 - Sensitive Data", "gdpr": "Art. 9 - Special Category","severity": "HIGH"},
    SensitiveDataType.VOTER_ID:     {"dpdp": "Section 3 - Sensitive Data", "gdpr": "Art. 9 - Special Category","severity": "HIGH"},
    SensitiveDataType.DATE_OF_BIRTH:{"dpdp": "Section 3 - Personal Data",  "gdpr": "Art. 4 - Personal Data",   "severity": "HIGH"},
    SensitiveDataType.GST:          {"dpdp": "Section 3 - Business Data",  "gdpr": "Art. 4 - Personal Data",   "severity": "MEDIUM"},
    SensitiveDataType.IP_ADDRESS:   {"dpdp": "Section 3 - Technical Data", "gdpr": "Art. 4 - Personal Data",   "severity": "LOW"},
    SensitiveDataType.CONFIDENTIAL: {"dpdp": "Section 3 - Business Data",  "gdpr": "Art. 5 - Data Minimisation","severity": "HIGH"},
    SensitiveDataType.UPI_ID:       {"dpdp": "Section 3 - Financial Data", "gdpr": "Art. 9 - Special Category","severity": "HIGH"},
    SensitiveDataType.VEHICLE_REG:  {"dpdp": "Section 3 - Personal Data",  "gdpr": "Art. 4 - Personal Data",   "severity": "LOW"},
    SensitiveDataType.SWIFT_CODE:   {"dpdp": "Section 3 - Financial Data", "gdpr": "Art. 9 - Special Category","severity": "HIGH"},
    SensitiveDataType.SSN:          {"dpdp": "Section 3 - Sensitive Data", "gdpr": "Art. 9 - Special Category","severity": "CRITICAL"},
}

# Remediation templates
REMEDIATIONS = {
    "CRITICAL": [
        "Immediately encrypt all identified sensitive data fields at rest and in transit.",
        "Implement field-level encryption for government IDs and financial credentials.",
        "Restrict document access to authorized personnel only (Role-Based Access Control).",
        "Perform an immediate data breach risk assessment.",
        "Consider tokenization for all critical identifiers before storage.",
        "Enable Data Loss Prevention (DLP) monitoring on all channels handling this document.",
        "Report to Data Protection Officer (DPO) within 24 hours.",
    ],
    "HIGH": [
        "Implement data masking for display purposes (show only last 4 digits, etc.).",
        "Review and enforce data retention policies — delete data when no longer needed.",
        "Enable audit logging for all access to documents containing PII.",
        "Conduct Privacy Impact Assessment (PIA) for systems handling this data.",
        "Implement multi-factor authentication for document access.",
        "Ensure proper consent mechanisms are documented under DPDP Act 2023.",
    ],
    "MEDIUM": [
        "Apply pseudonymization techniques to reduce re-identification risk.",
        "Enforce access controls and review user permissions quarterly.",
        "Ensure data minimization — collect only what is strictly necessary.",
        "Document purpose of data collection in your Privacy Notice.",
        "Train employees on data handling best practices.",
    ],
    "LOW": [
        "Review the necessity of storing this information.",
        "Ensure data is used only for its stated purpose.",
        "Maintain records of processing activities (ROPA).",
    ],
}


@dataclass
class RiskProfile:
    """Complete risk assessment profile for a document."""
    overall_risk: str                           # LOW / MEDIUM / HIGH / CRITICAL
    risk_score: float                           # 0.0 - 100.0
    total_detections: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    detected_types: List[str]
    compliance_violations: List[dict]
    remediation_steps: List[str]
    risk_breakdown: Dict[str, int]
    dpdp_violations: List[str]
    gdpr_violations: List[str]
    risk_factors: List[str]
    document_clearance: str                     # BLOCKED / REVIEW / CAUTION / CLEAR

    def to_dict(self) -> dict:
        return {
            "overall_risk": self.overall_risk,
            "risk_score": self.risk_score,
            "total_detections": self.total_detections,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "detected_types": self.detected_types,
            "compliance_violations": self.compliance_violations,
            "remediation_steps": self.remediation_steps,
            "dpdp_violations": self.dpdp_violations,
            "gdpr_violations": self.gdpr_violations,
            "risk_factors": self.risk_factors,
            "document_clearance": self.document_clearance,
        }


class RiskClassifier:
    """
    Multi-dimensional risk classification engine.
    Considers detection count, severity, data type combinations,
    and maps to GDPR + India DPDP Act 2023 compliance frameworks.
    """

    def classify(self, detections: List[Detection], text_length: int = 0) -> RiskProfile:
        """
        Classify risk level for a document based on category priorities.
        """
        if not detections:
            return self._no_risk_profile()

        # Count by risk level
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for det in detections:
            risk_counts[det.risk_contribution] = risk_counts.get(det.risk_contribution, 0) + 1

        # Detected types
        detected_types = list(set(det.data_type.value for det in detections))

        # Compliance violations
        compliance_violations = []
        dpdp_set = set()
        gdpr_set = set()
        for det in detections:
            mapping = COMPLIANCE_FRAMEWORK.get(det.data_type)
            if mapping:
                dpdp_set.add(mapping["dpdp"])
                gdpr_set.add(mapping["gdpr"])
                compliance_violations.append({
                    "data_type": det.data_type.value,
                    "dpdp": mapping["dpdp"],
                    "gdpr": mapping["gdpr"],
                })

        # Deduplicate
        compliance_violations = [dict(t) for t in {tuple(d.items()) for d in compliance_violations}]

        # Check presence of each custom category
        has_critical = False
        has_high = False
        has_medium = False
        has_low = False

        for det in detections:
            dt = det.data_type
            if dt in (
                SensitiveDataType.CLASSIFIED_MARKING,
                SensitiveDataType.API_KEY,
                SensitiveDataType.PASSWORD,
                SensitiveDataType.ENCRYPTION_KEY,
                SensitiveDataType.DIGITAL_CERTIFICATE,
                SensitiveDataType.MILITARY_DEFENSE,
                SensitiveDataType.CREDIT_CARD,
                SensitiveDataType.BANK_ACCOUNT
            ):
                has_critical = True
            elif dt in (
                SensitiveDataType.AADHAAR,
                SensitiveDataType.PASSPORT,
                SensitiveDataType.PAN,
                SensitiveDataType.DRIVING_LICENCE,
                SensitiveDataType.VOTER_ID,
                SensitiveDataType.GST,
                SensitiveDataType.GOVERNMENT_EMPLOYEE_ID,
                SensitiveDataType.CONFIDENTIAL
            ):
                has_high = True
            elif dt in (
                SensitiveDataType.DEPT_NAME,
                SensitiveDataType.OFFICE_ADDRESS,
                SensitiveDataType.GOV_DOC_REF,
                SensitiveDataType.GOV_EMPLOYEE_DETAIL,
                SensitiveDataType.EMPLOYEE_ID,
                SensitiveDataType.PHONE,
                SensitiveDataType.EMAIL,
                SensitiveDataType.DATE_OF_BIRTH,
                SensitiveDataType.UPI_ID,
                SensitiveDataType.IFSC,
                SensitiveDataType.SWIFT_CODE
            ):
                has_medium = True
            else:
                has_low = True

        # Special Rule: Sensitive IDs + Credentials/Keys -> CRITICAL
        has_sensitive_id = any(d.data_type in (
            SensitiveDataType.AADHAAR,
            SensitiveDataType.PASSPORT,
            SensitiveDataType.PAN,
            SensitiveDataType.DRIVING_LICENCE,
            SensitiveDataType.VOTER_ID
        ) for d in detections)

        has_credential = any(d.data_type in (
            SensitiveDataType.API_KEY,
            SensitiveDataType.PASSWORD,
            SensitiveDataType.ENCRYPTION_KEY
        ) for d in detections)

        if has_sensitive_id and has_credential:
            has_critical = True

        # Determine overall risk level
        if has_critical:
            overall = "CRITICAL"
        elif has_high:
            overall = "HIGH"
        elif has_medium:
            overall = "MEDIUM"
        else:
            overall = "LOW"

        # Determine risk score
        if overall == "CRITICAL":
            risk_score = 90.0 + min(10.0, len(detections) * 0.5)
        elif overall == "HIGH":
            risk_score = 65.0 + min(20.0, len(detections) * 1.5)
        elif overall == "MEDIUM":
            risk_score = 30.0 + min(30.0, len(detections) * 2.0)
        else:
            risk_score = min(25.0, len(detections) * 5.0)

        # Risk factors summary
        risk_factors = []
        if has_sensitive_id and has_credential:
            risk_factors.append("⚠️ Critical Exposure: Document contains both Government identity IDs and credentials/keys.")
        if has_critical and not (has_sensitive_id and has_credential):
            risk_factors.append("⚠️ Critical Security Alert: Credentials, classified markings, or military details detected.")
        if has_high:
            risk_factors.append("⚠️ High Risk Identifier: Plain text Government IDs (Aadhaar/Passport/PAN/Voter ID) present.")
        if has_medium:
            risk_factors.append("ℹ️ Medium Risk Exposure: Internal department names, employee profiles, or addresses found.")

        # Document clearance status
        clearance_map = {
            "CRITICAL": "🚫 BLOCKED (Contains credentials or classified information)",
            "HIGH":     "⚠️ REVIEW REQUIRED (Exposes Government PII/IDs)",
            "MEDIUM":   "⚡ CAUTION (Exposes organizational or employee details)",
            "LOW":      "✅ CLEAR (Only public details detected)",
        }

        # Build remediation steps
        remediations = REMEDIATIONS.get(overall, [])

        return RiskProfile(
            overall_risk=overall,
            risk_score=risk_score,
            total_detections=len(detections),
            critical_count=risk_counts["CRITICAL"],
            high_count=risk_counts["HIGH"],
            medium_count=risk_counts["MEDIUM"],
            low_count=risk_counts["LOW"],
            detected_types=detected_types,
            compliance_violations=compliance_violations,
            remediation_steps=remediations,
            risk_breakdown=risk_counts,
            dpdp_violations=sorted(list(dpdp_set)),
            gdpr_violations=sorted(list(gdpr_set)),
            risk_factors=risk_factors,
            document_clearance=clearance_map.get(overall, "⚡ CAUTION"),
        )

    def _no_risk_profile(self) -> RiskProfile:
        return RiskProfile(
            overall_risk="LOW",
            risk_score=0.0,
            total_detections=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            detected_types=[],
            compliance_violations=[],
            remediation_steps=REMEDIATIONS["LOW"],
            risk_breakdown={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            dpdp_violations=[],
            gdpr_violations=[],
            risk_factors=["✅ No sensitive data detected."],
            document_clearance="✅ CLEAR",
        )
