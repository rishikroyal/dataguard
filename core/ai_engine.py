"""
AI Engine
Groq API integration for:
- Compliance summary generation
- Security risk analysis
- Intelligent Q&A about documents
- Remediation recommendations
"""

import os
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class AIEngine:
    """
    Wrapper around Groq API.
    Provides AI-powered compliance analysis and Q&A.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.client = None
        self.model_name = "llama-3.1-8b-instant"
        self.is_available = False
        self._initialize()

    def _initialize(self):
        """Initialize Groq client."""
        if not self.api_key or self.api_key == "your_groq_api_key_here":
            logger.warning("Groq API key not set. AI features will be disabled.")
            return

        try:
            from groq import Groq
            self.client = Groq(api_key=self.api_key)
            self.is_available = True
            logger.info("Groq AI engine initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize Groq: {e}")
            self.is_available = False

    def generate_compliance_summary(
        self,
        document_text: str,
        detections: List[Any],
        risk_profile: Any,
        filename: str,
        raw_risk_profile: Optional[dict] = None,
        raw_detections: Optional[List[dict]] = None,
    ) -> str:
        """
        Generate a detailed AI compliance summary.
        Falls back to a structured rule-based summary if AI is unavailable.
        """
        # Re-hydrate/parse inputs
        rp_dict = raw_risk_profile if raw_risk_profile else (risk_profile.to_dict() if hasattr(risk_profile, 'to_dict') else risk_profile)
        dets_list = raw_detections if raw_detections else ([d.to_dict() if hasattr(d, 'to_dict') else d for d in detections] if detections else [])

        if not self.is_available or not rp_dict:
            return self._rule_based_summary(dets_list, rp_dict, filename)

        # Build detection summary for the prompt
        detection_summary = self._build_detection_summary(dets_list)
        risk_factors_text = "\n".join(rp_dict.get("risk_factors", []))
        dpdp_text = ", ".join(rp_dict.get("dpdp_violations", [])) or "None"
        gdpr_text = ", ".join(rp_dict.get("gdpr_violations", [])) or "None"

        prompt = f"""You are a senior Data Privacy & Security Compliance Expert specializing in Indian DPDP Act 2023 and GDPR.

You have analyzed the document: "{filename}"

## Detection Results:
{detection_summary}

## Risk Assessment:
- Overall Risk Level: {rp_dict.get('overall_risk', 'LOW')}
- Risk Score: {rp_dict.get('risk_score', 0.0):.1f}/100
- Total Sensitive Items Found: {rp_dict.get('total_detections', 0)}
- Critical: {rp_dict.get('critical_count', 0)} | High: {rp_dict.get('high_count', 0)} | Medium: {rp_dict.get('medium_count', 0)} | Low: {rp_dict.get('low_count', 0)}

## Compliance Violations:
- DPDP Act 2023: {dpdp_text}
- GDPR: {gdpr_text}

## Risk Factors:
{risk_factors_text}

Please provide a professional compliance report with these sections:

### 1. Executive Summary
Brief 3-4 sentence overview of the document's compliance posture.

### 2. Key Compliance Observations
Bullet-point observations referencing specific data types found and applicable regulations.

### 3. Security Risk Assessment
Analysis of the security risks, considering the types and quantity of sensitive data.

### 4. Regulatory Exposure
Specific DPDP Act 2023 and GDPR articles/sections that may be implicated.

### 5. Immediate Action Items
Prioritized, actionable remediation steps (top 5).

### 6. Long-term Recommendations
Strategic recommendations for improving data governance.

Keep the tone professional, specific, and actionable. Reference actual regulations where applicable."""

        try:
            completion = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a helpful and professional compliance assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=2048,
            )
            return completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return self._rule_based_summary(dets_list, rp_dict, filename)

    def answer_question(
        self,
        question: str,
        document_text: str,
        detections: List[Any],
        risk_profile: Any,
        filename: str,
        context_chunks: Optional[List[str]] = None,
        raw_risk_profile: Optional[dict] = None,
        raw_detections: Optional[List[dict]] = None,
    ) -> str:
        """
        Answer a user question about the document using AI.
        Uses RAG context chunks if available.
        """
        rp_dict = raw_risk_profile if raw_risk_profile else (risk_profile.to_dict() if hasattr(risk_profile, 'to_dict') else risk_profile)
        dets_list = raw_detections if raw_detections else ([d.to_dict() if hasattr(d, 'to_dict') else d for d in detections] if detections else [])

        if not self.is_available or not rp_dict:
            return self._rule_based_qa(question, dets_list, rp_dict, filename)

        # Build rich context
        detection_summary = self._build_detection_summary(dets_list)

        # Use RAG context if provided
        if context_chunks:
            context_text = "\n\n### Relevant Document Sections:\n" + "\n---\n".join(context_chunks[:3])
        else:
            context_text = f"\n\n### Document Preview:\n{document_text[:3000]}"

        prompt = f"""You are a Data Privacy & Security Compliance AI Assistant.

You are analyzing: "{filename}"

## Detected Sensitive Data:
{detection_summary}

## Risk Level: {rp_dict.get('overall_risk', 'LOW')} (Score: {rp_dict.get('risk_score', 0.0):.1f}/100)
{context_text}

## User Question:
{question}

Answer the question precisely and professionally. 
- **CRITICAL**: Never expose or include any raw, unmasked sensitive data values in your response (e.g., actual full PAN numbers, credit card numbers, passwords, etc.). If you must reference them, use their masked format (e.g., `XXXXX1234X` or `[API KEY]`) or general category names.
- If asking about counts, provide exact numbers from the detection data.
- If asking about compliance, reference DPDP Act 2023 or GDPR as appropriate.
- If the question is about document content not in the detections, use the document preview.
- Always be helpful, specific, and accurate.
- If you cannot answer from the available context, say so clearly."""

        try:
            completion = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a helpful and professional compliance assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=1024,
            )
            return completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq Q&A error: {e}")
            return self._rule_based_qa(question, dets_list, rp_dict)

    def _build_detection_summary(self, detections: List[dict]) -> str:
        """Build a text summary of detections for prompts."""
        if not detections:
            return "No sensitive data detected."

        by_type: dict = {}
        for det in detections:
            type_name = det.get("data_type", "Sensitive Data")
            if type_name not in by_type:
                by_type[type_name] = []
            by_type[type_name].append(det.get("masked_value", ""))

        lines = []
        for dtype, values in by_type.items():
            lines.append(f"- {dtype}: {len(values)} instance(s) — e.g., {values[0]}")

        return "\n".join(lines)

    def _rule_based_summary(
        self, detections: List[dict], risk_profile: Optional[dict], filename: str
    ) -> str:
        """Structured fallback summary when AI is not available."""
        if not risk_profile:
            return "No risk profile generated."

        risk_emoji = {"CRITICAL": "🔴", "HIGH": "生命", "MEDIUM": "🟡", "LOW": "🟢"}
        emoji = risk_emoji.get(risk_profile.get("overall_risk", "LOW"), "⚪")

        lines = [
            f"## {emoji} Compliance Summary for: {filename}",
            f"**Overall Risk Level:** {risk_profile.get('overall_risk', 'LOW')}  |  **Score:** {risk_profile.get('risk_score', 0.0):.1f}/100",
            "",
            "### Executive Summary",
            f"This document has been scanned and {risk_profile.get('total_detections', 0)} sensitive data instances have been identified.",
            f"The document is classified as **{risk_profile.get('overall_risk', 'LOW')} RISK** based on the types and quantities of sensitive data present.",
            "",
            "### Detected Data Categories",
        ]

        for dtype in risk_profile.get("detected_types", []):
            lines.append(f"- {dtype}")

        lines.extend([
            "",
            "### Compliance Framework Exposure",
            "**India DPDP Act 2023:**",
        ])
        for v in risk_profile.get("dpdp_violations", []):
            lines.append(f"  - {v}")

        lines.append("**GDPR:**")
        for v in risk_profile.get("gdpr_violations", []):
            lines.append(f"  - {v}")

        lines.extend([
            "",
            "### Risk Factors",
        ])
        for rf in risk_profile.get("risk_factors", []):
            lines.append(f"- {rf}")

        lines.extend([
            "",
            "### Recommended Actions",
        ])
        for step in risk_profile.get("remediation_steps", [])[:5]:
            lines.append(f"1. {step}")

        lines.extend([
            "",
            "---",
            "*⚠️ To enable AI-powered analysis, configure the GROQ_API_KEY environment variable in your backend environment.*",
        ])

        return "\n".join(lines)

    def _rule_based_qa(
        self, question: str, detections: List[dict], risk_profile: Optional[dict], filename: str = "Document"
    ) -> str:
        """Rule-based Q&A fallback."""
        if not risk_profile:
            return "No risk profile generated."

        q_lower = question.lower()

        if any(word in q_lower for word in ["email", "emails", "email address"]):
            count = sum(1 for d in detections if d.get("data_type") == "Email Address")
            return f"**{count} email address(es)** were detected in this document."

        elif any(word in q_lower for word in ["how many", "count", "total", "number of"]):
            return f"A total of **{len(detections)} sensitive data instances** were detected across {len(risk_profile.get('detected_types', []))} categories."

        elif any(word in q_lower for word in ["risk", "level", "classification"]):
            return f"This document is classified as **{risk_profile.get('overall_risk', 'LOW')} RISK** with a score of {risk_profile.get('risk_score', 0.0):.1f}/100."

        elif any(word in q_lower for word in ["sensitive", "data", "what", "found", "detected"]):
            types_str = ", ".join(risk_profile.get("detected_types", [])) if risk_profile.get("detected_types") else "nothing significant"
            return f"The following sensitive data types were detected: **{types_str}**"

        elif any(word in q_lower for word in ["summarize", "summary", "overview"]):
            types_str = ", ".join(risk_profile.get("detected_types", [])) if risk_profile.get("detected_types") else "no sensitive categories"
            return (
                f"### 📋 Document Compliance Summary\n"
                f"- **Filename:** `{filename}`\n"
                f"- **Risk Profile:** **{risk_profile.get('overall_risk', 'LOW')} RISK** (Score: {risk_profile.get('risk_score', 0.0):.1f}/100)\n"
                f"- **Key Findings:** Identified a total of **{risk_profile.get('total_detections', 0)}** sensitive data indicators.\n"
                f"- **Detected Categories:** {types_str}.\n\n"
                f"*(Note: Individual data values are automatically masked and omitted from this summary to protect confidentiality. You can view the list of masked records in the Detection tab.)*"
            )

        elif any(word in q_lower for word in ["compliance", "gdpr", "dpdp", "regulation"]):
            dpdp = ", ".join(risk_profile.get("dpdp_violations", [])) or "None identified"
            gdpr = ", ".join(risk_profile.get("gdpr_violations", [])) or "None identified"
            return f"**DPDP Act 2023 violations:** {dpdp}\n\n**GDPR violations:** {gdpr}"

        elif any(word in q_lower for word in ["remediation", "fix", "action", "recommend"]):
            steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(risk_profile.get("remediation_steps", [])[:5]))
            return f"**Recommended Actions:**\n{steps}"
        else:
            return (
                f"I found **{risk_profile.get('total_detections', 0)}** sensitive data items in this document "
                f"(Risk Level: **{risk_profile.get('overall_risk', 'LOW')}**). "
                f"For more specific AI-powered answers, please configure the GROQ_API_KEY environment variable in your backend environment."
            )
