#!/usr/bin/env python3
import os
import json
import re
import sys
from enum import Enum
from datetime import datetime
from google import genai
import time
DEBUG = False
VERSION = "1.2.3"
MAX_RETRIES = 3
class RiskLevel(str, Enum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious" 
    DANGEROUS = "Dangerous"

class PhishingDetector:
    def __init__(self, api_key=None, debug=False):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Missing API key! Set GEMINI_API_KEY or pass to constructor")
        self.client = genai.Client(api_key=self.api_key)
        self.debug = debug
        self._cache = {}
        self.api_calls = 0
        print(f"[*] Phish detector v{VERSION} ready")
    
    def analyze_email(self, email_text):
        if not email_text or email_text.strip() == "":
            return self._error_response("Empty email text")
        sender, subject, body = self._extract_email_parts(email_text)
        prompt = self._build_prompt(sender, subject, body)
        cache_key = hash(prompt)
        if cache_key in self._cache and not self.debug:
            if self.debug:
                print("[DEBUG] Using cached response")
            response_text = self._cache[cache_key]
        else:
            response_text = self._call_gemini_with_retry(prompt)
            self._cache[cache_key] = response_text
        analysis = self._extract_json(response_text)
        risk_level = self._calc_risk_level(analysis)
        return {
            "timestamp": "2025-03-07 14:05:36",
            "risk_level": risk_level,
            "confidence": self._format_confidence(analysis.get("confidence", 0.5)),
            "reasons": analysis.get("insights", [])[:5],
            "recommended_action": analysis.get("recommended_action", "Review email carefully"), 
            "analysis": analysis.get("reasoning", "")
        }
    def _extract_email_parts(self, raw_text):
        sender = "unknown"
        subject = "unknown"
        body = raw_text
        from_match = re.search(r"From:\s*(.*?)(?:\n|$)", raw_text, re.I)
        if from_match:
            sender = from_match.group(1).strip()
        subj_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", raw_text, re.I)
        if subj_match:
            subject = subj_match.group(1).strip()
        header_pos = 0
        if from_match:
            header_pos = max(header_pos, from_match.end())
        if subj_match:
            header_pos = max(header_pos, subj_match.end())
        if header_pos > 0:
            body = raw_text[header_pos:].strip()
        return sender, subject, body
    def _build_prompt(self, sender, subject, body):
        max_body_len = 5000
        if len(body) > max_body_len:
            body = body[:max_body_len] + "...[truncated]"
        return f"""Analyze this email for phishing threats and security risks.
EMAIL:
From: {sender}
Subject: {subject}
Body: 
{body}
Look for:
- Urgency/threatening language
- Spelling/grammar issues
- Requests for sensitive data (credentials, personal info)
- Suspicious links or attachments
- Brand impersonation attempts
- Social engineering tactics
IMPORTANT: Respond with ONLY a JSON object having this structure:
{{
  "phishing_likelihood": <float 0-1>,
  "confidence": <float 0-1>,
  "insights": [<strings listing specific red flags>],
  "reasoning": "<detailed explanation>",
  "recommended_action": "<action advice for user>"
}}
"""
    def _call_gemini_with_retry(self, prompt):
        models_to_try = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.0-pro"]
        for attempt in range(MAX_RETRIES):
            try:
                model_idx = min(attempt, len(models_to_try) - 1)
                model = models_to_try[model_idx]
                if self.debug:
                    print(f"[DEBUG] Attempt {attempt+1} using model: {model}")
                self.api_calls += 1
                start_time = time.time()
                response = self.client.models.generate_content(
                    model=model,
                    contents=prompt
                )
                if self.debug:
                    elapsed = time.time() - start_time
                    print(f"[DEBUG] API call took {elapsed:.2f}s")
                return response.text
            except Exception as e:
                error_msg = str(e)
                if self.debug:
                    print(f"[DEBUG] API error: {error_msg}")
                if "rate limit" in error_msg.lower():
                    wait_time = (attempt + 1) * 2
                    print(f"Rate limited, waiting {wait_time}s...")
                    time.sleep(wait_time)
                elif attempt < MAX_RETRIES - 1:
                    print(f"Model {model} failed, trying fallback...")
                    time.sleep(1)
                else:
                    return json.dumps({
                        "phishing_likelihood": 0.5,
                        "confidence": 0.4,
                        "insights": ["API error: Unable to analyze email"],
                        "reasoning": f"Error: {error_msg}",
                        "recommended_action": "Please examine the email carefully"
                    })
        return "{}"
    def _extract_json(self, text):
        if not text:
            return {}
        try:
            return json.loads(text)
        except:
            match = re.search(r'({[\s\S]*})', text)
            if match:
                try:
                    return json.loads(match.group(1))
                except:
                    json_text = match.group(1)
                    json_text = re.sub(r'(\w+):', r'"\1":', json_text)
                    json_text = json_text.replace("'", '"')
                    try:
                        return json.loads(json_text)
                    except:
                        pass
        if self.debug:
            print(f"[DEBUG] Failed to parse: {text[:100]}...")
        return {
            "phishing_likelihood": 0.5,
            "confidence": 0.3,
            "insights": ["Parser error - couldn't extract analysis"],
            "reasoning": "Response format error",
            "recommended_action": "Manually review this email"
        }
    def _calc_risk_level(self, analysis):
        phish_score = analysis.get("phishing_likelihood", 0.5)
        insights = analysis.get("insights", [])
        danger_keywords = ["credentials", "password", "account", "urgent", "login", "verify"]
        for insight in insights:
            insight_lower = insight.lower()
            for keyword in danger_keywords:
                if keyword in insight_lower:
                    phish_score += 0.1
                    break
        phish_score = min(phish_score, 1.0)
        if phish_score < 0.35:
            return RiskLevel.SAFE
        elif phish_score < 0.65:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.DANGEROUS
    def _format_confidence(self, confidence):
        try:
            conf_value = float(confidence)
            return conf_value * 100
        except:
            return 50.0
    def _error_response(self, message):
        return {
            "timestamp": "2025-03-07 14:05:36",
            "risk_level": RiskLevel.SUSPICIOUS,
            "confidence": 50.0,
            "reasons": ["Error in analysis process"],
            "recommended_action": "Manual review required",
            "analysis": message
        }
def main():
    print("\n" + "=" * 60)
    print("  PHISHING SHIELD - EMAIL SECURITY ANALYZER  ".center(60, "="))
    print("=" * 60)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = input("Enter Gemini API key: ").strip()
        if not api_key:
            print("Error: No API key provided")
            sys.exit(1)
    debug_mode = "--debug" in sys.argv
    print("Initializing security analyzer...")
    try:
        detector = PhishingDetector(api_key, debug=debug_mode)
    except ValueError as e:
        print(f"Initialization failed: {e}")
        sys.exit(1)
    if "--file" in sys.argv:
        idx = sys.argv.index("--file")
        if idx + 1 < len(sys.argv):
            filename = sys.argv[idx + 1]
            try:
                with open(filename, 'r') as f:
                    email_text = f.read()
                print(f"Loaded email from {filename}")
            except Exception as e:
                print(f"Error reading file: {e}")
                sys.exit(1)
        else:
            print("Error: No filename provided after --file")
            sys.exit(1)
    else:
        print("\nPaste email text below. When finished:")
        print("- Windows: Press Ctrl+Z then Enter")
        print("- Mac/Linux: Press Ctrl+D")
        print("-" * 60)
        email_lines = []
        try:
            while True:
                line = input()
                email_lines.append(line)
        except (EOFError, KeyboardInterrupt):
            pass
        email_text = "\n".join(email_lines)
    if not email_text.strip():
        print("No email text provided!")
        sys.exit(1)
    print("\nAnalyzing email for threats...")
    start_time = time.time()
    try:
        result = detector.analyze_email(email_text)
        elapsed = time.time() - start_time
        risk_level = result["risk_level"]
        risk_colors = {
            "Safe": "\033[92m",
            "Suspicious": "\033[93m",
            "Dangerous": "\033[91m"
        }
        color = risk_colors.get(risk_level, "")
        reset = "\033[0m"
        print("\n" + "=" * 60)
        print(f"  {color}ANALYSIS RESULT: {risk_level}{reset}  ".center(60, "="))
        print("=" * 60)
        print(f"Risk Assessment: {color}{risk_level}{reset}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Analysis time: {elapsed:.2f} seconds")
        print("\nWarning signs detected:")
        if result["reasons"]:
            for i, reason in enumerate(result["reasons"], 1):
                print(f"  {i}. {reason}")
        else:
            print("  None found")
        print(f"\nRecommended Action: {result['recommended_action']}")
        print("\nDetailed Analysis:")
        print("-" * 60)
        print(result["analysis"])
        print("-" * 60)
    except Exception as e:
        print(f"Analysis failed: {e}")
        if debug_mode:
            import traceback
            traceback.print_exc()
if __name__ == "__main__":
    main()
