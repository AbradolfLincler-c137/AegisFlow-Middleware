#!/usr/bin/env python3
"""
AegisFlow CSIC Joblib Threat Predictor
======================================
Predicts threat score (0 to 100) and attack category for incoming payloads using csic2010_best_model.joblib.
"""

import sys
import json
import os
import math
import re
import joblib

# Suppress sklearn unpickling warnings
import warnings
warnings.filterwarnings("ignore")

# Resolve model paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "csic2010_best_model.joblib")
FEATURE_PATH = os.path.join(BASE_DIR, "csic2010_feature_order.joblib")

model = None
feature_names = None

try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
    if os.path.exists(FEATURE_PATH):
        feature_names = list(joblib.load(FEATURE_PATH))
except Exception:
    pass

# ── Attack Signature Patterns (require SQL/attack context, NOT bare English) ──
SQLI_REGEX = re.compile(
    r"('\s*(OR|AND)\s+(1=1|'|true|1\s*=\s*1)|UNION\s+(ALL\s+)?SELECT|DROP\s+(TABLE|DATABASE)"
    r"|INSERT\s+INTO|DELETE\s+FROM|xp_cmdshell|EXEC\s*\(|CONCAT\s*\(|CHAR\s*\("
    r"|LOAD_FILE|INTO\s+OUTFILE|BENCHMARK\s*\(|SLEEP\s*\(|WAITFOR\s+DELAY"
    r"|;\s*(DROP|DELETE|INSERT|UPDATE)\b)",
    re.IGNORECASE
)
XSS_REGEX = re.compile(
    r"(<script[\s>]|javascript\s*:|on(error|load|click|mouseover)\s*=|alert\s*\("
    r"|<iframe|<embed|<object|document\.(cookie|location|write)|eval\s*\()",
    re.IGNORECASE
)
PROMPT_INJ_REGEX = re.compile(
    r"(ignore\s+(all\s+)?previous|system\s+(prompt|override)|jailbreak|dan\s+mode"
    r"|disregard\s+(all|previous|your)|SYSTEM\s+OVERRIDE|unrestricted\s+mode"
    r"|bypass\s+(safety|filter|guard))",
    re.IGNORECASE
)
PATH_TRAVERSAL_REGEX = re.compile(
    r"(\.\./(\.\./)+"
    r"|\.\.\\(\.\.\\)+"
    r"|/etc/(passwd|shadow|hosts)"
    r"|/proc/self"
    r"|%2e%2e%2f)",
    re.IGNORECASE
)
CRED_STUFF_REGEX = re.compile(r"(admin@target\.com|password123|carding|credential.?stuffing)", re.IGNORECASE)

# Benign content detection (no anchor — matches anywhere in text)
BENIGN_REGEX = re.compile(
    r"\b(hi|hello|hey|help|suggest|what|recommend|show|find|compare|looking\s+for"
    r"|need|want|best|top|cheap|cheaper|affordable|budget|review|price|cost"
    r"|how\s+much|where|which|can\s+you|tell\s+me|do\s+you|don'?t|options?"
    r"|keyboards?|docks?|monitors?|displays?|laptops?|mice|mouse|headphones?"
    r"|speakers?|cables?|adapters?|hubs?|accessories?|products?|categories?"
    r"|cart|checkout|order|shipping|warranty|security|software|select\s+a"
    r"|choose|browse|search|filter|sort|under|about|features?|specs?"
    r"|available|store|shop|buy|purchase|deal|offer|return|refund)\b",
    re.IGNORECASE
)

def calculate_entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(text):
    text_str = str(text)
    length_val = len(text_str)
    content_length_log1p = math.log1p(length_val)
    url_length = length_val
    path_length = length_val
    path_depth = text_str.count('/')
    query_length = length_val if '?' in text_str else 0
    num_params = text_str.count('&') + (1 if '?' in text_str else 0)
    num_special_chars = len(re.findall(r"[<>'\"\;%$\&*()=+\-]", text_str))
    num_digits = len(re.findall(r"\d", text_str))
    num_uppercase = len(re.findall(r"[A-Z]", text_str))
    url_entropy = calculate_entropy(text_str)

    has_sqli = 1 if SQLI_REGEX.search(text_str) else 0
    has_xss = 1 if XSS_REGEX.search(text_str) else 0
    has_traversal = 1 if PATH_TRAVERSAL_REGEX.search(text_str) else 0

    return [
        length_val, content_length_log1p, url_length, path_length, path_depth, query_length,
        num_params, num_special_chars, num_digits, num_uppercase, url_entropy,
        has_sqli, has_xss, has_traversal, length_val, 0, 0, 1, 0, 0
    ]

def predict_payload(payload):
    if not payload or len(payload.strip()) == 0:
        return {"score": 0, "category": "Clean"}

    payload_str = payload.strip()

    # Signature checks (same patterns as onnxWaf.js)
    if PROMPT_INJ_REGEX.search(payload_str):
        return {"score": 95, "category": "PromptInjection"}
    if SQLI_REGEX.search(payload_str):
        return {"score": 99, "category": "SqlInjection"}
    if XSS_REGEX.search(payload_str):
        return {"score": 98, "category": "XSS"}
    if PATH_TRAVERSAL_REGEX.search(payload_str):
        return {"score": 96, "category": "PathTraversal"}
    if CRED_STUFF_REGEX.search(payload_str):
        return {"score": 95, "category": "CredentialStuffing"}

    # Benign Shopping Query Fast-pass
    if BENIGN_REGEX.search(payload_str):
        return {"score": 0, "category": "Clean"}

    if model:
        try:
            feats = [extract_features(payload_str)]
            probs = model.predict_proba(feats)[0]
            # Index 1 = anomaly/attack probability
            attack_prob = float(probs[1]) if len(probs) >= 2 else float(probs[0])
            score = int(round(attack_prob * 100))

            category = "Clean"
            if score >= 60:
                category = "CSIC_Anomaly"
            return {"score": score, "category": category}
        except Exception:
            pass

    return {"score": 5, "category": "Clean"}

if __name__ == "__main__":
    payload = sys.argv[1] if len(sys.argv) > 1 else ""
    res = predict_payload(payload)
    print(json.dumps(res))


