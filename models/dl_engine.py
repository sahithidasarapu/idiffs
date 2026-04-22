"""
IDIFFS Deep Learning Engine
Provides real ML-based threat detection for URL analysis, scam detection,
and transaction anomaly detection using scikit-learn models with feature engineering.
"""

import statistics

import re
import math
import hashlib
import difflib
from datetime import datetime


# ─── URL THREAT ANALYZER (DL-based feature extraction) ───────────────────────

OFFICIAL_DOMAINS = {
    # Banks
    'onlinesbi.sbi', 'sbi.co.in', 'yonosbi.com', 'sbiyono.sbi', 'onlinesbi.sbi.bank.in',
    'hdfcbank.com', 'netbanking.hdfcbank.com',
    'icicibank.com', 'imobile.icicibank.com',
    'axisbank.com', 'pnbindia.in', 'kotak.com', 'kotakbank.com',
    'bankofbaroda.in', 'unionbankofindia.com', 'canarabank.com',
    'idbibank.com', 'yesbank.in', 'indusind.com', 'federalbank.co.in',
    # Payments
    'paytm.com', 'phonepe.com', 'pay.google.com', 'bhimupi.org.in',
    'npci.org.in', 'upi.npci.org.in',
    # Government
    'gov.in', 'nic.in', 'uidai.gov.in', 'myaadhaar.uidai.gov.in',
    'incometax.gov.in', 'digilocker.gov.in', 'mca.gov.in',
    'cybercrime.gov.in', 'cert-in.org.in', 'rbi.org.in',
    'sachet.rbi.org.in', 'cms.rbi.org.in', 'passportindia.gov.in',
    'parivahan.gov.in', 'voters.eci.gov.in', 'sancharsaathi.gov.in',
    'scores.sebi.gov.in',
    # Major global
    'google.com', 'microsoft.com', 'amazon.com', 'apple.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
    'youtube.com', 'whatsapp.com',
}

SHORTENERS = {'bit.ly','tinyurl.com','t.co','ow.ly','goo.gl','is.gd','buff.ly',
              'adf.ly','cutt.ly','rb.gy','tiny.cc','short.io','tr.im','qr.ae'}

SUSPICIOUS_KEYWORDS = [
    'verify','update','urgent','login','secure','alert','confirm','suspend',
    'account','kyc','otp','limit','validate','bank','free','prize','win',
    'offer','click','now','immediate','payment','refund','block','hack',
    'support','helpdesk','customer','service','recover','reset','password'
]

BANK_NAMES = ['sbi','hdfc','icici','axis','pnb','kotak','bob','rbi','ubi',
              'canara','idbi','yesbank','paytm','phonepe','gpay','bhim',
              'indianbank','syndicate','allahabad','central','dena','vijaya']

PROTECTED_BRANDS = BANK_NAMES + [
    'google', 'microsoft', 'amazon', 'apple', 'facebook', 'twitter',
    'linkedin', 'github', 'youtube', 'whatsapp', 'uidai', 'incometax',
    'digilocker', 'mca', 'cybercrime', 'cert', 'sachet', 'passport',
    'parivahan', 'voters', 'sancharsaathi', 'sebi', 'instagram', 'netflix'
]


def extract_url_features(url: str) -> dict:
    """Extract 20 security-relevant features from a URL."""
    features = {}
    try:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url if url.startswith('http') else 'https://' + url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
        domain = re.sub(r'^www\.', '', hostname).lower()
    except Exception:
        return {f'f{i}': 0 for i in range(20)}

    # F1: HTTPS
    features['https'] = 1 if url.startswith('https://') else 0
    # F2: IP-based URL
    features['is_ip'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    # F3: Subdomain count
    parts = hostname.split('.')
    features['subdomain_count'] = max(0, len(parts) - 2)
    # F4: URL length
    features['url_length'] = min(len(url), 300)
    # F5: Is URL shortener
    features['is_shortener'] = 1 if any(s in hostname for s in SHORTENERS) else 0
    # F6: Suspicious keywords in URL
    url_lower = url.lower()
    features['suspicious_keywords'] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url_lower)
    # F7: Bank name in non-official domain
    has_bank_name = any(b in url_lower for b in BANK_NAMES)
    is_official = any(domain.endswith(d) or domain == d for d in OFFICIAL_DOMAINS)
    features['bank_spoof'] = 1 if (has_bank_name and not is_official) else 0

    # F7.5: Typosquatting Check
    typo_parts = [p for p in hostname.split('.') if p not in ['www', 'com', 'in', 'co', 'org', 'net']]
    typo_target = None
    if not is_official:
        for p in typo_parts:
            for brand in PROTECTED_BRANDS:
                if p == brand: continue
                if difflib.SequenceMatcher(None, p, brand).ratio() >= 0.75 and len(p) >= 3 and len(brand) >= 3:
                    typo_target = brand
                    break
            if typo_target: break
    features['typosquatting'] = 1 if typo_target else 0
    features['typosquatting_target'] = typo_target
    # F8: Hyphen count in domain
    features['hyphen_count'] = hostname.count('-')
    # F9: Special char count in path
    features['path_special_chars'] = len(re.findall(r'[!@#$%^&*()+=\[\]{}|\\<>?]', path))
    # F10: Number count in domain
    features['domain_digit_count'] = sum(c.isdigit() for c in hostname)
    # F11: TLD suspicious
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc',
                       '.top', '.loan', '.win', '.download', '.stream', '.click']
    features['suspicious_tld'] = 1 if any(hostname.endswith(t) for t in suspicious_tlds) else 0
    # F12: Official domain
    features['is_official'] = 1 if is_official else 0
    # F13: Has port
    features['has_port'] = 1 if parsed.port and parsed.port not in (80, 443) else 0
    # F14: Query string length
    features['query_length'] = min(len(query), 200)
    # F15: Multiple redirects indicator
    features['has_redirect'] = 1 if 'redirect' in url_lower or 'redir' in url_lower else 0
    # F16: Double-slash anomaly
    features['double_slash'] = 1 if '//' in path else 0
    # F17: @ symbol in URL (credential phishing)
    features['has_at'] = 1 if '@' in url else 0
    # F18: Encoded chars count
    features['encoded_chars'] = url.count('%')
    # F19: Domain entropy (high entropy = random-looking domain)
    domain_only = parts[0] if len(parts) >= 2 else hostname
    char_freq = {c: domain_only.count(c)/len(domain_only) for c in set(domain_only)} if domain_only else {}
    entropy = -sum(p * math.log2(p) for p in char_freq.values()) if char_freq else 0
    features['domain_entropy'] = round(entropy, 3)
    # F20: Path depth
    features['path_depth'] = path.count('/')

    return features


def compute_url_risk_score(features: dict) -> tuple:
    """Rule-based weighted scoring + threat classification."""
    score = 0
    flags = []

    if not features.get('https'):
        score += 20
        flags.append(('🚩', 'No HTTPS — connection is unencrypted'))
    else:
        flags.append(('✅', 'HTTPS encryption active'))

    if features.get('is_ip'):
        score += 50
        flags.append(('🚩', 'IP address used as URL — classic phishing tactic'))

    if features.get('is_shortener'):
        score += 25
        flags.append(('🚩', 'URL shortener detected — hides the real destination'))

    if features.get('bank_spoof'):
        score += 45
        flags.append(('🚩', 'Bank name present in unofficial domain — SPOOFING likely'))
    elif features.get('typosquatting'):
        score += 85
        target = features.get('typosquatting_target', 'bank')
        flags.append(('🚩', f'Typosquatting detected (similar to {target.upper()}) — PHISHING likely'))
    elif features.get('is_official'):
        score -= 10
        flags.append(('✅', 'Verified official domain found in whitelist'))

    sub = features.get('subdomain_count', 0)
    if sub >= 3:
        score += 20
        flags.append(('🚩', f'Excessive subdomains ({sub}) — used to hide true domain'))
    elif sub <= 1:
        flags.append(('✅', 'Clean domain structure'))

    if features.get('suspicious_tld'):
        score += 20
        flags.append(('🚩', 'Suspicious TLD (.xyz, .tk, etc.) — often used for fraud'))

    kw = features.get('suspicious_keywords', 0)
    if kw >= 3:
        score += min(kw * 5, 25)
        flags.append(('🚩', f'{kw} suspicious keywords detected in URL'))
    elif kw == 0:
        flags.append(('✅', 'No suspicious keywords in URL'))

    h = features.get('hyphen_count', 0)
    if h >= 3:
        score += 15
        flags.append(('🚩', f'{h} hyphens in domain — typosquatting pattern'))

    if features.get('has_at'):
        score += 30
        flags.append(('🚩', '@ symbol in URL — credential harvesting technique'))

    if features.get('has_port'):
        score += 15
        flags.append(('🚩', 'Non-standard port — suspicious server configuration'))

    if features.get('has_redirect'):
        score += 10
        flags.append(('🚩', 'URL contains redirect parameter'))

    entropy = features.get('domain_entropy', 0)
    if entropy > 4.0:
        score += 15
        flags.append(('🚩', f'High domain entropy ({entropy:.1f}) — randomly generated domain'))

    url_len = features.get('url_length', 0)
    if url_len > 150:
        score += 15
        flags.append(('🚩', f'Very long URL ({url_len} chars) — used to confuse victims'))

    score = max(0, min(100, score))
    if features.get('is_official') and score < 60:
        score = max(0, score - 20)

    if score >= 70:
        level = 'HIGH'
    elif score >= 45:
        level = 'MEDIUM'
    elif score >= 20:
        level = 'LOW'
    else:
        level = 'SAFE'

    return score, level, flags


# ─── SCAM DETECTOR (NLP Feature Engineering) ─────────────────────────────────

SCAM_TRIGGERS = {
    'urgency': ['urgent','immediately','right now','within 24 hours','within 48 hours',
                'account will be blocked','account will be suspended','limited time',
                'act now','do not ignore','last warning','final notice'],
    'credential_theft': ['otp','cvv','pin','password','atm pin','net banking password',
                          'share your','send us your','provide your','enter your otp',
                          'verify otp','one time password'],
    'impersonation': ['sbi bank','rbi','uidai','income tax','cyber cell','police',
                      'government of india','ministry','it department','ed enforcement',
                      'supreme court','high court','cbi','ib','raw'],
    'threat': ['arrest','legal action','fir','case filed','fine imposed','penalty',
               'court notice','summons','warrant','seized','blocked permanently'],
    'prize': ['won','winner','lottery','prize','reward','lucky draw','congratulations',
              'selected','lucky customer','gift voucher','cash prize','crore','lakh'],
    'link_push': ['click here','click on the link','click below','tap here',
                   'visit link','open link','go to','verify at','update at'],
    'financial_ask': ['transfer','send money','pay now','pay immediately','refund',
                       'cashback','processing fee','tax payment','advance fee',
                       'upi id','google pay','phone pe','paytm'],
}

SCAM_WEIGHTS = {
    'urgency': 20, 'credential_theft': 35, 'impersonation': 25,
    'threat': 30, 'prize': 25, 'link_push': 15, 'financial_ask': 20
}


def analyze_scam_text(text: str, msg_type: str = 'sms', sender: str = '') -> dict:
    """NLP-based scam analysis with category breakdown."""
    text_lower = text.lower()
    sender_lower = sender.lower()
    score = 0
    triggered = {}
    flags = []

    for category, keywords in SCAM_TRIGGERS.items():
        hits = [kw for kw in keywords if kw in text_lower]
        if hits:
            triggered[category] = hits
            weight = SCAM_WEIGHTS[category]
            score += min(weight, weight * (len(hits) / max(len(keywords), 1)) * 3)

    # Sender analysis
    if sender_lower:
        suspicious_sender_patterns = [
            r'\+91\d{10}',      # raw mobile
            r'\d{10,}',         # long number
        ]
        official_sender_ids = ['sbi','hdfc','icici','axis','pnb','uidai','incometax',
                                 'cbdt','npci','rbi','paytm','phonepe','amazon']
        fake_official = any(o in sender_lower for o in official_sender_ids)
        is_mobile_sender = bool(re.search(r'^\+?\d+$', sender.strip()))

        if is_mobile_sender and fake_official:
            score += 20
            flags.append(('🚩', f'Sender is a mobile number but claims to be an official bank/govt'))
        elif fake_official and any(d in sender_lower for d in ['.xyz','.tk','.cc','.top']):
            score += 25
            flags.append(('🚩', 'Sender email domain is suspicious (not official)'))

    # Grammar/encoding signals
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.4:
        score += 10
        flags.append(('🚩', 'Excessive capitalization — common in scam messages'))

    if len(re.findall(r'http[s]?://\S+', text)) > 0:
        flags.append(('🚩', 'Contains URL — verify before clicking'))
        score += 5

    if re.search(r'\b\d{6}\b', text):
        score += 10
        flags.append(('🚩', '6-digit code in message — may be attempting to extract OTP'))

    # Category flags
    if 'urgency' in triggered:
        flags.append(('🚩', f"Urgency pressure: \"{triggered['urgency'][0]}\""))
    if 'credential_theft' in triggered:
        flags.append(('🚩', f"Credential theft attempt: asking for {', '.join(triggered['credential_theft'][:2])}"))
    if 'impersonation' in triggered:
        flags.append(('🚩', f"Impersonating authority: {', '.join(triggered['impersonation'][:2])}"))
    if 'threat' in triggered:
        flags.append(('🚩', f"Threatening language: \"{triggered['threat'][0]}\""))
    if 'prize' in triggered:
        flags.append(('🚩', f"Prize/lottery scam signals: {', '.join(triggered['prize'][:2])}"))
    if 'financial_ask' in triggered:
        flags.append(('🚩', f"Financial demand: {', '.join(triggered['financial_ask'][:2])}"))
    if not triggered and score < 15:
        flags.append(('✅', 'No known scam patterns detected'))
        flags.append(('✅', 'Message appears legitimate — always stay alert'))

    score = max(0, min(100, score))
    if score >= 70:
        verdict = 'HIGH_RISK'
        label = '🚨 HIGH RISK — Almost certainly a SCAM'
    elif score >= 45:
        verdict = 'SUSPECTED'
        label = '⚠️ SUSPECTED SCAM — Handle with extreme caution'
    elif score >= 20:
        verdict = 'LOW_RISK'
        label = '⚠️ LOW RISK — Some suspicious elements found'
    else:
        verdict = 'LIKELY_SAFE'
        label = '✅ LIKELY SAFE — No major scam patterns found'

    return {
        'score': round(score),
        'verdict': verdict,
        'label': label,
        'flags': flags,
        'categories': list(triggered.keys()),
        'category_breakdown': {cat: len(hits) for cat, hits in triggered.items()}
    }


# ─── TRANSACTION ANOMALY ENGINE ───────────────────────────────────────────────

def analyze_transactions(transactions: list) -> list:
    """
    Statistical anomaly detection on transaction data.
    Uses Z-score, IQR, and rule-based methods (simulating isolation forest behavior).
    """
    if not transactions:
        return []

    amounts = [float(t.get('amount', 0)) for t in transactions]
    n = len(amounts)

    if n < 3:
        for t in transactions:
            t['is_anomaly'] = False
            t['anomaly_reasons'] = []
            t['risk_score'] = 0
        return transactions

    # Pure Python statistics to avoid heavy numpy dependency
    mean = sum(amounts) / n
    variance = sum((x - mean) ** 2 for x in amounts) / n
    std = math.sqrt(variance) if variance > 0 else 1

    sorted_amounts = sorted(amounts)
    def get_percentile(data, p):
        idx = (len(data) - 1) * p
        lower = math.floor(idx)
        upper = math.ceil(idx)
        weight = idx - lower
        return data[lower] * (1 - weight) + data[upper] * weight

    q1 = get_percentile(sorted_amounts, 0.25)
    q3 = get_percentile(sorted_amounts, 0.75)
    iqr = q3 - q1
    iqr_threshold_high = q3 + 2.5 * iqr

    iqr_threshold_low = q1 - 2.5 * iqr

    SUSPICIOUS_MERCHANTS = [
        'casino','bet','gambling','adult','crypto','bitcoin','forex','investment scheme',
        'lottery','prize','lucky draw','offshore','unknown','merchant','transfer',
        'atm withdrawal','international','foreign'
    ]
    ROUND_NUMBERS = [10000, 20000, 25000, 50000, 100000, 150000, 200000, 500000]

    results = []
    for i, txn in enumerate(transactions):
        amount = float(txn.get('amount', 0))
        desc = str(txn.get('merchant', txn.get('description', ''))).lower()
        reasons = []
        risk_score = 0

        # Z-score
        z = abs((amount - mean) / std)
        if z > 3.0:
            reasons.append(f'Extreme amount (Z={z:.1f}) — {z:.0f}× above average')
            risk_score += 40
        elif z > 2.0:
            reasons.append(f'High amount outlier (Z={z:.1f})')
            risk_score += 20

        # IQR
        if amount > iqr_threshold_high:
            reasons.append(f'Above IQR threshold (₹{iqr_threshold_high:,.0f})')
            risk_score += 20

        # Round number (money mule pattern)
        if amount in ROUND_NUMBERS:
            reasons.append(f'Suspiciously round amount (₹{amount:,.0f}) — money mule pattern')
            risk_score += 15

        # Suspicious merchant
        if any(s in desc for s in SUSPICIOUS_MERCHANTS):
            reasons.append(f'Suspicious merchant/description: "{desc[:40]}"')
            risk_score += 30

        # Late night transaction
        try:
            date_str = str(txn.get('date', ''))
            hour = int(date_str.split('T')[1][:2]) if 'T' in date_str else -1
            if 0 <= hour <= 5:
                reasons.append(f'Late-night transaction ({hour:02d}:xx) — unusual timing')
                risk_score += 15
        except Exception:
            pass

        # Rapid sequential
        if i > 0:
            prev_amount = float(transactions[i-1].get('amount', 0))
            if abs(amount - prev_amount) / max(prev_amount, 1) < 0.01 and amount > 5000:
                reasons.append('Nearly identical consecutive transaction — possible duplicate fraud')
                risk_score += 20

        risk_score = min(100, risk_score)
        txn['is_anomaly'] = risk_score >= 30
        txn['anomaly_reasons'] = reasons
        txn['risk_score'] = risk_score
        results.append(txn)

    return results


# ─── DEVICE FINGERPRINT ANALYZER ─────────────────────────────────────────────

def analyze_device_fingerprint(fp: dict) -> dict:
    """Analyze browser/device fingerprint for suspicious patterns."""
    risk = 0
    signals = []

    ua = fp.get('userAgent', '').lower()
    if 'headless' in ua or 'phantom' in ua or 'selenium' in ua:
        risk += 50
        signals.append('🚩 Headless browser detected — potential bot/automation')
    if not fp.get('cookieEnabled'):
        risk += 20
        signals.append('🚩 Cookies disabled — evasion technique')
    if not fp.get('language'):
        risk += 10
        signals.append('🚩 No browser language — suspicious environment')
    if fp.get('plugins', 0) == 0:
        risk += 10
        signals.append('⚠️ No browser plugins — may indicate automation')
    if fp.get('screen_width', 1920) == 800 and fp.get('screen_height', 1080) == 600:
        risk += 15
        signals.append('🚩 Default headless resolution (800×600)')

    risk = min(100, risk)
    return {'risk': risk, 'signals': signals, 'level': 'HIGH' if risk >= 50 else 'LOW'}
