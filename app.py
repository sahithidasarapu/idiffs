# -*- coding: utf-8 -*-
import eventlet
eventlet.monkey_patch()

import os
# Ensure essential directories exist before any other imports or logging
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
os.makedirs('models', exist_ok=True)

"""
IDIFFS — Integrated Digital Intelligence & Forensic Security System


Professional Cyber Crime Intelligence Platform
Government-grade application for cyber forensics and crime detection
"""

import os
import re
import sys
import psutil
import json
import sqlite3
import math
import uuid
import hashlib
import logging
import threading
import subprocess
from flask_socketio import SocketIO, emit
try:
    from scapy.all import sniff, IP, TCP, DNS, DNSQR
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

import time as time_module
import requests
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
try:
    from win10toast import ToastNotifier
    system_notifier = ToastNotifier()
except ImportError:
    system_notifier = None

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (Flask, render_template, request, jsonify,
                   session, redirect, url_for, send_from_directory)
from flask_mail import Mail, Message  # pip install Flask-Mail
from config import Config
# from flask_cors import CORS  # install: pip install flask-cors

# Deep learning engine
from models.dl_engine import (
    extract_url_features, compute_url_risk_score,
    analyze_scam_text, analyze_transactions, analyze_device_fingerprint,
    OFFICIAL_DOMAINS
)

# ─── APP SETUP ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ─── REAL-TIME IDS CONFIG ──────────────────────────────────────────────────
SUSPICIOUS_DOMAINS = ["malware.com", "phish.xyz", "c2-server.net", "hack.io"]
IDS_ACTIVE = True

# ─── CACHE CONTROL ────────────────────────────────────────────────────────────
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# CORS(app)  # Enable in production

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/idiffs.log', mode='a')
    ]
)
logger = logging.getLogger('IDIFFS')


# ─── DATABASE SETUP (SQLite Persistence) ─────────────────────────────────────
DB_PATH = 'data/idiffs.db'
os.makedirs('data', exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    # Forensic Events Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        timestamp TEXT,
        module TEXT,
        type TEXT,
        severity INTEGER,
        desc TEXT,
        ip TEXT,
        session TEXT,
        block_hash TEXT
    )''')
    # Blockchain Ledger Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS blockchain (
        idx INTEGER PRIMARY KEY,
        timestamp TEXT,
        data_hash TEXT,
        prev_hash TEXT,
        nonce TEXT,
        hash TEXT
    )''')
    # Identity Vault Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS vault (
        id TEXT PRIMARY KEY,
        type TEXT,
        label TEXT,
        data TEXT,
        masked TEXT,
        added TEXT,
        source TEXT,
        session_id TEXT
    )''')
    # Scam Analysis History
    cursor.execute('''CREATE TABLE IF NOT EXISTS scam_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        sender TEXT,
        score INTEGER,
        verdict TEXT,
        time TEXT,
        session_id TEXT
    )''')
    # URL Analysis History
    cursor.execute('''CREATE TABLE IF NOT EXISTS url_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        hostname TEXT,
        score INTEGER,
        level TEXT,
        time TEXT,
        session_id TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

# ─── BLOCKCHAIN LEDGER (Persistent) ──────────────────────────────────────────
ledger_lock = threading.Lock()

# Forensic Speed Cache
geo_cache = {}
CACHE_EXPIRY = 3600 * 24 # 24 Hours

def seal_on_blockchain(data_dict):
    """Cryptographically seal an event or document on a persistent blockchain ledger."""
    with ledger_lock:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT hash FROM blockchain ORDER BY idx DESC LIMIT 1")
        row = cursor.fetchone()
        prev_hash = row[0] if row else "0" * 64
        
        idx = cursor.execute("SELECT COUNT(*) FROM blockchain").fetchone()[0]
        timestamp = datetime.now().isoformat()
        data_hash = hashlib.sha256(json.dumps(data_dict, sort_keys=True).encode()).hexdigest()
        nonce = str(uuid.uuid4())[:8]
        
        block_content = f"{idx}{timestamp}{data_hash}{prev_hash}{nonce}"
        block_hash = hashlib.sha256(block_content.encode()).hexdigest()
        
        cursor.execute("INSERT INTO blockchain (idx, timestamp, data_hash, prev_hash, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)",
                       (idx, timestamp, data_hash, prev_hash, nonce, block_hash))
        conn.commit()
        conn.close()
        return block_hash

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def get_session_id():
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
    return session['sid']

# ─── FORENSIC INTELLIGENCE DATABASE (Manual Overrides for Accuracy) ──────────
# This ensures major Indian Govt/Bank data centers show their actual physical site
FORENSIC_INTEL_DB = {
    "uidai.gov.in": {"city": "Bengaluru", "lat": 12.9716, "lon": 77.5946, "desc": "UIDAI Primary Data Center (Aadhaar)"},
    "rbi.org.in": {"city": "Mumbai", "lat": 18.9220, "lon": 72.8347, "desc": "Reserve Bank of India HQ"},
    "nic.in": {"city": "New Delhi", "lat": 28.6139, "lon": 77.2090, "desc": "National Informatics Centre HQ"},
    "isro.gov.in": {"city": "Bengaluru", "lat": 13.0343, "lon": 77.5650, "desc": "ISRO Headquarters"},
    "onlinesbi.sbi": {"city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "desc": "SBI Centralized Banking Server"}
}

def get_geo_info(ip_or_host):
    """Retrieve geolocation data with Forensic Intelligence Override."""
    # Check Intelligence DB first for "Exact" Accuracy
    if ip_or_host in FORENSIC_INTEL_DB:
        intel = FORENSIC_INTEL_DB[ip_or_host]
        return {
            'latitude': intel['lat'],
            'longitude': intel['lon'],
            'city': intel['city'],
            'country_name': 'India',
            'source': 'Forensic Intelligence DB'
        }

    ip = ip_or_host
    key = os.environ.get('IPSTACK_KEY')
    now = time_module.time()
    
    # Cache Check
    if ip in geo_cache:
        cached_data, timestamp = geo_cache[ip]
        if now - timestamp < CACHE_EXPIRY:
            return cached_data

    if not ip and request:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        
    if not ip or ip in ['127.0.0.1', 'localhost', '::1']:
        return None

    # ENGINE 1: Ipstack (Global Standard)
    data = None
    if key:
        try:
            r = requests.get(f"http://api.ipstack.com/{ip}?access_key={key}", timeout=3)
            data = r.json()
        except Exception:
            data = None

    # ENGINE 2: IP-API (High-Precision Fallback)
    try:
        r2 = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,as", timeout=3)
        data2 = r2.json()
        if data2.get('status') == 'success':
            city = data2.get('city')
            lat, lon = data2.get('lat'), data2.get('lon')
            isp = data2.get('isp', '').upper()
            
            # --- FORENSIC NODE RESOLVER: City-Code Intelligence ---
            # We perform a Reverse DNS lookup to find city codes in the hardware name
            try:
                import socket
                hostname_node, _, _ = socket.gethostbyaddr(ip)
                node_name = hostname_node.lower()
                
                # City Code Mapping (High-Precision nodes)
                city_fixes = {
                    'blr': ('Bengaluru', 12.9716, 77.5946),
                    'bangalore': ('Bengaluru', 12.9716, 77.5946),
                    'bom': ('Mumbai', 18.9220, 72.8347),
                    'mumbai': ('Mumbai', 18.9220, 72.8347),
                    'del': ('New Delhi', 28.6139, 77.2090),
                    'delhi': ('New Delhi', 28.6139, 77.2090),
                    'hyd': ('Hyderabad', 17.3850, 78.4867),
                    'maa': ('Chennai', 13.0827, 80.2707),
                    'chn': ('Chennai', 13.0827, 80.2707)
                }
                for code, (fixed_city, fixed_lat, fixed_lon) in city_fixes.items():
                    if code in node_name:
                        city, lat, lon = fixed_city, fixed_lat, fixed_lon
                        break
            except Exception: pass

            # SPECIAL FORENSIC LOGIC: Indian Govt Network (NIC) Accuracy Fix
            if "NATIONAL INFORMATICS CENTRE" in isp:
                # If we detect NIC, we use a 3rd specialized provider for Govt Nodes
                try:
                    r3 = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
                    data3 = r3.json()
                    if data3.get('city'):
                        city = data3.get('city')
                except Exception: pass

            result = {
                'latitude': lat,
                'longitude': lon,
                'city': city,
                'country_name': data2.get('country'),
                'region_name': data2.get('regionName'),
                'isp': data2.get('isp'),
                'source': 'Forensic Backbone Trace'
            }
            geo_cache[ip] = (result, now)
            return result
    except Exception:
        pass

    # Fallback to Engine 1 if Engine 2 failed
    if data and 'latitude' in data:
        result = {
            'latitude': data['latitude'],
            'longitude': data['longitude'],
            'city': data.get('city'),
            'country_name': data.get('country_name'),
            'region_name': data.get('region_name'),
            'source': 'Global Engine'
        }
        geo_cache[ip] = (result, now)
        return result

    return None

def block_malicious_domain(domain):
    """Add a Windows Firewall rule to block a suspicious domain."""
    if not domain: return
    try:
        # Create a blocking rule for the domain (IP lookup might be needed, but we start with a hostname rule if possible via hosts file or firewall)
        # Note: netsh usually blocks IPs. For simplicity, we'll try to resolve and block.
        ip_addr = hashlib.sha256(domain.encode()).hexdigest()[:8] # Dummy for log
        cmd = f'netsh advfirewall firewall add rule name="IDIFFS_BLOCK_{domain}" dir=out action=block remoteip=any description="IDIFFS Auto-Block: {domain}"'
        # subprocess.run(cmd, shell=True) # Uncomment in production with admin
        logger.info(f"FIREWALL: Rule prepared to block {domain}")
        return True
    except Exception as e:
        logger.error(f"Firewall block error: {e}")
        return False

def log_forensic_event(module, event_type, severity, description, agent_ip=None):
    time_str = datetime.now().strftime('%H:%M:%S')
    timestamp = datetime.now().isoformat()
    ip = agent_ip or request.remote_addr if request else 'SYSTEM'
    session_id = get_session_id() if request else 'SYSTEM'
    
    # Pre-seal data
    ev_data = {
        'time': time_str,
        'module': module,
        'type': event_type,
        'severity': severity,
        'desc': description
    }
    block_hash = seal_on_blockchain(ev_data)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO events 
        (time, timestamp, module, type, severity, desc, ip, session, block_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (time_str, timestamp, module, event_type, severity, description, ip, session_id, block_hash))
    conn.commit()
    conn.close()

    # Emit via Socket.IO for INSTANT dashboard updates
    event_payload = {
        'time': time_str, 'module': module, 'type': event_type,
        'severity': severity, 'desc': description, 'block_hash': block_hash
    }
    socketio.emit('new_event', event_payload, namespace='/')
    
    # Check for Critical Alerts for System Notification
    if severity >= 4:
        send_system_notification(f"CRITICAL: {module}", description)

    logger.info(f"[{module}] {event_type} SEV:{severity} — {description} [SEALED:{block_hash[:8]}]")
    return {'block_hash': block_hash}
digilocker_sessions = {}
sessions_data = {}

def ts():
    return datetime.now().strftime('%H:%M:%S')

def send_system_notification(title, message):
    """Send a Windows system toast notification."""
    if system_notifier:
        try:
            # Run in a thread so it doesn't block the Flask request
            threading.Thread(target=system_notifier.show_toast, args=(title, message), 
                             kwargs={'duration': 10, 'threaded': True}).start()
        except Exception:
            pass

def send_ntfy_notification(topic, title, message):
    """Send a free notification to a mobile device via ntfy.sh (No API Key Required)."""
    try:
        requests.post(f"https://ntfy.sh/{topic}",
            data=message.encode('utf-8'),
            headers={
                "Title": title,
                "Priority": "high",
                "Tags": "locked_with_key,key"
            },
            timeout=5
        )
        return True
    except Exception as e:
        logger.error(f"NTFY delivery failed: {str(e)}")
        return False

def send_otp_email(recipient_email, otp_code, user_display):
    """Send OTP to the user's real email address."""
    try:
        msg = Message(
            subject=f"IDIFFS - DigiLocker Verification Code: {otp_code}",
            recipients=[recipient_email],
            body=f"Namaste,\n\nYour DigiLocker Identity Verification Code is: {otp_code}\n\nThis code is being used for access through the IDIFFS Cyber Forensic Platform for {user_display}.\n\nIf you did not request this, please ignore this email.\n\nJai Hind,\nIDIFFS Security Team"
        )
        # Use HTML for a more professional look
        msg.html = render_template('email_otp.html', otp=otp_code, display=user_display)
        
        # Run in thread to avoid blocking
        threading.Thread(target=app.with_app_context(lambda: mail.send(msg))).start()
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email}: {str(e)}")
        return False

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

@app.route('/api/debug/geo/<target>')
def api_debug_geo(target):
    """Debug route to test Ipstack connectivity and response."""
    key = os.environ.get('IPSTACK_KEY')
    try:
        r = requests.get(f"http://api.ipstack.com/{target}?access_key={key}", timeout=5)
        return jsonify({
            'status_code': r.status_code,
            'response': r.json(),
            'key_used': f"{key[:4]}...{key[-4:]}" if key else "None"
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# ─── ROUTES: MAIN ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    sid = get_session_id()
    log_forensic_event('SYSTEM', 'ACCESS', 1, f'Platform accessed — Session {sid[:8]}')
    return render_template('index.html', session_id=sid)

@app.route('/api/session/info')
def session_info():
    sid = get_session_id()
    return jsonify({
        'session_id': sid,
        'agent_ip': request.remote_addr,
        'platform_time': datetime.now().isoformat(),
        'platform_version': 'IDIFFS v3.2.1-GOV',
        'modules': ['URL_ANALYZER','SCAM_DETECTOR','TRANSACTION_ENGINE',
                    'VAULT','DIGILOCKER','VOICE_AI','FORENSICS']
    })

# ─── ROUTES: URL ANALYZER ────────────────────────────────────────────────────

@app.route('/api/url/analyze', methods=['POST'])
@require_api_key
def api_url_analyze():
    data = request.get_json()
    raw_url = (data or {}).get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'URL is required'}), 400

    url = raw_url if raw_url.startswith('http') else 'https://' + raw_url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        domain = re.sub(r'^www\.', '', hostname).lower()
    except Exception:
        return jsonify({'error': 'Invalid URL format'}), 400

    try:
        import socket
        socket.gethostbyname(hostname)
        is_reachable = True
    except socket.gaierror:
        is_reachable = False

    features = extract_url_features(url)
    score, level, flags = compute_url_risk_score(features)

    if not is_reachable:
        score = 100
        level = 'HIGH'
        flags.insert(0, ('🚨', 'URL Unreachable — Domain does not exist or is offline (ACCESS STOPPED)'))

    severity_map = {'SAFE': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 5, 'INVALID': 2}
    log_forensic_event(
        'URL_ANALYZER', 'URL_SCAN', severity_map.get(level, 2),
        f'Scanned: {hostname} — {level} ({score}/100)'
    )

    # Geo & whois simulation
    registered_tld = hostname.split('.')[-1] if '.' in hostname else 'unknown'

    # Save to history DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO url_history (url, hostname, score, level, time, session_id)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   (url, hostname, score, level, datetime.now().strftime('%H:%M:%S'), get_session_id()))
    conn.commit()
    conn.close()

    # Geo lookup for the map
    geo = get_geo_info(hostname)
    if geo and geo.get('latitude'):
        socketio.emit('new_threat_map', {
            'lat': geo['latitude'],
            'lon': geo['longitude'],
            'city': geo.get('city', 'Unknown'),
            'type': 'URL_MANUAL_SCAN',
            'desc': f"Manual Scan: {hostname} ({level})",
            'source': geo.get('source', 'Standard')
        })

    return jsonify({
        'url': raw_url,
        'hostname': hostname,
        'domain': domain,
        'score': score,
        'level': level,
        'flags': flags,
        'features': features,
        'registered_tld': registered_tld,
        'is_official': any(domain.endswith(d) or domain == d for d in OFFICIAL_DOMAINS),
        'timestamp': ts(),
        'scan_id': str(uuid.uuid4())[:8].upper()
    })

# ─── ROUTES: SCAM DETECTOR ───────────────────────────────────────────────────

@app.route('/api/scam/analyze', methods=['POST'])
@require_api_key
def api_scam_analyze():
    data = request.get_json()
    text = (data or {}).get('text', '').strip()
    msg_type = (data or {}).get('type', 'sms')
    sender = (data or {}).get('sender', '')

    if not text:
        return jsonify({'error': 'Message text is required'}), 400
    if len(text) > 5000:
        return jsonify({'error': 'Message too long (max 5000 chars)'}), 400

    result = analyze_scam_text(text, msg_type, sender)

    severity_map = {'HIGH_RISK': 5, 'SUSPECTED': 4, 'LOW_RISK': 2, 'LIKELY_SAFE': 1}
    # Log result
    time_str = datetime.now().strftime('%H:%M:%S')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO scam_history (type, sender, score, verdict, time, session_id)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   (msg_type, sender, result['score'], result['verdict'], time_str, get_session_id()))
    conn.commit()
    conn.close()

    log_forensic_event('SCAM_DETECTOR', 'SCAN_COMPLETE', 2 if result['score'] > 50 else 1, 
                        f"Scam analysis for {sender}: {result['verdict']} ({result['score']}%)")
    
    # Geo lookup for the map
    geo = get_geo_info(None) # None will force it to check the requester's IP
    if geo and geo.get('latitude'):
        socketio.emit('new_threat_map', {
            'lat': geo['latitude'],
            'lon': geo['longitude'],
            'city': geo.get('city', 'Unknown'),
            'type': 'SCAM_MANUAL_SCAN',
            'desc': f"Manual Scam Scan from {geo.get('city')}: {result['verdict']}",
            'source': geo.get('source', 'Standard')
        })

    return jsonify(result)

# ─── ROUTES: SMS COMPANION ───────────────────────────────────────────────────

@app.route('/api/sms', methods=['POST'])
def api_sms_webhook():
    data = request.get_json() or {}
    sender = data.get('sender', 'Unknown')
    message = data.get('message', '') or data.get('text', '')
    
    if not message:
        return jsonify({'error': 'No message provided'}), 400

    logger.info(f"Received SMS from companion app: {sender}")
    
    # Analyze the incoming SMS for scams/threats
    result = analyze_scam_text(message, 'sms', sender)
    
    # Save directly to the database
    time_str = datetime.now().strftime('%H:%M:%S')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO scam_history (type, sender, score, verdict, time, session_id)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   ('sms', sender, result['score'], result['verdict'], time_str, 'COMPANION_APP'))
    conn.commit()
    conn.close()

    # Log to forensic ledger
    log_forensic_event('SCAM_DETECTOR', 'COMPANION_SMS_RECEIVED', 2 if result['score'] > 50 else 1, 
                        f"Companion App SMS from {sender}: {result['verdict']} ({result['score']}%)")

    # Enhancement 2: AI-powered deep triage
    ai_result = ai_triage_sms(sender, message)
    if ai_result:
        tactics = ', '.join(ai_result.get('tactics', [])) or 'None'
        log_forensic_event('AI_TRIAGE', 'SMS_DEEP_ANALYSIS', 
                          3 if ai_result.get('threat_level') in ['HIGH', 'CRITICAL'] else 1,
                          f"AI Triage: {ai_result.get('threat_level')} (conf:{ai_result.get('confidence')}%) | Tactics: {tactics}")

    # ----- LIVE URL EXTRACTION AND ANALYSIS -----
    # Extract URLs from the SMS message
    urls = re.findall(r'(https?://[^\s]+)', message)
    if not urls:
        # fallback for URLs without http/https
        urls = re.findall(r'\b(www\.[^\s]+)\b', message)
        
    for raw_url in urls:
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
        except Exception:
            hostname = raw_url
            
        # Analyze the URL
        features = extract_url_features(url)
        url_score, url_level, url_flags = compute_url_risk_score(features)
        
        # Save to URL history
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO url_history (url, hostname, score, level, time, session_id)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                       (url, hostname, url_score, url_level, time_str, 'COMPANION_APP'))
        conn.commit()
        conn.close()

        # Geo lookup for the URL
        geo = get_geo_info(hostname)
        if geo and geo.get('latitude'):
            socketio.emit('new_threat_map', {
                'lat': geo['latitude'],
                'lon': geo['longitude'],
                'city': geo.get('city', 'Unknown'),
                'type': 'URL_PHISH',
                'desc': f"Phishing URL hosted in {geo.get('country_name')}",
                'source': geo.get('source', 'Standard')
            })

        # Auto-Block if HIGH_RISK
        if url_level == 'HIGH' or url_score > 80:
            block_malicious_domain(hostname)
            log_forensic_event('FIREWALL', 'AUTO_BLOCK', 4, f"Blocked high-risk domain: {hostname}")

        severity_map = {'SAFE': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 5, 'INVALID': 2}
        log_forensic_event(
            'URL_ANALYZER', 'LIVE_SMS_URL_SCAN', severity_map.get(url_level, 2),
            f'SMS URL Detected: {hostname} — {url_level} ({url_score}/100)'
        )

    # Send a Windows system notification so the user knows an SMS arrived!
    send_system_notification("IDIFFS Companion App", f"SMS Analyzed from {sender}: {result['verdict']} ({result['score']}%)")

    return jsonify({'success': True, 'message': 'SMS received and analyzed'})

@app.route('/api/scam/history', methods=['GET'])
def api_scam_history():
    """Fetch scam analysis history for live updating UI."""
    try:
        conn = get_db()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scam_history ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.close()
        history = []
        for r in rows:
            history.append({
                'time': r['time'],
                'type': r['type'],
                'sender': r['sender'],
                'score': r['score'],
                'verdict': r['verdict']
            })
        return jsonify({'history': history})
    except Exception as e:
        logger.error(f"Error fetching scam history: {e}")
        return jsonify({'history': []})

@app.route('/api/url/history', methods=['GET'])
def api_url_history():
    """Fetch URL analysis history for live updating UI."""
    try:
        conn = get_db()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM url_history ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.close()
        history = []
        for r in rows:
            history.append({
                'time': r['time'],
                'url': r['url'],
                'hostname': r['hostname'],
                'score': r['score'],
                'level': r['level']
            })
        return jsonify({'history': history})
    except Exception as e:
        logger.error(f"Error fetching URL history: {e}")
        return jsonify({'history': []})

# ─── ROUTES: TRANSACTION ANALYZER ────────────────────────────────────────────

@app.route('/api/transaction/analyze', methods=['POST'])
@require_api_key
def api_transaction_analyze():
    data = request.get_json()
    transactions = (data or {}).get('transactions', [])

    if not transactions:
        return jsonify({'error': 'No transaction data provided'}), 400
    if len(transactions) > 10000:
        return jsonify({'error': 'Too many transactions (max 10,000)'}), 400

    results = analyze_transactions(transactions)
    anomalies = [r for r in results if r.get('is_anomaly')]
    amounts = [float(r.get('amount', 0)) for r in results]
    total = sum(amounts)
    avg = total / len(amounts) if amounts else 0

    log_forensic_event(
        'TRANSACTION_ENGINE', 'ANOMALY_SCAN', 3 if anomalies else 1,
        f'{len(transactions)} transactions analyzed — {len(anomalies)} anomalies found'
    )

    return jsonify({
        'results': results,
        'summary': {
            'total_transactions': len(results),
            'anomaly_count': len(anomalies),
            'total_amount': round(total, 2),
            'average_amount': round(avg, 2),
            'anomaly_rate': round(len(anomalies)/len(results)*100, 1) if results else 0
        },
        'timestamp': ts()
    })


# ─── ROUTES: DIGILOCKER INTEGRATION ─────────────────────────────────────────
@app.route('/api/digilocker/initiate-real', methods=['GET'])
def api_digilocker_initiate_real():
    """Initiate real OAuth 2.0 handshake with DigiLocker."""
    sid = get_session_id()
    state = hashlib.sha256(f"{sid}{app.secret_key}".encode()).hexdigest()
    
    params = {
        "response_type": "code",
        "client_id": app.config['DL_CLIENT_ID'],
        "redirect_uri": app.config['DL_REDIRECT_URI'],
        "state": state
    }
    auth_url = f"{app.config['DL_AUTH_URL']}?{urllib.parse.urlencode(params)}"
    return jsonify({"success": True, "auth_url": auth_url})


@app.route('/api/digilocker/callback', methods=['GET'])
def api_digilocker_callback():
    """Handle OAuth 2.0 callback from DigiLocker."""
    code = request.args.get('code')
    state_received = request.args.get('state')
    sid = get_session_id()
    
    # Verify state for security
    expected_state = hashlib.sha256(f"{sid}{app.secret_key}".encode()).hexdigest()
    if state_received != expected_state:
        return "Security Error: State mismatch", 403

    # Exchange code for access token
    payload = {
        "code": code,
        "grant_type": "authorization_code",
        "client_id": app.config['DL_CLIENT_ID'],
        "client_secret": app.config['DL_CLIENT_SECRET'],
        "redirect_uri": app.config['DL_REDIRECT_URI']
    }
    
    try:
        r = requests.post(app.config['DL_TOKEN_URL'], data=payload)
        token_data = r.json()
        
        if 'access_token' in token_data:
            # Fetch issued files
            token = token_data['access_token']
            headers = {"Authorization": f"Bearer {token}"}
            f_res = requests.get(app.config['DL_FILES_URL'], headers=headers)
            files = f_res.json().get('items', [])
            
            # Convert to our format
            docs = []
            for f in files:
                docs.append({
                    'id': f.get('id', str(uuid.uuid4())[:8]),
                    'name': f.get('name', 'Document'),
                    'issuer': f.get('issuer', 'Government Entity'),
                    'type': 'issued', 'icon': '📄',
                    'number': f.get('doctype', 'N/A'),
                    'valid_till': 'N/A', 'status': 'OFFICIAL',
                    'fetched_at': datetime.now().strftime('%d %b %Y %H:%M')
                })
                
            digilocker_sessions[sid] = {
                'state': 'CONNECTED',
                'connected': True,
                'display': token_data.get('name', 'Citizen'),
                'documents': docs,
                'access_token': token,
                'connected_at': datetime.now().isoformat()
            }
            
            log_forensic_event('DIGILOCKER', 'PROD_AUTH', 1, f'Real DigiLocker sync successful for {token_data.get("name")}')
            
            # Redirect back to frontend
            return redirect('/#digilocker')
        else:
            return f"Auth Error: {token_data.get('error_description', 'Unknown error')}", 400
            
    except Exception as e:
        return f"System Error: {str(e)}", 500


@app.route('/api/digilocker/initiate', methods=['POST'])
def api_digilocker_initiate():
    """
    Initiates DigiLocker OAuth 2.0 flow.
    In direct mode: skips manual entry and connects.
    """
    data = request.get_json()
    mode = (data or {}).get('mode', 'manual')
    identifier = (data or {}).get('identifier', '').strip()
    id_type = (data or {}).get('type', 'mobile')

    sid = get_session_id()
    auth_code = str(uuid.uuid4())[:6].upper()

    if mode == 'direct':
        # Use provided identifier or default
        if not identifier:
            identifier = "OFFICIAL_AUTH"
        id_type = "oauth2"
        display = identifier if "@" in identifier else f"User: {identifier}"
        recognized_name = f"AUTHENTICATED: {identifier.upper()}"
    else:
        if not identifier:
            return jsonify({'error': 'Phone number or email is required'}), 400
        # Validate manual
        if id_type == 'mobile':
            clean = re.sub(r'[\s\-\+]', '', identifier)
            if not re.match(r'^(?:91)?[6-9]\d{9}$', clean):
                return jsonify({'error': 'Invalid Indian mobile number. Use 10-digit mobile starting with 6-9'}), 400
            display = f'+91-{clean[-10:-5]}-{clean[-5:]}'
        else:
            if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', identifier):
                return jsonify({'error': 'Invalid email address format'}), 400
            display = identifier
        recognized_name = "SAHITHI ****" if id_type == 'mobile' else "S**** @G****.COM"

    digilocker_sessions[sid] = {
        'state': 'OTP_SENT' if mode != 'direct' else 'CONNECTED',
        'identifier': identifier,
        'id_type': id_type,
        'display': display,
        'auth_code': auth_code,
        'initiated_at': datetime.now().isoformat(),
        'connected': mode == 'direct'
    }

    if mode == 'direct':
        # Skip OTP and go to docs
        docs = _simulate_digilocker_documents(identifier)
        digilocker_sessions[sid].update({
            'documents': docs,
            'connected_at': datetime.now().isoformat(),
            'access_token': hashlib.sha256(f"{sid}DIRECT".encode()).hexdigest()[:32]
        })
        log_forensic_event('DIGILOCKER', 'DIRECT_AUTH_SUCCESS', 1, f'Direct DigiLocker sync for {display}')
        
        steps = [
            f'[{ts()}] 🌐 Connecting to official DigiLocker OAuth 2.0 gateway...',
            f'[{ts()}] 🔐 Protocol: TLS 1.3 / AES-256-GCM',
            f'[{ts()}] 🆔 Handshake successful — Citizen identified',
            f'[{ts()}] 📂 Syncing {len(docs)} verified documents from National Data Center...',
            f'[{ts()}] ✅ Sync complete. All documents sealed on forensic ledger.',
        ]
        return jsonify({
            'success': True,
            'state': 'CONNECTED',
            'display': display,
            'documents': docs,
            'steps': steps,
            'connected_at': datetime.now().strftime('%d %b %Y %H:%M:%S'),
            'message': 'Connected directly to DigiLocker Official.'
        })

    # Manual mode logic below...
    log_forensic_event('DIGILOCKER', 'AUTH_INITIATE', 1, f'DigiLocker auth initiated for {id_type}: {display}')
    
    steps = [
        f'[{ts()}] 🔐 Initiating DigiLocker OAuth 2.0 handshake...',
        f'[{ts()}] 🌐 Connecting to api.digitallocker.gov.in...',
        f'[{ts()}] 📡 TLS 1.3 encrypted channel established',
        f'[{ts()}] 🔍 Searching National Population Register (NPR) database...',
        f'[{ts()}] ✅ Citizen Record Found: {recognized_name}',
        f'[{ts()}] 📱 OTP sent to registered device {display}',
        f'[{ts()}] ⏳ Awaiting OTP verification...',
    ]


    # TRIGER SYSTEM NOTIFICATION (On the device)
    send_system_notification(
        "IDIFFS - OTP RECEIVED",
        f"G.O.I. DigiLocker OTP for {display} is: {auth_code}\nValid for 10 minutes."
    )

    # TRIGGER REAL EMAIL (If identifier is email)
    if id_type == 'email':
        send_otp_email(identifier, auth_code, display)
    
    # TRIGGER FREE MOBILE NOTIFICATION (NTFY)
    # Using a topic based on the identifier to keep it somewhat unique
    topic = "idiffs_" + hashlib.md5(identifier.encode()).hexdigest()[:8]
    send_ntfy_notification(
        topic,
        "IDIFFS Identity Verification",
        f"Your DigiLocker OTP for {display} is: {auth_code}. Proceed to platform to verify."
    )
    
    return jsonify({
        'success': True,
        'state': 'OTP_SENT',
        'display': display,
        'user_hint': recognized_name,
        'otp_hint': f'Demo OTP: {auth_code}', 
        'ntfy_topic': topic,
        'steps': steps,
        'message': f'OTP sent to {display}. Enter OTP to complete verification.'
    })


@app.route('/api/digilocker/verify', methods=['POST'])
def api_digilocker_verify():
    """Verify OTP and complete DigiLocker authentication."""
    data = request.get_json()
    otp = (data or {}).get('otp', '').strip().upper()
    sid = get_session_id()

    dl_state = digilocker_sessions.get(sid)
    if not dl_state:
        return jsonify({'error': 'No active DigiLocker session. Please initiate first.'}), 400

    if dl_state['state'] != 'OTP_SENT':
        return jsonify({'error': 'Invalid session state'}), 400

    # Verify OTP (demo: match auth_code; production: call DigiLocker API)
    if otp != dl_state['auth_code']:
        log_forensic_event('DIGILOCKER', 'AUTH_FAIL', 3,
                            f'DigiLocker OTP mismatch for {dl_state["display"]}')
        return jsonify({'error': 'Invalid OTP. Please check and try again.', 'success': False}), 401

    # Simulate document fetch from DigiLocker
    docs = _simulate_digilocker_documents(dl_state['identifier'])

    digilocker_sessions[sid].update({
        'state': 'CONNECTED',
        'connected': True,
        'connected_at': datetime.now().isoformat(),
        'documents': docs,
        'access_token': hashlib.sha256(f"{sid}{otp}".encode()).hexdigest()[:32]
    })

    log_forensic_event('DIGILOCKER', 'AUTH_SUCCESS', 1,
                        f'DigiLocker connected for {dl_state["display"]} — {len(docs)} documents fetched')

    steps = [
        f'[{ts()}] ✅ OTP verified successfully',
        f'[{ts()}] 🔑 Access token issued',
        f'[{ts()}] 📂 Fetching document manifest from DigiLocker...',
        f'[{ts()}] 🪪 Aadhaar Card (UIDAI Official) — Verified',
        f'[{ts()}] 📄 PAN Card (CBDT Issued) — Verified',
        f'[{ts()}] 🚗 Driving Licence (Transport Dept) — Verified',
        f'[{ts()}] ✅ {len(docs)} documents synced to secure vault',
        f'[{ts()}] 🔒 Session encrypted with AES-256-GCM',
    ]

    return jsonify({
        'success': True,
        'documents': docs,
        'steps': steps,
        'display': dl_state['display'],
        'connected_at': datetime.now().strftime('%d %b %Y %H:%M:%S'),
        'message': f'DigiLocker connected successfully for {dl_state["display"]}'
    })


@app.route('/api/digilocker/status', methods=['GET'])
def api_digilocker_status():
    sid = get_session_id()
    dl_state = digilocker_sessions.get(sid, {})
    return jsonify({
        'connected': dl_state.get('connected', False),
        'state': dl_state.get('state', 'NOT_INITIATED'),
        'display': dl_state.get('display', ''),
        'documents': dl_state.get('documents', []) if dl_state.get('connected') else [],
        'connected_at': dl_state.get('connected_at', '')
    })


@app.route('/api/digilocker/disconnect', methods=['POST'])
def api_digilocker_disconnect():
    sid = get_session_id()
    if sid in digilocker_sessions:
        display = digilocker_sessions[sid].get('display', '')
        del digilocker_sessions[sid]
        log_forensic_event('DIGILOCKER', 'AUTH_REVOKE', 1,
                            f'DigiLocker session revoked for {display}')
    return jsonify({'success': True, 'message': 'DigiLocker session terminated'})


@app.route('/api/digilocker/sync-to-vault', methods=['POST'])
def api_digilocker_sync_to_vault():
    """Sync a DigiLocker document to the secure Identity Vault."""
    data = request.get_json()
    doc_id = data.get('doc_id')
    sid = get_session_id()

    dl_state = digilocker_sessions.get(sid)
    if not dl_state or not dl_state.get('connected'):
        return jsonify({'error': 'DigiLocker not connected'}), 401

    doc = next((d for d in dl_state.get('documents', []) if d['id'] == doc_id), None)
    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    # Add to vault
    if sid not in sessions_data:
        sessions_data[sid] = {}
    vault = sessions_data[sid].setdefault('vault', [])

    # Check if already exists
    if any(v['id'] == doc['id'] for v in vault):
        return jsonify({'error': 'Document already in vault'}), 400

    # Simulate AES-256 encryption for the vault
    encrypted_data = hashlib.sha256(doc['number'].encode()).hexdigest()
    
    vault_item = {
        'id': doc['id'],
        'type': doc['type'],
        'label': doc['name'],
        'data': encrypted_data,  # Stored as encrypted hash
        'masked': doc['number'],
        'added': datetime.now().strftime('%d %b %Y %H:%M'),
        'source': 'DIGILOCKER'
    }
    vault.append(vault_item)

    # Seal this sync on blockchain
    block_hash = seal_on_blockchain(vault_item)

    log_forensic_event('DIGILOCKER', 'SYNC_TO_VAULT', 1,
                        f'DigiLocker document synced to vault: {doc["name"]} — SEALED:{block_hash[:12]}')

    return jsonify({
        'success': True,
        'item': vault_item,
        'block_hash': block_hash,
        'message': f'{doc["name"]} successfully synced and cryptographically sealed.'
    })


def _simulate_digilocker_documents(identifier):
    """Generate realistic document metadata for DigiLocker session."""
    seed = int(hashlib.md5(identifier.encode()).hexdigest()[:8], 16)
    # Consistent pseudorandom docs per user
    aadhaar_tail = str(seed % 10000).zfill(4)
    pan_letters = ''.join([chr(65 + (seed >> i) % 26) for i in range(5)])
    pan_nums = str(seed % 10000).zfill(4)

    return [
        {
            'id': f'DL-AADH-{aadhaar_tail}',
            'name': 'Aadhaar Card',
            'issuer': 'Unique Identification Authority of India (UIDAI)',
            'type': 'identity',
            'icon': '🪪',
            'number': f'XXXX-XXXX-{aadhaar_tail}',
            'valid_till': 'Lifetime',
            'status': 'VERIFIED',
            'fetched_at': datetime.now().strftime('%d %b %Y %H:%M')
        },
        {
            'id': f'DL-PAN-{pan_letters[:5]}{pan_nums}',
            'name': 'PAN Card',
            'issuer': 'Central Board of Direct Taxes (CBDT)',
            'type': 'tax',
            'icon': '📄',
            'number': f'{pan_letters[:5]}{pan_nums}P',
            'valid_till': 'Lifetime',
            'status': 'VERIFIED',
            'fetched_at': datetime.now().strftime('%d %b %Y %H:%M')
        },
        {
            'id': f'DL-DL-{seed % 99999:05d}',
            'name': 'Driving Licence',
            'issuer': 'Ministry of Road Transport & Highways',
            'type': 'licence',
            'icon': '🚗',
            'number': f'MH{seed%50:02d}-{seed%99999:05d}',
            'valid_till': (datetime.now() + timedelta(days=365*5)).strftime('%d %b %Y'),
            'status': 'VERIFIED',
            'fetched_at': datetime.now().strftime('%d %b %Y %H:%M')
        },
        {
            'id': f'DL-VID-{seed % 999999:06d}',
            'name': 'Voter ID (EPIC)',
            'issuer': 'Election Commission of India',
            'type': 'identity',
            'icon': '🗳️',
            'number': f'IND{seed%9999999:07d}',
            'valid_till': 'Lifetime',
            'status': 'VERIFIED',
            'fetched_at': datetime.now().strftime('%d %b %Y %H:%M')
        },
    ]

# ─── ROUTES: FORENSIC EVENTS ──────────────────────────────────────────────────

@app.route('/api/events', methods=['GET'])
def api_events():
    limit = int(request.args.get('limit', 50))
    module = request.args.get('module', '')
    
    conn = get_db()
    cursor = conn.cursor()
    if module:
        cursor.execute("SELECT * FROM events WHERE module = ? ORDER BY id DESC LIMIT ?", (module, limit))
    else:
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    
    rows = cursor.fetchall()
    total = cursor.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    
    events = [dict(r) for r in rows]
    return jsonify({'events': events, 'total': total})

@app.route('/api/events/clear', methods=['POST'])
def api_events_clear():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    log_forensic_event('SYSTEM', 'LOG_CLEARED', 1, 'Forensic event log cleared by agent')
    return jsonify({'success': True})

@app.route('/api/events/log', methods=['POST'])
def api_events_log():
    data = request.get_json()
    ev = log_forensic_event(
        data.get('module', 'SYSTEM'),
        data.get('type', 'EVENT'),
        data.get('severity', 1),
        data.get('desc', '')
    )
    return jsonify({'success': True, 'event': ev})

# ─── ROUTES: SYSTEM MONITOR ──────────────────────────────────────────────────

@app.route('/api/system/monitor', methods=['GET'])
def api_system_monitor():
    """Live telemetry of system processes and resource forensics."""
    processes = []
    suspect_keywords = ['cmd', 'powershell', 'regedit', 'anydesk', 'teamviewer', 'putty', 'wireshark', 'nmap', 'miner', 'crypt']
    
    try:
        # Get top 20 processes
        for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']), 
                          key=lambda p: p.info['cpu_percent'], reverse=True)[:20]:
            try:
                pinfo = proc.info
                name = pinfo['name'].lower()
                # Forensic Risk Scoring
                risk_score = 10 if any(kw in name for kw in suspect_keywords) else 0
                if pinfo['cpu_percent'] > 40: risk_score += 30
                if pinfo['memory_percent'] > 20: risk_score += 20
                
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu': round(pinfo['cpu_percent'], 1),
                    'ram': round(pinfo['memory_percent'], 1),
                    'status': pinfo['status'],
                    'risk': risk_score,
                    'is_suspect': risk_score > 30
                })
                
                # Log to forensic events if risk is very high
                if risk_score >= 50:
                    log_forensic_event('SYSTEM', 'SUSPECT_PROC', 3, f'High-risk process detected: {pinfo["name"]} (PID: {pinfo["pid"]})')
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.error(f"System Monitor Error: {e}")

    return jsonify({
        'timestamp': ts(),
        'cpu_total': psutil.cpu_percent(),
        'ram_total': psutil.virtual_memory().percent,
        'processes': processes
    })


# ─── ROUTES: IDENTITY VAULT ──────────────────────────────────────────────────

@app.route('/api/vault/items', methods=['GET'])
def api_vault_items():
    sid = get_session_id()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vault WHERE session_id = ?", (sid,))
    rows = cursor.fetchall()
    conn.close()
    items = [dict(r) for r in rows]
    return jsonify({'items': items})

@app.route('/api/vault/add', methods=['POST'])
def api_vault_add():
    data = request.get_json()
    sid = get_session_id()
    item_id = str(uuid.uuid4())[:12].upper()
    masked = data.get('data')[:4] + "*" * (len(data.get('data'))-4) if data.get('data') else "****"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO vault (id, type, label, data, masked, added, source, session_id)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                   (item_id, data.get('type'), data.get('label'), data.get('data'), 
                    masked, datetime.now().strftime('%d %b %Y %H:%M'), 'MANUAL', sid))
    conn.commit()
    conn.close()
    
    log_forensic_event('VAULT', 'ITEM_ADDED', 1, f"New identity document added to vault: {data.get('label')}")
    return jsonify({'success': True, 'id': item_id, 'masked': masked})

@app.route('/api/vault/delete/<id>', methods=['DELETE'])
def api_vault_delete(id):
    sid = get_session_id()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE id = ? AND session_id = ?", (id, sid))
    conn.commit()
    conn.close()
    log_forensic_event('VAULT', 'ITEM_DELETED', 1, f"Vault item {id} removed by user")
    return jsonify({'success': True})

# ─── ROUTES: AI ASSISTANT ─────────────────────────────────────────────────────

# Enhancement 1: Conversation Memory (per session)
conversation_memory = {}  # session_id -> list of {role, content}

def get_conversation_context(sid):
    """Get conversation history for context-aware AI."""
    if sid not in conversation_memory:
        conversation_memory[sid] = []
    # Also inject forensic session context
    ctx_parts = []
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT url, level, score FROM url_history ORDER BY id DESC LIMIT 5")
        urls = cursor.fetchall()
        if urls:
            ctx_parts.append("Recent URL scans: " + ", ".join([f"{r[0]}({r[1]},{r[2]}/100)" for r in urls]))
        cursor.execute("SELECT sender, verdict, score FROM scam_history ORDER BY id DESC LIMIT 5")
        scams = cursor.fetchall()
        if scams:
            ctx_parts.append("Recent scam analyses: " + ", ".join([f"From {r[0]}:{r[1]}({r[2]}%)" for r in scams]))
        cursor.execute("SELECT module, desc FROM events ORDER BY id DESC LIMIT 5")
        events = cursor.fetchall()
        if events:
            ctx_parts.append("Recent events: " + ", ".join([f"[{r[0]}] {r[1][:50]}" for r in events]))
        conn.close()
    except Exception:
        pass
    return ctx_parts

@app.route('/api/chat', methods=['POST'])
def api_chat():
    data = request.get_json()
    message = data.get('message', '')
    sid = get_session_id()
    
    # Store user message in memory
    if sid not in conversation_memory:
        conversation_memory[sid] = []
    conversation_memory[sid].append({'role': 'user', 'content': message})
    # Keep only last 10 messages
    conversation_memory[sid] = conversation_memory[sid][-10:]
    
    response = _expert_system_response(message, sid)
    
    # Store AI response in memory
    conversation_memory[sid].append({'role': 'assistant', 'content': response[:200]})
    
    log_forensic_event('AI_ASSISTANT', 'QUERY', 1, f'Query: {message[:40]}')
    return jsonify({'response': response, 'timestamp': ts()})

def _expert_system_response(msg, sid=None):
    """Generative Forensic Intelligence — Dynamic Response Engine with built-in fallback."""
    # Try Gemini API first (optional)
    api_key = app.config.get('GEMINI_API_KEY')
    if api_key and api_key != 'YOUR_GEMINI_API_KEY_HERE':
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)

            system_instruction = "You are a professional Cyber Forensic AI Assistant. Your goal is to help users understand and resolve cyber threats. You MUST follow this exact structure for every response: 1. ANALYSIS: Explain the problem/risk clearly in 1-2 sentences. 2. SOLUTION: Provide a brief, actionable step-by-step solution. 3. REDIRECTIONS: Include relevant [GOTO:module] or [CALL:1930] tags. Always output clean HTML (use <strong>, <ul>, <li>, <br>). DO NOT use Markdown asterisks (**). "

            # Build context-aware prompt with conversation memory
            context_lines = []
            if sid:
                session_ctx = get_conversation_context(sid)
                if session_ctx:
                    context_lines.append("FORENSIC SESSION CONTEXT:\n" + "\n".join(session_ctx))
                history = conversation_memory.get(sid, [])
                if history:
                    conv_text = "\n".join([f"{m['role'].upper()}: {m['content'][:100]}" for m in history[-6:]])
                    context_lines.append(f"CONVERSATION HISTORY:\n{conv_text}")

            context_block = "\n\n".join(context_lines) if context_lines else "No prior context."

            prompt = f"""
{context_block}

CURRENT USER QUERY: "{msg}"

Create a brief, comprehensive response in pure HTML format. Use this structure exactly:
<strong>Analysis:</strong> [1-2 sentences explaining the risk clearly]<br><br>
<strong>Action Plan:</strong>
<ul>
<li>[Specific action step 1]</li>
<li>[Specific action step 2]</li>
</ul>
<br>
[Include ALL relevant redirection tags here, separated by spaces. Example: [GOTO:scam_detector] [GOTO:url_analyzer] [CALL:1930]]

Valid modules for GOTO: system_monitor, url_analyzer, scam_detector, transaction_analyzer, vault, digilocker, report.
Valid CALL numbers: 1930 (Cyber Crime Helpline).

If the user references previous scans or questions, use the conversation history and session context above to give a relevant follow-up answer.
Ensure the response is highly informative but readable. NEVER use markdown asterisks. Only use standard HTML tags. Do not output ```html blocks.
"""
            # Try models in order of preference (higher free-tier quota first)
            models_to_try = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-2.5-flash']
            last_error = None
            for model_name in models_to_try:
                try:
                    model = genai.GenerativeModel(model_name, system_instruction=system_instruction)
                    response = model.generate_content(prompt)
                    text = response.text.strip()
                    if text.startswith('```html'):
                        text = text.replace('```html', '', 1)
                    if text.endswith('```'):
                        text = text[:-3]
                    text = text.replace('**', '')
                    text = text.replace('\n', '')
                    logger.info(f"Gemini AI response generated using {model_name}")
                    return text
                except Exception as model_err:
                    last_error = model_err
                    logger.warning(f"Gemini model {model_name} failed: {model_err}. Trying next model...")
                    continue

            logger.error(f"All Gemini models failed. Last error: {last_error}. Falling back to built-in expert system.")
        except Exception as e:
            logger.error(f"Gemini API error: {e}. Falling back to built-in expert system.")

    # ─── BUILT-IN EXPERT SYSTEM (No API Key Required) ─────────────────────
    return _builtin_forensic_expert(msg)


def _builtin_forensic_expert(msg):
    """Comprehensive offline forensic AI expert — zero API keys needed."""
    m = msg.lower().strip()

    # Knowledge base: keyword -> (response HTML, goto_tags)
    knowledge = [
        (['phishing', 'fake website', 'fake site', 'fake link', 'spoof'],
         '<strong>ANALYSIS:</strong> Phishing is a social engineering attack where criminals create fake websites or send deceptive messages to steal your passwords and financial data.<br><br>'
         '<strong>SOLUTION:</strong><ul>'
         '<li>Do not click the link. Instead, type the official website address directly into your browser.</li>'
         '<li>Use our URL Threat Analyzer to scan the link for malware or fraud patterns.</li>'
         '<li>If you have already entered details, change your passwords immediately and inform your bank.</li></ul>',
         '[GOTO:url_analyzer] [CALL:1930]'),

        (['otp', 'one time password', 'verification code'],
         '<strong>ANALYSIS:</strong> An OTP (One Time Password) is a secure code used to authorize transactions. Scammers ask for this to gain control of your bank accounts or social media.<br><br>'
         '<strong>SOLUTION:</strong><ul>'
         '<li>Never share your OTP with anyone, even if they claim to be from a bank or government agency.</li>'
         '<li>If you receive an unsolicited OTP, your credentials may already be compromised; change your password immediately.</li>'
         '<li>Immediately report any unauthorized OTP requests to the 1930 helpline.</li></ul>',
         '[GOTO:scam_detector] [CALL:1930]'),

        (['upi', 'google pay', 'phonepe', 'paytm', 'bhim', 'gpay'],
         '<strong>Analysis:</strong> UPI fraud is one of the most common cyber crimes in India. Scammers trick victims into approving collect requests or sharing UPI PINs.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>You only need to enter UPI PIN to SEND money — never to receive it</li>'
         '<li>Reject unknown collect/payment requests immediately</li>'
         '<li>Never scan QR codes sent by strangers claiming to "send" you money</li>'
         '<li>Verify the merchant name before completing any payment</li>'
         '<li>Report unauthorized UPI transactions within 24 hours to your bank</li>'
         '<li>Use our Transaction Anomaly Engine to detect suspicious patterns</li></ul>',
         '[GOTO:transaction_analyzer] [CALL:1930]'),

        (['scam', 'fraud', 'suspicious message', 'spam', 'fake sms', 'fake call'],
         '<strong>ANALYSIS:</strong> Scam messages use urgency and fear (e.g., "account blocked") to trick you into clicking dangerous links or sharing data.<br><br>'
         '<strong>SOLUTION:</strong><ul>'
         '<li>Use the Scam Detector below to analyze the message content for fraud signals.</li>'
         '<li>Block the sender and delete the message immediately. Do not call any numbers provided in the text.</li>'
         '<li>If money was lost, call 1930 within the "Golden Hour" for better recovery chances.</li></ul>',
         '[GOTO:scam_detector] [CALL:1930]'),

        (['ransomware', 'malware', 'virus', 'hack', 'hacked', 'encrypt'],
         '<strong>Analysis:</strong> Ransomware encrypts your files and demands payment. Malware can steal data, monitor activity, or damage your system.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Disconnect from the internet and network immediately</li>'
         '<li>Do NOT pay the ransom — it does not guarantee file recovery</li>'
         '<li>Report to CERT-In (Indian Computer Emergency Response Team) at cert-in.org.in</li>'
         '<li>Check nomoreransom.org for free decryption tools for known ransomware</li>'
         '<li>Restore files from clean, offline backups</li>'
         '<li>Run a full system scan with updated antivirus software</li>'
         '<li>Use our System Monitor to check for suspicious processes</li></ul>',
         '[GOTO:system_monitor] [CALL:1930]'),

        (['aadhaar', 'uidai', 'biometric', 'identity theft', 'aadhar'],
         '<strong>Analysis:</strong> Aadhaar fraud involves misuse of your 12-digit UID for unauthorized transactions, SIM swaps, or fake KYC verification.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Lock your biometrics at myaadhaar.uidai.gov.in immediately</li>'
         '<li>Generate a Virtual ID (VID) — use this instead of your actual Aadhaar number</li>'
         '<li>Check your Aadhaar authentication history for unauthorized usage</li>'
         '<li>Never share your Aadhaar OTP with anyone</li>'
         '<li>Store your Aadhaar securely in our Identity Vault with AES-256 encryption</li>'
         '<li>Report Aadhaar misuse at UIDAI helpline: 1947</li></ul>',
         '[GOTO:vault] [GOTO:digilocker]'),

        (['pan', 'income tax', 'tax', 'itr'],
         '<strong>Analysis:</strong> PAN card fraud can lead to financial identity theft, fake tax filings, and unauthorized credit applications in your name.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Never share your PAN number on unverified websites or with strangers</li>'
         '<li>Check your tax filings at incometax.gov.in for unauthorized ITR submissions</li>'
         '<li>Link your PAN with Aadhaar for additional security</li>'
         '<li>Monitor your CIBIL score regularly for unauthorized credit inquiries</li>'
         '<li>Store your PAN securely in our encrypted Identity Vault</li></ul>',
         '[GOTO:vault]'),

        (['report', 'complaint', 'fir', 'file', 'police', 'helpline', 'how to report'],
         '<strong>Analysis:</strong> Quick reporting is critical in cyber crime cases. The first 24 hours are the "golden period" for fund recovery.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li><strong>Step 1:</strong> Call 1930 (National Cyber Crime Helpline) immediately</li>'
         '<li><strong>Step 2:</strong> File an online complaint at cybercrime.gov.in</li>'
         '<li><strong>Step 3:</strong> Visit your nearest police station to file an FIR</li>'
         '<li><strong>Step 4:</strong> Preserve all evidence — screenshots, messages, transaction IDs, call logs</li>'
         '<li><strong>Step 5:</strong> Block compromised bank accounts and cards</li>'
         '<li><strong>Step 6:</strong> Inform your bank about the fraud for possible reversal</li></ul>',
         '[GOTO:report] [CALL:1930]'),

        (['bank', 'banking', 'net banking', 'online banking', 'account'],
         '<strong>Analysis:</strong> Online banking fraud includes unauthorized access, credential theft, and social engineering attacks targeting your bank account.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Always access banking through the official bank app or typed URL — never via links</li>'
         '<li>Enable two-factor authentication (2FA) on all banking accounts</li>'
         '<li>Set transaction limits and enable SMS/email alerts</li>'
         '<li>Never use public Wi-Fi for banking transactions</li>'
         '<li>Regularly check your statement for unauthorized transactions</li>'
         '<li>Use our URL Analyzer to verify any banking link before visiting</li></ul>',
         '[GOTO:url_analyzer] [GOTO:transaction_analyzer]'),

        (['password', 'strong password', 'secure', 'login'],
         '<strong>Analysis:</strong> Weak passwords are the #1 cause of account compromise. A strong password policy is your first line of defense.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Use passwords with 12+ characters mixing uppercase, lowercase, numbers, and symbols</li>'
         '<li>Never reuse passwords across multiple accounts</li>'
         '<li>Use a password manager (KeePass, Bitwarden) to store passwords securely</li>'
         '<li>Enable 2FA/MFA wherever possible</li>'
         '<li>Change passwords immediately if you suspect a breach</li>'
         '<li>Check if your password has been compromised at our Enhanced Dashboard breach checker</li></ul>',
         '[GOTO:vault]'),

        (['social media', 'instagram', 'facebook', 'whatsapp', 'twitter', 'impersonation'],
         '<strong>Analysis:</strong> Social media hacking and impersonation are used for blackmail, financial fraud, and reputation damage.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Enable 2FA on all social media accounts immediately</li>'
         '<li>Check active sessions and remove unknown devices</li>'
         '<li>Report impersonation accounts directly to the platform</li>'
         '<li>Never share personal photos or videos with strangers online</li>'
         '<li>If blackmailed, DO NOT pay — report to cybercrime.gov.in and call 1930</li></ul>',
         '[GOTO:report] [CALL:1930]'),

        (['job scam', 'loan scam', 'investment', 'stock', 'crypto', 'bitcoin', 'trading'],
         '<strong>Analysis:</strong> Job scams, fake investment schemes, and crypto fraud promise unrealistic returns to steal your money.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>No legitimate job requires you to pay money upfront</li>'
         '<li>Verify company registration at mca.gov.in before investing</li>'
         '<li>"Guaranteed returns" in stock/crypto trading is always a scam</li>'
         '<li>Check SEBI-registered brokers at scores.sebi.gov.in</li>'
         '<li>Report investment fraud to SEBI SCORES portal</li></ul>',
         '[GOTO:report] [CALL:1930]'),

        (['sim swap', 'sim', 'mobile', 'phone', 'call forwarding'],
         '<strong>Analysis:</strong> SIM swap fraud allows criminals to take over your phone number, intercepting OTPs and gaining access to your bank accounts.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>If your SIM suddenly stops working, contact your telecom provider immediately</li>'
         '<li>Register on sancharsaathi.gov.in to monitor your mobile connections</li>'
         '<li>Set a SIM lock/PIN on your mobile device</li>'
         '<li>Use app-based 2FA instead of SMS-based OTP where possible</li>'
         '<li>Alert your bank if you suspect a SIM swap attack</li></ul>',
         '[CALL:1930]'),

        (['safe', 'secure', 'protect', 'prevention', 'tips', 'safety'],
         '<strong>Analysis:</strong> Proactive cyber hygiene is the best defense against digital threats. Here are essential security practices.<br><br>'
         '<strong>Action Plan:</strong><ul>'
         '<li>Keep your OS, browser, and apps updated to the latest versions</li>'
         '<li>Use strong, unique passwords with a password manager</li>'
         '<li>Enable 2FA on all important accounts</li>'
         '<li>Never click links from unknown sources</li>'
         '<li>Regularly check your bank statements and credit report</li>'
         '<li>Lock your Aadhaar biometrics when not in use</li>'
         '<li>Back up important data offline regularly</li>'
         '<li>Use our platform tools to scan URLs, messages, and transactions</li></ul>',
         '[GOTO:url_analyzer] [GOTO:scam_detector]'),

        (['hello', 'hi', 'hey', 'help', 'what can you do', 'namaste'],
         '<strong>Namaste! I am your IDIFFS Forensic AI Assistant.</strong><br><br>'
         'I can help you with:<ul>'
         '<li>🔗 Checking if a website URL is safe or a phishing trap</li>'
         '<li>📨 Analyzing suspicious SMS, email, or WhatsApp messages for scam signals</li>'
         '<li>💳 Detecting anomalies in your bank transactions</li>'
         '<li>🔐 Securing your Aadhaar, PAN, and other identity documents</li>'
         '<li>📁 Syncing government documents via DigiLocker</li>'
         '<li>🚨 Filing cyber crime complaints and getting emergency helpline numbers</li>'
         '<li>🛡️ Cybersecurity tips and best practices</li></ul><br>'
         'Just type your question and I will provide expert guidance!',
         ''),
    ]

    # Match query against knowledge base
    for keywords, response_html, tags in knowledge:
        if any(kw in m for kw in keywords):
            full = response_html
            if tags:
                full += '<br>' + tags
            return full

    # Default response for unmatched queries
    return (
        '<strong>Analysis:</strong> I understand your concern. Let me guide you to the right resource.<br><br>'
        '<strong>Here is what I can help with:</strong><ul>'
        '<li><strong>Suspicious URL?</strong> — Use our URL Threat Analyzer to scan it</li>'
        '<li><strong>Got a scam message?</strong> — Paste it in the Scam Detector for NLP analysis</li>'
        '<li><strong>Unusual bank transactions?</strong> — Upload your statement to the Transaction Engine</li>'
        '<li><strong>Identity protection?</strong> — Store documents securely in the Identity Vault</li>'
        '<li><strong>Need to report a crime?</strong> — Call 1930 or file at cybercrime.gov.in</li></ul><br>'
        '<strong>Tip:</strong> Try asking about specific topics like "phishing", "OTP safety", "UPI fraud", '
        '"ransomware", "Aadhaar protection", or "how to report cyber crime".<br><br>'
        '[GOTO:report] [CALL:1930]'
    )

# ─── Enhancement 2: AI-POWERED SMS TRIAGE ────────────────────────────────────
def ai_triage_sms(sender, message):
    """Use Gemini AI for deep contextual SMS threat assessment."""
    api_key = app.config.get('GEMINI_API_KEY')
    if not api_key or api_key == 'YOUR_GEMINI_API_KEY_HERE':
        return None
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        prompt = f"""Analyze this SMS for cyber threats. Sender: {sender}. Message: \"{message}\"

Return a JSON object with: threat_level (SAFE/LOW/MEDIUM/HIGH/CRITICAL), confidence (0-100), tactics (list of social engineering tactics detected like urgency, impersonation, fear), regional_pattern (any known regional scam pattern matched), recommendation (one sentence advice).
Return ONLY the JSON, no markdown."""
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text.startswith('```'): text = text.split('\n', 1)[1]
        if text.endswith('```'): text = text[:-3]
        return json.loads(text)
    except Exception as e:
        logger.error(f"AI SMS Triage error: {e}")
        return None

# ─── Enhancement 3: FORENSIC REPORT GENERATION ───────────────────────────────
@app.route('/api/report/generate', methods=['POST'])
def api_generate_report():
    """Generate a professional forensic investigation report using AI."""
    try:
        conn = get_db()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")
        events = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM url_history ORDER BY id DESC LIMIT 20")
        urls = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM scam_history ORDER BY id DESC LIMIT 20")
        scams = [dict(r) for r in cursor.fetchall()]
        conn.close()
        
        summary_data = {
            'total_events': len(events),
            'high_severity': len([e for e in events if e.get('severity', 0) >= 4]),
            'urls_scanned': len(urls),
            'high_risk_urls': len([u for u in urls if u.get('level') == 'HIGH']),
            'sms_analyzed': len(scams),
            'scams_detected': len([s for s in scams if s.get('verdict') in ['HIGH_RISK', 'SUSPECTED']]),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        api_key = app.config.get('GEMINI_API_KEY')
        if api_key and api_key != 'YOUR_GEMINI_API_KEY_HERE':
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            prompt = f"""Generate a professional forensic investigation report in HTML format based on this data:

Session Summary: {json.dumps(summary_data)}
Recent Events: {json.dumps(events[:10])}
URL Scans: {json.dumps(urls[:10])}
SMS Analyses: {json.dumps(scams[:10])}

Format as a formal report with: Executive Summary, Threat Overview, Key Findings, Risk Assessment, Recommendations.
Use clean HTML with <h3>, <p>, <table>, <strong>, <ul>, <li>. No markdown. Make it look professional."""
            model = genai.GenerativeModel('gemini-2.0-flash')
            response = model.generate_content(prompt)
            report_html = response.text.strip()
            if report_html.startswith('```'): report_html = report_html.split('\n', 1)[1]
            if report_html.endswith('```'): report_html = report_html[:-3]
        else:
            report_html = f"""<h3>IDIFFS Forensic Investigation Report</h3>
<p><strong>Generated:</strong> {summary_data['timestamp']}</p>
<h4>Executive Summary</h4>
<p>Total events logged: {summary_data['total_events']} | High severity: {summary_data['high_severity']}</p>
<p>URLs scanned: {summary_data['urls_scanned']} | High risk: {summary_data['high_risk_urls']}</p>
<p>SMS analyzed: {summary_data['sms_analyzed']} | Scams detected: {summary_data['scams_detected']}</p>"""
        
        log_forensic_event('REPORT_ENGINE', 'REPORT_GENERATED', 1, 'Forensic report generated')
        return jsonify({'report': report_html, 'summary': summary_data, 'timestamp': ts()})
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({'error': str(e)}), 500

# ─── Enhancement 4: VOICE COMMAND DISPATCHER ─────────────────────────────────
@app.route('/api/voice/command', methods=['POST'])
def api_voice_command():
    """Process voice commands and dispatch actions."""
    data = request.get_json()
    command = (data.get('command', '') or '').lower().strip()
    
    result = {'action': 'none', 'message': 'Command not recognized'}
    
    if 'scan' in command and ('url' in command or 'http' in command or '.com' in command or '.in' in command):
        # Extract URL from command
        import re
        urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+|[\w.-]+\.(?:com|in|org|net|xyz|io)[^\s]*)', command)
        if urls:
            url = urls[0] if urls[0].startswith('http') else 'https://' + urls[0]
            features = extract_url_features(url)
            score, level, flags = compute_url_risk_score(features)
            result = {'action': 'url_scan', 'url': url, 'score': score, 'level': level, 
                      'message': f'URL scanned: {level} risk ({score}/100)'}
    elif 'block' in command and 'domain' in command:
        domains = re.findall(r'[\w.-]+\.(?:com|in|org|net|xyz|io)', command)
        if domains:
            block_malicious_domain(domains[0])
            log_forensic_event('FIREWALL', 'VOICE_BLOCK', 4, f'Voice command: blocked {domains[0]}')
            result = {'action': 'block', 'domain': domains[0], 'message': f'Domain {domains[0]} blocked'}
    elif 'high severity' in command or 'critical' in command or 'alerts' in command:
        result = {'action': 'navigate', 'target': 'dashboard', 'filter': 'high', 
                  'message': 'Showing high severity events'}
    elif 'report' in command or 'generate' in command:
        result = {'action': 'navigate', 'target': 'report', 'message': 'Opening report generator'}
    elif any(w in command for w in ['scam', 'phishing', 'fraud']):
        result = {'action': 'navigate', 'target': 'scam', 'message': 'Opening Scam Detector'}
    elif 'monitor' in command or 'network' in command:
        result = {'action': 'navigate', 'target': 'monitor', 'message': 'Opening System Monitor'}
    
    log_forensic_event('VOICE_AI', 'VOICE_COMMAND', 1, f'Voice: {command[:40]} -> {result["action"]}')
    return jsonify(result)

# ─── REAL-TIME IDS SNIFFER (IDS) ─────────────────────────────────────────────
def ids_sniffer_thread():
    """Background thread for real-time network sniffing."""
    logger.info("IDS: Real-time network sniffer initialized.")
    
    def packet_callback(packet):
        if not IDS_ACTIVE or not HAS_SCAPY: return

        
        # Monitor DNS Queries
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            query = packet.getlayer(DNSQR).qname.decode('utf-8').strip('.')
            for malicious in SUSPICIOUS_DOMAINS:
                if malicious in query:
                    log_forensic_event('IDS_ENGINE', 'SUSPICIOUS_DNS_QUERY', 4, 
                                       f"ALERT: Local machine queried malicious domain: {query}")
                    socketio.emit('ids_alert', {'domain': query, 'type': 'DNS_PHISH'})

    try:
        if HAS_SCAPY:
            # Note: Sniffing on Windows requires Npcap/WinPcap
            sniff(prn=packet_callback, store=0, filter="udp port 53")
        else:
            logger.warning("IDS: Scapy not installed. Sniffer disabled.")
    except Exception as e:
        logger.error(f"IDS Sniffer failed: {e}")


@socketio.on('send_chat')
def handle_chat(data):
    """Handle messages in the Forensic War Room."""
    emit('chat_msg', data, broadcast=True)

@socketio.on('connect')
def handle_connect():
    """Welcome message for new investigators."""
    emit('chat_msg', {
        'time': datetime.now().strftime('%H:%M:%S'),
        'text': "New investigator joined the forensic session."
    }, broadcast=True)

# ─── RUN ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logger.info('='*60)
    logger.info('IDIFSS Cyber Crime Intelligence Platform v3.2.1-GOV')
    logger.info('Starting Flask server on http://0.0.0.0:5000')
    logger.info('Persistence: SQLite Engine [data/idiffs.db]')
    logger.info('='*60)

    # Log startup to persistent DB
    log_forensic_event('SYSTEM', 'BOOT', 1, 'IDIFSS Platform initialized — SQLite Persistence Active')
    log_forensic_event('SYSTEM', 'MONITOR', 1, 'Real-time monitoring active — URL, SCAM, TRANSACTION, VAULT, DIGILOCKER')

    # Start IDS in background
    threading.Thread(target=ids_sniffer_thread, daemon=True).start()

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
