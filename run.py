#!/usr/bin/env python3
"""
IDIFFS Launcher — Run this file to start the platform
"""
import eventlet
eventlet.monkey_patch()

import os, sys, webbrowser, threading, time

os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
os.makedirs('models', exist_ok=True)

# Check __init__
if not os.path.exists('models/__init__.py'):
    open('models/__init__.py', 'w').close()

print("""
+------------------------------------------------------------------+
|         IDIFFS - Cyber Crime Intelligence Platform               |
|         Integrated Digital Intelligence & Forensic System        |
|         Government of India - Cyber Crime Wing                   |
|         Version 3.2.1-GOV - Deep Learning Enabled                |
+------------------------------------------------------------------|
|  Modules: URL Analyzer - Scam Detector - Transaction Engine      |
|           Identity Vault - DigiLocker - AI Assistant - Voice     |
+------------------------------------------------------------------+
""")

print("Starting IDIFFS server on http://localhost:5000 ...")
print("Emergency Helpline: 1930 | Police: 100 | National Emergency: 112")
print("-" * 68)
print("Press CTRL+C to stop the server")
print()

def open_browser():
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')

t = threading.Thread(target=open_browser, daemon=True)
t.start()

from app import app, socketio
import eventlet.wsgi

print("[PRODUCTION] Socket.IO + Eventlet server handling connections...")
socketio.run(app, host='0.0.0.0', port=5000, debug=False)
