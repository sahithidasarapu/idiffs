import os

# Manual .env loader (no external dependency needed)
def _load_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value

_load_env_file()
class Config:
    # ─── GMAIL SMTP CONFIGURATION ───────────────────────────────────────────
    # To use this, you MUST:
    # 1. Have a Google Account
    # 2. Enable 2-Step Verification
    # 3. Create an "App Password" (https://myaccount.google.com/apppasswords)
    
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    
    # ENTER YOUR CREDENTIALS HERE:
    MAIL_USERNAME = 'your-email@gmail.com'
    MAIL_PASSWORD = 'your-app-password-here'  # 16-character code
    MAIL_DEFAULT_SENDER = ('IDIFFS Secure', 'your-email@gmail.com')



    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'IDIFFS-CYBER-FORENSICS-2024-GOV-SECURE'

    # ─── GOOGLE GEMINI AI CONFIGURATION ──────────────────────────────────────
    # To use this, you MUST:
    # 1. Get an API key from Google AI Studio (https://aistudio.google.com/app/apikey)
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY') or 'YOUR_GEMINI_API_KEY_HERE'


    # ─── DIGILOCKER PRODUCTION API (MeitY / GOI) ────────────────
    # Register at https://partners.digitallocker.gov.in/
    DL_CLIENT_ID = os.environ.get('DIGILOCKER_CLIENT_ID') or 'YOUR_CLIENT_ID'
    DL_CLIENT_SECRET = os.environ.get('DIGILOCKER_CLIENT_SECRET') or 'YOUR_CLIENT_SECRET'
    DL_REDIRECT_URI = os.environ.get('DIGILOCKER_REDIRECT_URI') or 'http://localhost:5000/api/digilocker/callback'
    
    DL_AUTH_URL = "https://api.digitallocker.gov.in/public/oauth2/1/authorize"
    DL_TOKEN_URL = "https://api.digitallocker.gov.in/public/oauth2/1/token"
    DL_FILES_URL = "https://api.digitallocker.gov.in/public/oauth2/1/files/issued"
    DL_DOC_URL = "https://api.digitallocker.gov.in/public/oauth2/1/file/"
