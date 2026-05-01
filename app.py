from flask import Flask, request, jsonify, send_from_directory, Response, make_response, redirect
from flask_cors import CORS
import sqlite3, hashlib, hmac as _hmac, jwt, json, datetime, smtplib
import urllib.request, urllib.parse, os, secrets, base64, time, csv, io, re, bcrypt
from email.mime.text import MIMEText
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from html.parser import HTMLParser
from collections import defaultdict

load_dotenv('/home/jackson/OR-Compliance/.env')
load_dotenv('/home/jackson/OR-Compliance/canopy/.env', override=False)

app = Flask(__name__, static_folder='static')
CORS(app, origins='*')

SECRET          = os.environ.get('ADMIN_SECRET', 'peekbot_secret_2026')
OPENAI_KEY      = os.environ.get('OPENAI_API_KEY', '')
SMTP_HOST       = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT       = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER       = os.environ.get('SMTP_USER', '')
SMTP_PASS       = os.environ.get('SMTP_PASS', '')
STRIPE_SECRET   = os.environ.get('STRIPE_SECRET', '')
STRIPE_WEBHOOK  = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PRO      = os.environ.get('STRIPE_PRO_PRICE', '')
STRIPE_SUPER    = os.environ.get('STRIPE_SUPER_PRO_PRICE', '')
ADMIN_EMAIL     = 'jackson@cana.chat'
BASE_URL        = 'https://peekbot.cana.chat'

QB_CLIENT_ID     = os.environ.get('QB_CLIENT_ID', '')
QB_CLIENT_SECRET = os.environ.get('QB_CLIENT_SECRET', '')
QB_REDIRECT_URI  = os.environ.get('QB_REDIRECT_URI', f'{BASE_URL}/api/quickbooks/callback')

DB        = '/home/jackson/peekbot.db'
UPLOAD_DIR = os.path.expanduser('~/Peekbot/uploads')
DOCS_DIR   = os.path.expanduser('~/Peekbot/documents')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)
ALLOWED_EXT = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg'}

FREE_MSG_LIMIT = 10  # per month

# ─── RATE LIMITING ───
_rate = defaultdict(list)

def rate_ok(key, limit=20):
    now = time.time()
    _rate[key] = [t for t in _rate[key] if now - t < 60]
    if len(_rate[key]) >= limit:
        return False
    _rate[key].append(now)
    return True

# ─── PASSWORD ───
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pw(pw, stored):
    try:
        if stored.startswith('$2b$') or stored.startswith('$2a$'):
            return bcrypt.checkpw(pw.encode(), stored.encode())
        # legacy sha256 fallback
        return secrets.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)
    except Exception:
        return False

# ─── DB ───
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            qb_realm_id TEXT,
            qb_access_token TEXT,
            qb_refresh_token TEXT,
            qb_token_expires_at TEXT,
            commission_currency TEXT DEFAULT 'USD',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            plan TEXT DEFAULT 'free',
            org_id INTEGER,
            role TEXT DEFAULT 'agent',
            stripe_customer_id TEXT,
            stripe_sub_id TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT 'Assistant',
            greeting TEXT DEFAULT 'Hi! How can I help you today?',
            system_prompt TEXT DEFAULT 'You are a helpful assistant.',
            color TEXT DEFAULT '#7c6af7',
            avatar TEXT DEFAULT '',
            lead_capture INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id INTEGER NOT NULL,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id INTEGER NOT NULL,
            name TEXT,
            email TEXT,
            phone TEXT,
            notes TEXT,
            status TEXT DEFAULT 'new',
            assigned_to INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            deal_name TEXT,
            property_address TEXT,
            buyer_name TEXT,
            buyer_email TEXT,
            seller_name TEXT,
            seller_email TEXT,
            purchase_price REAL,
            earnest_money REAL,
            closing_date TEXT,
            commission_amount REAL,
            deal_status TEXT DEFAULT 'lead',
            qb_invoice_id TEXT,
            contract_id TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS deal_commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            commission_amount REAL,
            commission_status TEXT DEFAULT 'pending',
            qb_bill_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id INTEGER NOT NULL,
            contract_type TEXT,
            pdf_path TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'agent',
            token TEXT UNIQUE NOT NULL,
            accepted INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS contract_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            file_path TEXT,
            file_type TEXT,
            category TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS knowledge_base (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            source TEXT,
            source_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS generated_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            doc_type TEXT,
            title TEXT,
            data_json TEXT,
            file_path TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS data_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id INTEGER NOT NULL,
            source_type TEXT,
            name TEXT,
            url TEXT,
            instagram_handle TEXT,
            api_key TEXT,
            sync_status TEXT DEFAULT 'pending',
            item_count INTEGER DEFAULT 0,
            last_synced TEXT,
            last_error TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    # Add columns that may be missing from older schema versions
    for table, col, typedef in [
        ('leads',        'status',      'TEXT DEFAULT "new"'),
        ('knowledge_base','source_id',  'INTEGER'),
        ('data_sources', 'item_count',  'INTEGER DEFAULT 0'),
        ('data_sources', 'last_error',  'TEXT'),
        ('users',        'stripe_customer_id', 'TEXT'),
        ('users',        'stripe_sub_id',      'TEXT'),
        ('deals',        'notes',       'TEXT'),
        ('deals',        'deal_status', 'TEXT DEFAULT "lead"'),
    ]:
        try:
            db.execute(f'ALTER TABLE {table} ADD COLUMN {col} {typedef}')
            db.commit()
        except Exception:
            pass
    db.commit()
    db.close()

init_db()

# ─── HELPERS ───
def make_token(user_id, email):
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    return jwt.encode({'user_id': user_id, 'email': email, 'exp': exp}, SECRET, algorithm='HS256')

def verify_token(req):
    auth = req.headers.get('Authorization', '')
    if not auth.startswith('Bearer '): return None
    try:
        data = jwt.decode(auth[7:], SECRET, algorithms=['HS256'])
        return data['user_id']
    except Exception:
        return None

def get_user(uid, db):
    return db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()

def get_org_bot(org_id, db):
    return db.execute('SELECT * FROM bots WHERE org_id=? ORDER BY id LIMIT 1', (org_id,)).fetchone()

def send_email(to, subject, body):
    if not SMTP_USER or not SMTP_PASS:
        return
    try:
        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = to
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, to, msg.as_string())
    except Exception as e:
        print(f'[email] {e}')

def openai_call(messages, max_tokens=500, model='gpt-4o-mini'):
    payload = json.dumps({
        'model': model,
        'messages': messages,
        'max_tokens': max_tokens
    }).encode()
    req = urllib.request.Request(
        'https://api.openai.com/v1/chat/completions',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {OPENAI_KEY}'
        }
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        result = json.loads(r.read())
        return result['choices'][0]['message']['content']

def monthly_msg_count(bot_id, db):
    start = datetime.datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    row = db.execute(
        "SELECT COUNT(*) FROM conversations WHERE bot_id=? AND role='user' AND created_at>=?",
        (bot_id, start)
    ).fetchone()
    return row[0]

# ─── WEB SCRAPER ───
class _Extractor(HTMLParser):
    SKIP = {'script','style','noscript','nav','footer','head','iframe','svg'}
    def __init__(self):
        super().__init__()
        self._depth = 0
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP: self._depth += 1
    def handle_endtag(self, tag):
        if tag in self.SKIP and self._depth > 0: self._depth -= 1
    def handle_data(self, data):
        if not self._depth:
            s = ' '.join(data.split())
            if len(s) > 20: self.parts.append(s)

def scrape_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 Peekbot/1.0'})
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read(500_000).decode('utf-8', errors='ignore')
        p = _Extractor()
        p.feed(raw)
        full = '\n'.join(p.parts)
        chunks = []
        for i in range(0, min(len(full), 15_000), 800):
            chunk = full[i:i+800].strip()
            if chunk:
                chunks.append(chunk)
        return chunks, None
    except Exception as e:
        return [], str(e)

# ─── STRIPE HELPERS ───
def stripe_post(path, params):
    data = urllib.parse.urlencode(params).encode()
    auth = base64.b64encode(f'{STRIPE_SECRET}:'.encode()).decode()
    req = urllib.request.Request(
        f'https://api.stripe.com/v1/{path}',
        data=data,
        headers={
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

def verify_stripe_sig(payload_bytes, sig_header):
    try:
        ts   = [p.split('=')[1] for p in sig_header.split(',') if p.startswith('t=')][0]
        sigs = [p.split('=',1)[1] for p in sig_header.split(',') if p.startswith('v1=')]
        signed = f'{ts}.'.encode() + payload_bytes
        expected = _hmac.new(STRIPE_WEBHOOK.encode(), signed, hashlib.sha256).hexdigest()
        return any(secrets.compare_digest(expected, s) for s in sigs)
    except Exception:
        return False

# ─── STATIC ROUTES ───
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/dashboard')
@app.route('/accept-invite')
def spa():
    return send_from_directory('static', 'index.html')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'ts': datetime.datetime.utcnow().isoformat()})

# ─── AUTH ───
@app.route('/api/register', methods=['POST'])
def register():
    d = request.json or {}
    email    = (d.get('email') or '').lower().strip()
    password = d.get('password', '')
    name     = d.get('name', '').strip()
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    db = get_db()
    try:
        db.execute('INSERT INTO users (email, password, name, plan) VALUES (?, ?, ?, ?)',
            (email, hash_pw(password), name, 'free'))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        db.execute('INSERT INTO organizations (owner_id, name) VALUES (?, ?)',
            (user['id'], (name or email.split('@')[0]) + ' Organization'))
        db.commit()
        org = db.execute('SELECT * FROM organizations WHERE owner_id=?', (user['id'],)).fetchone()
        db.execute('UPDATE users SET org_id=?, role=? WHERE id=?', (org['id'], 'owner', user['id']))
        bot_token = secrets.token_hex(16)
        db.execute('INSERT INTO bots (org_id, token, name) VALUES (?, ?, ?)',
            (org['id'], bot_token, (name or 'My') + "'s Bot"))
        db.commit()
        db.close()
        return jsonify({
            'token': make_token(user['id'], email),
            'email': email,
            'name': name,
            'plan': 'free',
            'role': 'owner'
        })
    except Exception:
        db.close()
        return jsonify({'error': 'Email already registered'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json or {}
    email = (d.get('email') or '').lower().strip()
    pw    = d.get('password', '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not user or not check_pw(pw, user['password']):
        db.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    # Upgrade legacy sha256 password to bcrypt on login
    if not (user['password'].startswith('$2b$') or user['password'].startswith('$2a$')):
        db.execute('UPDATE users SET password=? WHERE id=?', (hash_pw(pw), user['id']))
        db.commit()
    db.close()
    return jsonify({
        'token': make_token(user['id'], user['email']),
        'email': user['email'],
        'name':  user['name'] or '',
        'plan':  user['plan'] or 'free',
        'role':  user['role'] or 'agent',
        'org_id': user['org_id']
    })

@app.route('/api/me', methods=['GET'])
def me():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    if not user:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    org  = db.execute('SELECT * FROM organizations WHERE id=?', (user['org_id'],)).fetchone()
    bot  = get_org_bot(user['org_id'], db) if user['org_id'] else None
    db.close()
    return jsonify({
        'id':      user['id'],
        'email':   user['email'],
        'name':    user['name'] or '',
        'plan':    user['plan'] or 'free',
        'role':    user['role'] or 'agent',
        'org_id':  user['org_id'],
        'org_name': org['name'] if org else '',
        'bot_token': bot['token'] if bot else '',
    })

# ─── BOT ───
@app.route('/api/bot', methods=['GET'])
def get_bot():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    bot  = get_org_bot(user['org_id'], db)
    db.close()
    if not bot: return jsonify({'error': 'No bot found'}), 404
    return jsonify({**dict(bot), 'role': user['role']})

@app.route('/api/bot', methods=['PUT'])
def update_bot():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    db = get_db()
    user = get_user(uid, db)
    bot  = get_org_bot(user['org_id'], db)
    if not bot:
        tok = secrets.token_hex(16)
        db.execute('INSERT INTO bots (org_id, token, name, greeting, system_prompt, color, lead_capture) VALUES (?,?,?,?,?,?,?)',
            (user['org_id'], tok, d.get('name','My Bot'), d.get('greeting','Hi!'),
             d.get('system_prompt',''), d.get('color','#7c6af7'), d.get('lead_capture',1)))
    else:
        db.execute('UPDATE bots SET name=?, greeting=?, system_prompt=?, color=?, lead_capture=? WHERE org_id=?',
            (d.get('name'), d.get('greeting'), d.get('system_prompt'),
             d.get('color','#7c6af7'), d.get('lead_capture',1), user['org_id']))
    db.commit()
    bot = get_org_bot(user['org_id'], db)
    db.close()
    return jsonify(dict(bot))

@app.route('/api/bots', methods=['GET'])
def get_bots():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    bots = db.execute('SELECT * FROM bots WHERE org_id=? ORDER BY id', (user['org_id'],)).fetchall()
    db.close()
    return jsonify({'bots': [dict(b) for b in bots], 'role': user['role']})

# ─── DATA SOURCES ───
def _get_bot_for_user(uid, db):
    user = get_user(uid, db)
    return get_org_bot(user['org_id'], db), user

@app.route('/api/data-sources', methods=['GET'])
def get_data_sources():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot, _ = _get_bot_for_user(uid, db)
    if not bot:
        db.close()
        return jsonify([])
    sources = db.execute('SELECT * FROM data_sources WHERE bot_id=? ORDER BY created_at DESC', (bot['id'],)).fetchall()
    db.close()
    return jsonify([dict(s) for s in sources])

@app.route('/api/data-sources', methods=['POST'])
def add_data_source():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot, _ = _get_bot_for_user(uid, db)
    if not bot:
        db.close()
        return jsonify({'error': 'No bot found'}), 404
    d = request.json or {}
    if not d.get('source_type') or not d.get('name'):
        db.close()
        return jsonify({'error': 'source_type and name required'}), 400
    try:
        db.execute('''INSERT INTO data_sources (bot_id, source_type, name, url, instagram_handle, api_key, sync_status)
                      VALUES (?, ?, ?, ?, ?, ?, 'pending')''',
            (bot['id'], d['source_type'], d['name'], d.get('url'),
             d.get('instagram_handle'), d.get('api_key')))
        db.commit()
        sid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        src = db.execute('SELECT * FROM data_sources WHERE id=?', (sid,)).fetchone()
        db.close()
        return jsonify(dict(src)), 201
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 400

@app.route('/api/data-sources/<int:sid>', methods=['DELETE'])
def delete_data_source(sid):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot, user = _get_bot_for_user(uid, db)
    if not bot:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    src = db.execute('SELECT * FROM data_sources WHERE id=? AND bot_id=?', (sid, bot['id'])).fetchone()
    if not src:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    # Delete knowledge base entries from this source
    db.execute('DELETE FROM knowledge_base WHERE source_id=? AND org_id=?', (sid, user['org_id']))
    db.execute('DELETE FROM data_sources WHERE id=?', (sid,))
    db.commit()
    db.close()
    return jsonify({'success': True})

@app.route('/api/data-sources/<int:sid>/sync', methods=['POST'])
def sync_data_source(sid):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot, user = _get_bot_for_user(uid, db)
    if not bot:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    src = db.execute('SELECT * FROM data_sources WHERE id=? AND bot_id=?', (sid, bot['id'])).fetchone()
    if not src:
        db.close()
        return jsonify({'error': 'Not found'}), 404

    db.execute("UPDATE data_sources SET sync_status='syncing' WHERE id=?", (sid,))
    db.commit()

    chunks, err = [], None
    if src['source_type'] == 'website' and src['url']:
        chunks, err = scrape_url(src['url'])
    elif src['source_type'] == 'instagram':
        err = 'Instagram scraping requires authentication; use website URL instead.'
    elif src['source_type'] == 'mls':
        # Try fetching the API URL
        if src['url']:
            chunks, err = scrape_url(src['url'])
        else:
            err = 'No API URL configured'

    if chunks:
        db.execute('DELETE FROM knowledge_base WHERE source_id=? AND org_id=?', (sid, user['org_id']))
        for chunk in chunks:
            db.execute('INSERT INTO knowledge_base (org_id, content, source, source_id) VALUES (?,?,?,?)',
                (user['org_id'], chunk, src['name'], sid))
        db.execute('''UPDATE data_sources SET sync_status='synced', last_synced=CURRENT_TIMESTAMP,
                      item_count=?, last_error=NULL WHERE id=?''', (len(chunks), sid))
    elif err:
        db.execute("UPDATE data_sources SET sync_status='error', last_error=? WHERE id=?", (err[:500], sid))
    else:
        db.execute("UPDATE data_sources SET sync_status='synced', last_synced=CURRENT_TIMESTAMP, item_count=0 WHERE id=?", (sid,))

    db.commit()
    db.close()
    return jsonify({'success': True, 'chunks': len(chunks), 'error': err})

# ─── KNOWLEDGE BASE ───
@app.route('/api/knowledge', methods=['GET'])
def get_knowledge():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    kb = db.execute('SELECT * FROM knowledge_base WHERE org_id=? ORDER BY created_at DESC', (user['org_id'],)).fetchall()
    db.close()
    return jsonify([dict(k) for k in kb])

@app.route('/api/knowledge', methods=['POST'])
def add_knowledge():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    if not d.get('content'):
        return jsonify({'error': 'content required'}), 400
    db = get_db()
    user = get_user(uid, db)
    db.execute('INSERT INTO knowledge_base (org_id, content, source) VALUES (?, ?, ?)',
        (user['org_id'], d['content'][:2000], d.get('source', 'manual')))
    db.commit()
    kb = db.execute('SELECT * FROM knowledge_base WHERE org_id=? ORDER BY id DESC LIMIT 1', (user['org_id'],)).fetchone()
    db.close()
    return jsonify(dict(kb)), 201

@app.route('/api/knowledge/<int:kb_id>', methods=['DELETE'])
def delete_knowledge(kb_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    kb = db.execute('SELECT * FROM knowledge_base WHERE id=? AND org_id=?', (kb_id, user['org_id'])).fetchone()
    if not kb:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    db.execute('DELETE FROM knowledge_base WHERE id=?', (kb_id,))
    db.commit()
    db.close()
    return jsonify({'success': True})

# ─── LEADS ───
@app.route('/api/leads', methods=['GET'])
def get_leads():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    bots = db.execute('SELECT id FROM bots WHERE org_id=?', (user['org_id'],)).fetchall()
    if not bots:
        db.close()
        return jsonify([])
    ids = [b['id'] for b in bots]
    ph  = ','.join('?' * len(ids))
    leads = db.execute(f'SELECT * FROM leads WHERE bot_id IN ({ph}) ORDER BY created_at DESC', ids).fetchall()
    db.close()
    return jsonify([dict(l) for l in leads])

@app.route('/api/leads/<int:lead_id>', methods=['PATCH'])
def update_lead(lead_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    db = get_db()
    user = get_user(uid, db)
    bots = db.execute('SELECT id FROM bots WHERE org_id=?', (user['org_id'],)).fetchall()
    ids  = [b['id'] for b in bots]
    ph   = ','.join('?' * len(ids))
    lead = db.execute(f'SELECT * FROM leads WHERE id=? AND bot_id IN ({ph})', [lead_id]+ids).fetchone()
    if not lead:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    fields = {}
    for key in ('status', 'notes', 'assigned_to', 'name', 'email', 'phone'):
        if key in d:
            fields[key] = d[key]
    if fields:
        sets = ', '.join(f'{k}=?' for k in fields)
        db.execute(f'UPDATE leads SET {sets} WHERE id=?', list(fields.values()) + [lead_id])
        db.commit()
    lead = db.execute('SELECT * FROM leads WHERE id=?', (lead_id,)).fetchone()
    db.close()
    return jsonify(dict(lead))

@app.route('/api/leads/export', methods=['GET'])
def export_leads():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    bots = db.execute('SELECT id FROM bots WHERE org_id=?', (user['org_id'],)).fetchall()
    if not bots:
        db.close()
        return Response('', mimetype='text/csv')
    ids = [b['id'] for b in bots]
    ph  = ','.join('?' * len(ids))
    leads = db.execute(f'SELECT * FROM leads WHERE bot_id IN ({ph}) ORDER BY created_at DESC', ids).fetchall()
    db.close()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['id','name','email','phone','status','notes','created_at'])
    for l in leads:
        w.writerow([l['id'], l['name'], l['email'], l['phone'], l['status'], l['notes'], l['created_at']])
    resp = make_response(out.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=leads.csv'
    return resp

# ─── CONVERSATIONS ───
@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    bots = db.execute('SELECT id FROM bots WHERE org_id=?', (user['org_id'],)).fetchall()
    if not bots:
        db.close()
        return jsonify([])
    ids = [b['id'] for b in bots]
    ph  = ','.join('?' * len(ids))
    convos = db.execute(f'''SELECT session_id, MIN(created_at) as started, COUNT(*) as messages
                            FROM conversations WHERE bot_id IN ({ph})
                            GROUP BY session_id ORDER BY started DESC LIMIT 100''', ids).fetchall()
    db.close()
    return jsonify([dict(c) for c in convos])

@app.route('/api/conversations/<session_id>', methods=['GET'])
def get_conversation(session_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    msgs = db.execute('''SELECT c.* FROM conversations c
                         JOIN bots b ON c.bot_id=b.id
                         WHERE b.org_id=? AND c.session_id=? ORDER BY c.created_at''',
        (user['org_id'], session_id)).fetchall()
    db.close()
    return jsonify([dict(m) for m in msgs])

# ─── DEALS ───
@app.route('/api/deals', methods=['GET'])
def get_deals():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    deals = db.execute('SELECT * FROM deals WHERE org_id=? ORDER BY created_at DESC', (user['org_id'],)).fetchall()
    db.close()
    return jsonify([dict(d) for d in deals])

@app.route('/api/deals', methods=['POST'])
def create_deal():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    d = request.json or {}
    try:
        db.execute('''INSERT INTO deals (org_id, deal_name, property_address, buyer_name, buyer_email,
                                         seller_name, seller_email, purchase_price, earnest_money,
                                         closing_date, commission_amount, deal_status, notes)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (user['org_id'], d.get('deal_name'), d.get('property_address'),
             d.get('buyer_name'), d.get('buyer_email'), d.get('seller_name'), d.get('seller_email'),
             d.get('purchase_price'), d.get('earnest_money'), d.get('closing_date'),
             d.get('commission_amount'), d.get('deal_status', 'lead'), d.get('notes')))
        db.commit()
        deal = db.execute('SELECT * FROM deals WHERE org_id=? ORDER BY id DESC LIMIT 1', (user['org_id'],)).fetchone()
        db.close()
        return jsonify(dict(deal)), 201
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 400

@app.route('/api/deals/<int:deal_id>', methods=['PUT'])
def update_deal(deal_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    deal = db.execute('SELECT * FROM deals WHERE id=? AND org_id=?', (deal_id, user['org_id'])).fetchone()
    if not deal:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute('''UPDATE deals SET deal_name=?, property_address=?, buyer_name=?, buyer_email=?,
                  seller_name=?, seller_email=?, purchase_price=?, earnest_money=?,
                  closing_date=?, commission_amount=?, deal_status=?, notes=?, updated_at=CURRENT_TIMESTAMP
                  WHERE id=?''',
        (d.get('deal_name', deal['deal_name']), d.get('property_address', deal['property_address']),
         d.get('buyer_name', deal['buyer_name']), d.get('buyer_email', deal['buyer_email']),
         d.get('seller_name', deal['seller_name']), d.get('seller_email', deal['seller_email']),
         d.get('purchase_price', deal['purchase_price']), d.get('earnest_money', deal['earnest_money']),
         d.get('closing_date', deal['closing_date']), d.get('commission_amount', deal['commission_amount']),
         d.get('deal_status', deal['deal_status']), d.get('notes', deal['notes']), deal_id))
    db.commit()
    deal = db.execute('SELECT * FROM deals WHERE id=?', (deal_id,)).fetchone()
    db.close()
    return jsonify(dict(deal))

@app.route('/api/deals/<int:deal_id>', methods=['DELETE'])
def delete_deal(deal_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    deal = db.execute('SELECT * FROM deals WHERE id=? AND org_id=?', (deal_id, user['org_id'])).fetchone()
    if not deal:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    db.execute('DELETE FROM deals WHERE id=?', (deal_id,))
    db.commit()
    db.close()
    return jsonify({'success': True})

@app.route('/api/deals/<int:deal_id>/commission', methods=['POST'])
def add_commission(deal_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    deal = db.execute('SELECT * FROM deals WHERE id=? AND org_id=?', (deal_id, user['org_id'])).fetchone()
    if not deal:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute('INSERT INTO deal_commissions (deal_id, user_id, commission_amount) VALUES (?,?,?)',
        (deal_id, d.get('user_id'), d.get('commission_amount')))
    db.commit()
    comm = db.execute('SELECT * FROM deal_commissions WHERE deal_id=? ORDER BY id DESC LIMIT 1', (deal_id,)).fetchone()
    db.close()
    return jsonify(dict(comm)), 201

# ─── TEAM ───
@app.route('/api/team', methods=['GET'])
def get_team():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    team = db.execute('SELECT id, email, name, role, created_at FROM users WHERE org_id=?', (user['org_id'],)).fetchall()
    invites = db.execute("SELECT * FROM invitations WHERE org_id=? AND accepted=0", (user['org_id'],)).fetchall()
    db.close()
    return jsonify({'members': [dict(t) for t in team], 'pending': [dict(i) for i in invites]})

@app.route('/api/team/invite', methods=['POST'])
def invite_team():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    if user['role'] not in ('owner', 'admin'):
        db.close()
        return jsonify({'error': 'Must be org owner'}), 403
    org = db.execute('SELECT * FROM organizations WHERE id=?', (user['org_id'],)).fetchone()
    d = request.json or {}
    invite_email = (d.get('email') or '').lower().strip()
    if not invite_email:
        db.close()
        return jsonify({'error': 'Email required'}), 400
    tok = secrets.token_hex(20)
    try:
        db.execute('INSERT INTO invitations (org_id, email, role, token) VALUES (?,?,?,?)',
            (user['org_id'], invite_email, d.get('role', 'agent'), tok))
        db.commit()
        link = f'{BASE_URL}/accept-invite?token={tok}'
        send_email(invite_email, f"You're invited to {org['name']} on Peekbot",
            f'''<h2>Join {org['name']} on Peekbot</h2>
            <p>You've been invited as a <b>{d.get("role","agent")}</b>.</p>
            <p><a href="{link}" style="background:#7c6af7;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;">Accept Invitation</a></p>
            <p>Or copy: {link}</p>''')
        db.close()
        return jsonify({'success': True})
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 400

@app.route('/api/team/accept-invite', methods=['POST'])
def accept_invitation():
    d = request.json or {}
    tok      = d.get('token', '')
    email    = (d.get('email') or '').lower().strip()
    password = d.get('password', '')
    name     = d.get('name', '').strip()
    db = get_db()
    invite = db.execute('SELECT * FROM invitations WHERE token=? AND accepted=0', (tok,)).fetchone()
    if not invite:
        db.close()
        return jsonify({'error': 'Invalid or expired invitation'}), 400
    try:
        db.execute('INSERT INTO users (email, password, name, org_id, role) VALUES (?,?,?,?,?)',
            (email, hash_pw(password), name, invite['org_id'], invite['role']))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        db.execute('UPDATE invitations SET accepted=1 WHERE token=?', (tok,))
        db.commit()
        db.close()
        return jsonify({
            'token': make_token(user['id'], user['email']),
            'email': user['email'],
            'name':  user['name'],
            'plan':  'free',
            'role':  user['role']
        })
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 400

@app.route('/api/team/<int:member_id>', methods=['DELETE'])
def remove_team_member(member_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    if user['role'] not in ('owner', 'admin'):
        db.close()
        return jsonify({'error': 'Must be org owner'}), 403
    member = db.execute('SELECT * FROM users WHERE id=? AND org_id=?', (member_id, user['org_id'])).fetchone()
    if not member or member['role'] == 'owner':
        db.close()
        return jsonify({'error': 'Cannot remove this member'}), 400
    db.execute('DELETE FROM users WHERE id=?', (member_id,))
    db.commit()
    db.close()
    return jsonify({'success': True})

# ─── TEMPLATES ───
@app.route('/api/templates', methods=['GET'])
def get_templates():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    tmpl = db.execute('SELECT * FROM contract_templates WHERE org_id=?', (user['org_id'],)).fetchall()
    db.close()
    return jsonify([dict(t) for t in tmpl])

@app.route('/api/templates', methods=['POST'])
def upload_template():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if not f or not ('.' in f.filename and f.filename.rsplit('.',1)[1].lower() in ALLOWED_EXT):
        return jsonify({'error': 'Invalid file type'}), 400
    db = get_db()
    user = get_user(uid, db)
    fn  = secure_filename(f.filename)
    fp  = os.path.join(UPLOAD_DIR, f"{user['org_id']}_{int(time.time())}_{fn}")
    f.save(fp)
    db.execute('INSERT INTO contract_templates (org_id, name, description, file_path, file_type, category) VALUES (?,?,?,?,?,?)',
        (user['org_id'], request.form.get('name', fn), request.form.get('description',''),
         fp, fn.rsplit('.',1)[1], request.form.get('category','general')))
    db.commit()
    tmpl = db.execute('SELECT * FROM contract_templates WHERE org_id=? ORDER BY id DESC LIMIT 1', (user['org_id'],)).fetchone()
    db.close()
    return jsonify(dict(tmpl)), 201

@app.route('/api/templates/<int:tid>', methods=['DELETE'])
def delete_template(tid):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    tmpl = db.execute('SELECT * FROM contract_templates WHERE id=? AND org_id=?', (tid, user['org_id'])).fetchone()
    if not tmpl:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    try:
        os.remove(tmpl['file_path'])
    except Exception:
        pass
    db.execute('DELETE FROM contract_templates WHERE id=?', (tid,))
    db.commit()
    db.close()
    return jsonify({'success': True})

# ─── DOCUMENTS ───
@app.route('/api/documents', methods=['GET'])
def get_documents():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    docs = db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY created_at DESC', (user['org_id'],)).fetchall()
    db.close()
    return jsonify([dict(d) for d in docs])

@app.route('/api/generate-contract', methods=['POST'])
def generate_contract():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    db = get_db()
    user = get_user(uid, db)
    data = d.get('data', {})
    prompt = f"""Generate a professional contract:
Title: {d.get('title','Contract')}
Data: {json.dumps(data)}
Return complete contract text only."""
    try:
        contract_text = openai_call([{'role':'user','content':prompt}], max_tokens=2000)
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500
    fp = os.path.join(DOCS_DIR, f"contract_{int(time.time())}.txt")
    with open(fp, 'w') as fh:
        fh.write(contract_text)
    db.execute('INSERT INTO generated_documents (org_id, doc_type, title, data_json, file_path, status) VALUES (?,?,?,?,?,?)',
        (user['org_id'], 'contract', d.get('title','Contract'), json.dumps(data), fp, 'draft'))
    db.commit()
    doc = db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY id DESC LIMIT 1', (user['org_id'],)).fetchone()
    db.close()
    return jsonify({'success': True, 'doc_id': doc['id'], 'content': contract_text}), 201

@app.route('/api/generate-invoice', methods=['POST'])
def generate_invoice():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    db = get_db()
    user = get_user(uid, db)
    data   = d.get('data', {})
    amount = float(data.get('amount', 0))
    tax    = float(data.get('tax_rate', 0))
    total  = amount * (1 + tax/100)
    inv_num = data.get('invoice_num', secrets.token_hex(4).upper())
    text = f"""INVOICE #{inv_num}
Date: {datetime.datetime.now().strftime('%B %d, %Y')}
Due: {data.get('due_date','')}

From: {user['name']}

Bill To:
{data.get('client_name','')}
{data.get('client_email','')}

{data.get('description','')}

Subtotal: ${amount:.2f}
Tax ({tax}%): ${amount*tax/100:.2f}
TOTAL DUE: ${total:.2f}

Terms: {data.get('terms','Net 30')}
"""
    fp = os.path.join(DOCS_DIR, f"invoice_{int(time.time())}.txt")
    with open(fp, 'w') as fh:
        fh.write(text)
    db.execute('INSERT INTO generated_documents (org_id, doc_type, title, data_json, file_path, status) VALUES (?,?,?,?,?,?)',
        (user['org_id'], 'invoice', f'Invoice #{inv_num}', json.dumps(data), fp, 'draft'))
    db.commit()
    doc = db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY id DESC LIMIT 1', (user['org_id'],)).fetchone()
    db.close()
    return jsonify({'success': True, 'doc_id': doc['id'], 'content': text, 'total': total}), 201

@app.route('/api/documents/<int:doc_id>/download', methods=['GET'])
def download_document(doc_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    doc = db.execute('SELECT * FROM generated_documents WHERE id=? AND org_id=?', (doc_id, user['org_id'])).fetchone()
    db.close()
    if not doc: return jsonify({'error': 'Not found'}), 404
    return send_from_directory(os.path.dirname(doc['file_path']),
        os.path.basename(doc['file_path']), as_attachment=True)

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    doc = db.execute('SELECT * FROM generated_documents WHERE id=? AND org_id=?', (doc_id, user['org_id'])).fetchone()
    if not doc:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    try:
        os.remove(doc['file_path'])
    except Exception:
        pass
    db.execute('DELETE FROM generated_documents WHERE id=?', (doc_id,))
    db.commit()
    db.close()
    return jsonify({'success': True})

# ─── BILLING ───
@app.route('/api/upgrade', methods=['POST'])
def upgrade():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = get_user(uid, db)
    db.close()
    d    = request.json or {}
    plan = d.get('plan', 'pro')
    price_id = STRIPE_PRO if plan == 'pro' else STRIPE_SUPER

    if STRIPE_SECRET and price_id:
        try:
            sess = stripe_post('checkout/sessions', {
                'payment_method_types[]': 'card',
                'line_items[0][price]': price_id,
                'line_items[0][quantity]': '1',
                'mode': 'subscription',
                'customer_email': user['email'],
                'metadata[user_id]': str(uid),
                'metadata[plan]': plan,
                'success_url': f'{BASE_URL}/dashboard?upgraded=1',
                'cancel_url':  f'{BASE_URL}/dashboard?upgrade_cancelled=1',
            })
            return jsonify({'url': sess['url']})
        except Exception as e:
            print(f'[stripe] {e}')

    # Fallback: send email request
    send_email(ADMIN_EMAIL, f'Upgrade Request: {plan}',
        f'<p>User <b>{user["email"]}</b> wants to upgrade to <b>{plan}</b>.</p>'
        f'<p>Manually update plan in DB: UPDATE users SET plan="{plan}" WHERE email="{user["email"]}"; </p>')
    return jsonify({'message': 'Upgrade request sent. We\'ll be in touch within 24h.'})

@app.route('/api/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig = request.headers.get('Stripe-Signature', '')
    if STRIPE_WEBHOOK and not verify_stripe_sig(payload, sig):
        return jsonify({'error': 'Invalid signature'}), 400
    try:
        event = json.loads(payload)
        if event['type'] == 'checkout.session.completed':
            sess     = event['data']['object']
            user_id  = int(sess.get('metadata', {}).get('user_id', 0))
            plan     = sess.get('metadata', {}).get('plan', 'pro')
            sub_id   = sess.get('subscription', '')
            if user_id:
                db = get_db()
                db.execute('UPDATE users SET plan=?, stripe_sub_id=? WHERE id=?', (plan, sub_id, user_id))
                db.commit()
                db.close()
        elif event['type'] == 'customer.subscription.deleted':
            sub_id = event['data']['object']['id']
            db = get_db()
            db.execute("UPDATE users SET plan='free', stripe_sub_id=NULL WHERE stripe_sub_id=?", (sub_id,))
            db.commit()
            db.close()
    except Exception as e:
        print(f'[webhook] {e}')
    return jsonify({'received': True})

# ─── SETUP CHAT (LLM-backed onboarding) ───
@app.route('/api/setup-chat', methods=['POST'])
def setup_chat():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    messages = d.get('messages', [])
    system = """You are Peekbot Setup, a friendly assistant helping configure an AI chat widget for a business.
Collect these 3 things in order, one question at a time:
1. Business name
2. What the business does (1-2 sentences)
3. Bot personality tone (Professional, Friendly, Expert, or Casual)

Be brief, warm, and conversational. After you have all 3 pieces of information confirmed, output ONLY this JSON on the last line (no trailing text):
{"done":true,"name":"<business name>","purpose":"<what they do>","tone":"<professional|friendly|expert|casual>"}

Map any tone synonym to one of those 4 exact values."""
    try:
        reply = openai_call([{'role':'system','content':system}] + messages, max_tokens=250)
        config = None
        m = re.search(r'\{[^{}]*"done"\s*:\s*true[^{}]*\}', reply)
        if m:
            try:
                config = json.loads(m.group())
                reply  = reply[:m.start()].strip()
            except Exception:
                pass
        return jsonify({'reply': reply, 'config': config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/feature-request', methods=['POST'])
def feature_request():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    db = get_db()
    user = get_user(uid, db)
    db.close()
    send_email(ADMIN_EMAIL, f'Feature Request from {user["email"]}',
        f'<pre>{json.dumps(d, indent=2)}</pre>')
    return jsonify({'success': True})

# ─── PUBLIC CHAT ───
@app.route('/api/chat/<bot_token>', methods=['POST'])
def chat(bot_token):
    if not rate_ok(bot_token):
        return jsonify({'error': 'Rate limit exceeded. Try again in a minute.'}), 429

    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE token=?', (bot_token,)).fetchone()
    if not bot:
        db.close()
        return jsonify({'error': 'Bot not found'}), 404

    # Free tier message limit
    org = db.execute('SELECT * FROM organizations WHERE id=?', (bot['org_id'],)).fetchone()
    owner = db.execute('SELECT * FROM users WHERE id=?', (org['owner_id'],)).fetchone()
    if owner and owner['plan'] == 'free':
        count = monthly_msg_count(bot['id'], db)
        if count >= FREE_MSG_LIMIT:
            db.close()
            return jsonify({'reply': f"I've reached my message limit for this month. Please contact the site owner to upgrade."})

    d = request.json or {}
    messages   = d.get('messages', [])
    session_id = d.get('session_id') or secrets.token_hex(8)

    if messages:
        last = messages[-1]
        db.execute('INSERT INTO conversations (bot_id, session_id, role, message) VALUES (?,?,?,?)',
            (bot['id'], session_id, last['role'], last['content'][:2000]))
        db.commit()

    knowledge = db.execute('SELECT content FROM knowledge_base WHERE org_id=? ORDER BY id DESC LIMIT 15', (bot['org_id'],)).fetchall()
    kb_text = '\n\n'.join(k['content'] for k in knowledge)
    system = bot['system_prompt'] or 'You are a helpful assistant.'
    if kb_text:
        system += f'\n\n--- Knowledge Base ---\n{kb_text}\n--- End Knowledge ---'

    try:
        reply = openai_call([{'role':'system','content':system}] + messages)
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

    db.execute('INSERT INTO conversations (bot_id, session_id, role, message) VALUES (?,?,?,?)',
        (bot['id'], session_id, 'assistant', reply))
    db.commit()
    db.close()
    return jsonify({'reply': reply, 'session_id': session_id})

# ─── PUBLIC LEAD CAPTURE ───
@app.route('/api/lead/<bot_token>', methods=['POST'])
def capture_lead(bot_token):
    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE token=?', (bot_token,)).fetchone()
    if not bot:
        db.close()
        return jsonify({'error': 'Bot not found'}), 404
    d = request.json or {}
    db.execute('INSERT INTO leads (bot_id, name, email, phone, notes, status) VALUES (?,?,?,?,?,?)',
        (bot['id'], d.get('name'), d.get('email'), d.get('phone'), d.get('notes'), 'new'))
    db.commit()
    org   = db.execute('SELECT * FROM organizations WHERE id=?', (bot['org_id'],)).fetchone()
    owner = db.execute('SELECT * FROM users WHERE id=?', (org['owner_id'],)).fetchone()
    if owner:
        send_email(owner['email'], f'New lead from {bot["name"]} 🎉',
            f'''<h2>New Lead!</h2>
            <p><b>Name:</b> {d.get("name","N/A")}</p>
            <p><b>Email:</b> {d.get("email","N/A")}</p>
            <p><b>Phone:</b> {d.get("phone","N/A")}</p>
            <p><a href="{BASE_URL}/dashboard">View in Dashboard →</a></p>''')
    db.close()
    return jsonify({'success': True})

# ─── PUBLIC BOT CONFIG ───
@app.route('/api/config/<bot_token>', methods=['GET'])
def get_config(bot_token):
    db = get_db()
    bot = db.execute('SELECT id,name,greeting,color,lead_capture FROM bots WHERE token=?', (bot_token,)).fetchone()
    db.close()
    if not bot: return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(bot))

# ─── EMBED SCRIPT ───
@app.route('/embed.js')
def embed_script():
    script = r"""
(function() {
'use strict';
var t = document.currentScript && document.currentScript.getAttribute('data-token');
if (!t) return;
var base = 'https://peekbot.cana.chat';
var cfg = null, hist = [], sid = 'pb_' + Math.random().toString(36).substr(2, 9);
var pos = document.currentScript.getAttribute('data-position') || 'right';

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

fetch(base + '/api/config/' + t).then(function(r){ return r.json(); }).then(function(c){
  cfg = c;
  inject();
}).catch(function(){});

function inject() {
  // Use shadow DOM to isolate from host page CSS
  var host = document.createElement('div');
  host.id = 'peekbot-widget';
  host.style.cssText = 'position:fixed;bottom:1.5rem;z-index:2147483647;' + (pos === 'left' ? 'left:1.5rem' : 'right:1.5rem');
  document.body.appendChild(host);

  var shadow = host.attachShadow({mode:'closed'});

  var style = document.createElement('style');
  style.textContent = [
    ':host { all: initial; font-family: system-ui, -apple-system, sans-serif; font-size: 14px; }',
    '#pb-btn { width:52px;height:52px;border-radius:50%;background:'+cfg.color+';border:none;cursor:pointer;',
    '  display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(0,0,0,.25);',
    '  color:white;font-size:1.4rem;transition:transform .2s; }',
    '#pb-btn:hover { transform:scale(1.08); }',
    '#pb-panel { position:absolute;bottom:4rem;' + (pos === 'left' ? 'left:0' : 'right:0') + ';',
    '  width:320px;background:#fff;border-radius:16px;display:none;flex-direction:column;overflow:hidden;',
    '  border:1px solid rgba(0,0,0,.1);max-height:480px;box-shadow:0 8px 40px rgba(0,0,0,.18); }',
    '#pb-panel.open { display:flex; }',
    '#pb-head { background:'+cfg.color+';padding:.85rem 1rem;display:flex;align-items:center;gap:.6rem;color:#fff; }',
    '#pb-head-name { font-weight:600;font-size:.9rem;flex:1; }',
    '#pb-close { background:none;border:none;color:rgba(255,255,255,.8);cursor:pointer;font-size:1.1rem;padding:0; }',
    '#pb-msgs { flex:1;overflow-y:auto;padding:.85rem;display:flex;flex-direction:column;gap:.6rem;background:#f7f7f8; }',
    '.pb-msg { display:flex;gap:.4rem;max-width:100%; }',
    '.pb-msg.u { justify-content:flex-end; }',
    '.pb-bubble { max-width:80%;padding:.55rem .8rem;border-radius:14px;font-size:.8rem;line-height:1.5;word-break:break-word; }',
    '.pb-msg.b .pb-bubble { background:#fff;color:#111;border:1px solid #e5e5e5; }',
    '.pb-msg.u .pb-bubble { background:'+cfg.color+';color:#fff; }',
    '#pb-form { background:#fff;padding:.6rem .75rem;border-top:1px solid #f0f0f0;display:flex;gap:.4rem; }',
    '#pb-input { flex:1;border:1px solid #e5e5e5;border-radius:20px;padding:.4rem .85rem;font-size:.8rem;outline:none; }',
    '#pb-input:focus { border-color:'+cfg.color+'; }',
    '#pb-send { width:32px;height:32px;border-radius:50%;background:'+cfg.color+';border:none;cursor:pointer;',
    '  color:#fff;font-size:1rem;display:flex;align-items:center;justify-content:center;flex-shrink:0; }',
    '.pb-typing { display:flex;gap:4px;align-items:center;padding:.4rem; }',
    '.pb-dot { width:6px;height:6px;border-radius:50%;background:#999;animation:pb-bounce .8s infinite; }',
    '.pb-dot:nth-child(2){animation-delay:.15s}.pb-dot:nth-child(3){animation-delay:.3s}',
    '@keyframes pb-bounce{0%,80%,100%{transform:translateY(0)}40%{transform:translateY(-6px)}}',
  ].join('');
  shadow.appendChild(style);

  var panel = document.createElement('div');
  panel.id = 'pb-panel';
  panel.innerHTML =
    '<div id="pb-head">' +
      '<div style="width:28px;height:28px;border-radius:50%;background:rgba(255,255,255,.25);display:flex;align-items:center;justify-content:center;font-size:.9rem;">' + esc(cfg.name[0]) + '</div>' +
      '<div id="pb-head-name">' + esc(cfg.name) + '</div>' +
      '<button id="pb-close" aria-label="Close chat">✕</button>' +
    '</div>' +
    '<div id="pb-msgs" role="log" aria-live="polite"></div>' +
    '<div id="pb-form">' +
      '<input id="pb-input" type="text" placeholder="Type a message..." aria-label="Chat message"/>' +
      '<button id="pb-send" aria-label="Send">➤</button>' +
    '</div>';

  var btn = document.createElement('button');
  btn.id = 'pb-btn';
  btn.setAttribute('aria-label', 'Open chat');
  btn.innerHTML = '💬';

  shadow.appendChild(panel);
  shadow.appendChild(btn);

  var msgs   = shadow.getElementById('pb-msgs');
  var inp    = shadow.getElementById('pb-input');
  var open   = false;

  btn.addEventListener('click', function() {
    open = !open;
    panel.classList.toggle('open', open);
    btn.innerHTML = open ? '✕' : '💬';
    if (open) inp.focus();
  });
  shadow.getElementById('pb-close').addEventListener('click', function() {
    open = false;
    panel.classList.remove('open');
    btn.innerHTML = '💬';
  });
  shadow.getElementById('pb-send').addEventListener('click', function() { send(inp.value); });
  inp.addEventListener('keypress', function(e) { if (e.key === 'Enter') send(inp.value); });

  // Lead capture state
  var leadCaptureStep = 0, leadCaptureData = {};
  var LEAD_TRIGGER = 3; // after N bot messages, prompt for contact

  function add(text, role) {
    var d = document.createElement('div');
    d.className = 'pb-msg ' + (role === 'u' ? 'u' : 'b');
    var bub = document.createElement('div');
    bub.className = 'pb-bubble';
    bub.textContent = text; // textContent prevents XSS
    d.appendChild(bub);
    msgs.appendChild(d);
    msgs.scrollTop = msgs.scrollHeight;
    return d;
  }

  function addTyping() {
    var d = document.createElement('div');
    d.className = 'pb-msg b';
    d.id = 'pb-typing';
    d.innerHTML = '<div class="pb-bubble pb-typing"><div class="pb-dot"></div><div class="pb-dot"></div><div class="pb-dot"></div></div>';
    msgs.appendChild(d);
    msgs.scrollTop = msgs.scrollHeight;
    return d;
  }

  var botMsgCount = 0;
  function handleBotReply(text) {
    botMsgCount++;
    add(text, 'b');
    if (cfg.lead_capture && botMsgCount === LEAD_TRIGGER && leadCaptureStep === 0) {
      setTimeout(function() { promptLeadCapture(); }, 800);
    }
  }

  function promptLeadCapture() {
    leadCaptureStep = 1;
    add("Before I forget — would you like me to have someone follow up with you? I can take your name and email.", 'b');
  }

  async function send(text) {
    text = text.trim();
    if (!text) return;
    inp.value = '';

    // Lead capture flow
    if (leadCaptureStep === 1) {
      var lower = text.toLowerCase();
      if (lower.includes('yes') || lower.includes('sure') || lower.includes('ok') || lower.includes('yeah')) {
        leadCaptureStep = 2;
        add(text, 'u');
        add("Great! What's your name?", 'b');
        return;
      } else if (lower.includes('no') || lower.includes('nope') || lower.includes('skip')) {
        leadCaptureStep = -1;
        add(text, 'u');
        add("No problem! What else can I help you with?", 'b');
        return;
      }
    }
    if (leadCaptureStep === 2) {
      leadCaptureData.name = text;
      leadCaptureStep = 3;
      add(text, 'u');
      add("Thanks " + esc(text) + "! And your email address?", 'b');
      return;
    }
    if (leadCaptureStep === 3) {
      leadCaptureData.email = text;
      leadCaptureStep = 4;
      add(text, 'u');
      // Save lead
      fetch(base + '/api/lead/' + t, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(leadCaptureData)
      });
      add("Got it! Someone will be in touch soon. Now, what else can I help with?", 'b');
      return;
    }

    add(text, 'u');
    hist.push({role: 'user', content: text});
    var typing = addTyping();
    inp.disabled = true;

    try {
      var res  = await fetch(base + '/api/chat/' + t, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({messages: hist, session_id: sid})
      });
      var data = await res.json();
      typing.remove();
      inp.disabled = false;
      inp.focus();
      var reply = data.reply || data.error || 'Something went wrong.';
      hist.push({role: 'assistant', content: reply});
      handleBotReply(reply);
      if (data.session_id) sid = data.session_id;
    } catch(e) {
      typing.remove();
      inp.disabled = false;
      add('Connection error. Please try again.', 'b');
    }
  }

  add(cfg.greeting || 'Hi! How can I help?', 'b');
}
})();
"""
    resp = Response(script, mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'public, max-age=300'
    return resp

# ─── QUICKBOOKS ───
def qb_get_token(org, db):
    """Return a valid QB access token, refreshing if within 5 min of expiry."""
    expires_at = org['qb_token_expires_at']
    if expires_at:
        try:
            exp = datetime.datetime.fromisoformat(expires_at)
            if datetime.datetime.utcnow() < exp - datetime.timedelta(minutes=5):
                return org['qb_access_token']
        except Exception:
            pass
    credentials = base64.b64encode(f'{QB_CLIENT_ID}:{QB_CLIENT_SECRET}'.encode()).decode()
    data = urllib.parse.urlencode({
        'grant_type': 'refresh_token',
        'refresh_token': org['qb_refresh_token']
    }).encode()
    req = urllib.request.Request(
        'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
        data=data,
        headers={
            'Authorization': f'Basic {credentials}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
    )
    with urllib.request.urlopen(req) as resp:
        tokens = json.loads(resp.read())
    new_expires = (datetime.datetime.utcnow() + datetime.timedelta(seconds=tokens.get('expires_in', 3600))).isoformat()
    new_refresh  = tokens.get('refresh_token', org['qb_refresh_token'])
    db.execute('UPDATE organizations SET qb_access_token=?, qb_refresh_token=?, qb_token_expires_at=? WHERE id=?',
               (tokens['access_token'], new_refresh, new_expires, org['id']))
    db.commit()
    return tokens['access_token']


@app.route('/api/quickbooks/connect')
def qb_connect():
    token = request.args.get('token', '')
    try:
        jwt.decode(token, SECRET, algorithms=['HS256'])
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401
    state = base64.urlsafe_b64encode(json.dumps({'token': token}).encode()).decode()
    params = urllib.parse.urlencode({
        'client_id': QB_CLIENT_ID,
        'scope': 'com.intuit.quickbooks.accounting',
        'redirect_uri': QB_REDIRECT_URI,
        'response_type': 'code',
        'access_type': 'offline',
        'state': state
    })
    return redirect(f'https://appcenter.intuit.com/connect/oauth2?{params}')


@app.route('/api/quickbooks/callback')
def qb_callback():
    error = request.args.get('error', '')
    if error:
        return redirect('/?qb_error=1')
    code     = request.args.get('code', '')
    state    = request.args.get('state', '')
    realm_id = request.args.get('realmId', '')
    try:
        state_data = json.loads(base64.urlsafe_b64decode(state + '=='))
        token = state_data['token']
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        user_id = payload['user_id']
    except Exception:
        return redirect('/?qb_error=1')
    credentials = base64.b64encode(f'{QB_CLIENT_ID}:{QB_CLIENT_SECRET}'.encode()).decode()
    data = urllib.parse.urlencode({
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': QB_REDIRECT_URI
    }).encode()
    try:
        req = urllib.request.Request(
            'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
            data=data,
            headers={
                'Authorization': f'Basic {credentials}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
        )
        with urllib.request.urlopen(req) as resp:
            tokens = json.loads(resp.read())
    except Exception as e:
        return redirect(f'/?qb_error=1')
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(seconds=tokens.get('expires_in', 3600))).isoformat()
    db = get_db()
    user = get_user(user_id, db)
    db.execute('''UPDATE organizations SET qb_realm_id=?, qb_access_token=?, qb_refresh_token=?, qb_token_expires_at=?
                  WHERE id=?''',
               (realm_id, tokens['access_token'], tokens['refresh_token'], expires_at, user['org_id']))
    db.commit()
    db.close()
    return redirect('/?qb_connected=1')


@app.route('/api/quickbooks/status')
def qb_status():
    uid = verify_token(request)
    if not uid:
        return jsonify({'error': 'Unauthorized'}), 401
    db  = get_db()
    user = get_user(uid, db)
    org  = db.execute('SELECT qb_realm_id, qb_access_token FROM organizations WHERE id=?', (user['org_id'],)).fetchone()
    db.close()
    connected = bool(org and org['qb_access_token'] and org['qb_realm_id'])
    return jsonify({'connected': connected, 'realm_id': org['qb_realm_id'] if org else None})


@app.route('/api/quickbooks/sync', methods=['POST'])
def qb_sync():
    uid = verify_token(request)
    if not uid:
        return jsonify({'error': 'Unauthorized'}), 401
    db   = get_db()
    user = get_user(uid, db)
    org  = db.execute('SELECT * FROM organizations WHERE id=?', (user['org_id'],)).fetchone()
    if not org or not org['qb_access_token']:
        db.close()
        return jsonify({'error': 'QuickBooks not connected'}), 400
    try:
        access_token = qb_get_token(org, db)
    except Exception as e:
        db.close()
        return jsonify({'error': f'Token refresh failed: {e}'}), 502
    realm_id = org['qb_realm_id']
    query    = urllib.parse.quote("SELECT * FROM Customer MAXRESULTS 100")
    req = urllib.request.Request(
        f'https://quickbooks.api.intuit.com/v3/company/{realm_id}/query?query={query}&minorversion=65',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            qb_data = json.loads(resp.read())
    except Exception as e:
        db.close()
        return jsonify({'error': f'QB API error: {e}'}), 502
    customers = qb_data.get('QueryResponse', {}).get('Customer', [])
    synced = 0
    for c in customers:
        email = (c.get('PrimaryEmailAddr') or {}).get('Address', '').strip()
        name  = c.get('DisplayName', '').strip()
        if not email:
            continue
        existing = db.execute('SELECT id FROM leads WHERE email=? AND org_id=?', (email, user['org_id'])).fetchone()
        if not existing:
            db.execute('INSERT INTO leads (org_id, name, email, source, status, created_at) VALUES (?,?,?,?,?,?)',
                       (user['org_id'], name, email, 'quickbooks', 'new', datetime.datetime.utcnow().isoformat()))
            synced += 1
    db.commit()
    db.close()
    return jsonify({'synced': synced, 'total': len(customers)})


@app.route('/api/quickbooks/disconnect', methods=['POST'])
def qb_disconnect():
    uid = verify_token(request)
    if not uid:
        return jsonify({'error': 'Unauthorized'}), 401
    db   = get_db()
    user = get_user(uid, db)
    db.execute('UPDATE organizations SET qb_realm_id=NULL, qb_access_token=NULL, qb_refresh_token=NULL, qb_token_expires_at=NULL WHERE id=?',
               (user['org_id'],))
    db.commit()
    db.close()
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3005, debug=False)
