from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import sqlite3, hashlib, jwt, json, datetime, smtplib, urllib.request, os, secrets
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv('/home/jackson/OR-Compliance/.env')

app = Flask(__name__, static_folder='static')
CORS(app, origins='*')

SECRET = os.environ.get('ADMIN_SECRET', 'peekbot_secret_2026')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY', '')
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID', '')
PAYPAL_SECRET = os.environ.get('PAYPAL_SECRET', '')
PAYPAL_MODE = os.environ.get('PAYPAL_MODE', 'live')
PAYPAL_BASE = 'https://api-m.paypal.com' if PAYPAL_MODE == 'live' else 'https://api-m.sandbox.paypal.com'

DB = '/home/jackson/peekbot.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            plan TEXT DEFAULT 'free',
            paypal_sub_id TEXT,
            active INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT 'Assistant',
            greeting TEXT DEFAULT 'Hi! How can I help you today?',
            system_prompt TEXT DEFAULT 'You are a helpful assistant.',
            color TEXT DEFAULT '#111111',
            avatar TEXT DEFAULT '',
            lead_capture INTEGER DEFAULT 1,
            color_light TEXT DEFAULT '#ffffff',
            color_dark TEXT DEFAULT '#1c1c1c',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id INTEGER NOT NULL,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(bot_id) REFERENCES bots(id)
        );
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id INTEGER NOT NULL,
            name TEXT,
            email TEXT,
            phone TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(bot_id) REFERENCES bots(id)
        );
    ''')
    db.commit()
    db.close()

init_db()

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user_id, email):
    return jwt.encode({'user_id': user_id, 'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)}, SECRET, algorithm='HS256')

def verify_token(req):
    auth = req.headers.get('Authorization', '')
    if not auth.startswith('Bearer '): return None
    try:
        data = jwt.decode(auth[7:], SECRET, algorithms=['HS256'])
        return data['user_id']
    except: return None

def send_email(to, subject, body):
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
        print(f'Email error: {e}')

# ─── SERVE FRONTEND ───
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

# ─── AUTH ───
@app.route('/api/register', methods=['POST'])
def register():
    d = request.json
    db = get_db()
    try:
        db.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
            (d['email'].lower(), hash_pw(d['password']), d.get('name', '')))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE email=?', (d['email'].lower(),)).fetchone()
        # Auto-create first bot
        token = secrets.token_hex(16)
        db.execute('INSERT INTO bots (user_id, token, name) VALUES (?, ?, ?)',
            (user['id'], token, d.get('name', 'My') + "'s Assistant"))
        db.commit()
        db.close()
        return jsonify({'token': make_token(user['id'], user['email']), 'email': user['email']})
    except Exception as e:
        db.close()
        return jsonify({'error': 'Email already registered'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=? AND password=?',
        (d['email'].lower(), hash_pw(d['password']))).fetchone()
    db.close()
    if not user: return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'token': make_token(user['id'], user['email']), 'email': user['email'], 'name': user['name'], 'plan': user['plan']})

# ─── BOT CRUD ───
@app.route('/api/bot', methods=['GET'])
def get_bot():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    bot = db.execute('SELECT * FROM bots WHERE user_id=? ORDER BY id LIMIT 1', (uid,)).fetchone()
    db.close()
    if not bot: return jsonify({'error': 'No bot found'}), 404
    return jsonify({**dict(bot), 'plan': user['plan']})

@app.route('/api/bots', methods=['GET'])
def get_bots():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    bots = db.execute('SELECT * FROM bots WHERE user_id=? ORDER BY id', (uid,)).fetchall()
    db.close()
    return jsonify({'bots': [dict(b) for b in bots], 'plan': user['plan']})

@app.route('/api/bots', methods=['POST'])
def create_bot():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    bot_count = db.execute('SELECT COUNT(*) as cnt FROM bots WHERE user_id=?', (uid,)).fetchone()['cnt']
    if user['plan'] == 'free' and bot_count >= 1:
        db.close()
        return jsonify({'error': 'Upgrade to Pro for multiple bots'}), 403
    if user['plan'] == 'pro' and bot_count >= 3:
        db.close()
        return jsonify({'error': 'Pro plan allows up to 3 bots'}), 403
    import secrets as sec
    token = sec.token_hex(16)
    d = request.json
    db.execute('INSERT INTO bots (user_id, token, name, greeting, system_prompt, color) VALUES (?, ?, ?, ?, ?, ?)',
        (uid, token, d.get('name', 'Assistant'), d.get('greeting', 'Hi! How can I help?'),
         d.get('system_prompt', 'You are a helpful assistant.'), d.get('color', '#7c6af7')))
    db.commit()
    bot = db.execute('SELECT * FROM bots WHERE token=?', (token,)).fetchone()
    db.close()
    return jsonify(dict(bot))

@app.route('/api/bots/<int:bot_id>', methods=['DELETE'])
def delete_bot(bot_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot_count = db.execute('SELECT COUNT(*) as cnt FROM bots WHERE user_id=?', (uid,)).fetchone()['cnt']
    if bot_count <= 1:
        db.close()
        return jsonify({'error': 'Cannot delete your only bot'}), 400
    db.execute('DELETE FROM bots WHERE id=? AND user_id=?', (bot_id, uid))
    db.commit()
    db.close()
    return jsonify({'success': True})

@app.route('/api/bot', methods=['PUT'])
def update_bot():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json
    db = get_db()
    db.execute('''UPDATE bots SET name=?, greeting=?, system_prompt=?, color=?, lead_capture=?, color_light=?, color_dark=?
                  WHERE user_id=?''',
        (d.get('name'), d.get('greeting'), d.get('system_prompt'),
         d.get('color', '#111111'), d.get('lead_capture', 1),
         d.get('color_light', '#ffffff'), d.get('color_dark', '#1c1c1c'), uid))
    db.commit()
    bot = db.execute('SELECT * FROM bots WHERE user_id=?', (uid,)).fetchone()
    db.close()
    return jsonify(dict(bot))

# ─── LEADS ───
@app.route('/api/leads', methods=['GET'])
def get_leads():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE user_id=?', (uid,)).fetchone()
    if not bot: return jsonify([])
    leads = db.execute('SELECT * FROM leads WHERE bot_id=? ORDER BY created_at DESC', (bot['id'],)).fetchall()
    db.close()
    return jsonify([dict(l) for l in leads])

# ─── CONVERSATIONS ───
@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE user_id=?', (uid,)).fetchone()
    if not bot: return jsonify([])
    convos = db.execute('''SELECT session_id, MIN(created_at) as started, COUNT(*) as messages
                           FROM conversations WHERE bot_id=?
                           GROUP BY session_id ORDER BY started DESC LIMIT 50''', (bot['id'],)).fetchall()
    db.close()
    return jsonify([dict(c) for c in convos])

@app.route('/api/conversations/<session_id>', methods=['GET'])
def get_conversation(session_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE user_id=?', (uid,)).fetchone()
    msgs = db.execute('SELECT * FROM conversations WHERE bot_id=? AND session_id=? ORDER BY created_at',
        (bot['id'], session_id)).fetchall()
    db.close()
    return jsonify([dict(m) for m in msgs])

# ─── CHAT (public, token-based) ───
@app.route('/api/chat/<bot_token>', methods=['POST'])
def chat(bot_token):
    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE token=?', (bot_token,)).fetchone()
    if not bot:
        db.close()
        return jsonify({'error': 'Bot not found'}), 404

    d = request.json
    messages = d.get('messages', [])
    session_id = d.get('session_id', secrets.token_hex(8))

    # Check message limit for free users
    user = db.execute('SELECT * FROM users WHERE id=?', (bot['user_id'],)).fetchone()
    if user and user['plan'] == 'free':
        import calendar
        now = datetime.datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0).strftime('%Y-%m-%d %H:%M:%S')
        msg_count = db.execute(
            "SELECT COUNT(*) as cnt FROM conversations WHERE bot_id=? AND role='user' AND created_at >= ?",
            (bot['id'], month_start)
        ).fetchone()['cnt']
        if msg_count >= 10:
            db.close()
            return jsonify({'reply': 'Monthly message limit reached. Upgrade to Pro at peekbot.cana.chat for unlimited messages! 🚀', 'session_id': session_id, 'limit_reached': True})

    # Store user message
    if messages:
        last = messages[-1]
        db.execute('INSERT INTO conversations (bot_id, session_id, role, message) VALUES (?, ?, ?, ?)',
            (bot['id'], session_id, last['role'], last['content']))
        db.commit()

    # Call OpenAI
    payload = json.dumps({
        'model': 'gpt-4o-mini',
        'messages': [{'role': 'system', 'content': bot['system_prompt']}] + messages,
        'max_tokens': 500
    }).encode()

    req = urllib.request.Request(
        'https://api.openai.com/v1/chat/completions',
        data=payload,
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {OPENAI_KEY}'}
    )

    try:
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
            reply = result['choices'][0]['message']['content']
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

    # Store bot reply
    db.execute('INSERT INTO conversations (bot_id, session_id, role, message) VALUES (?, ?, ?, ?)',
        (bot['id'], session_id, 'assistant', reply))
    db.commit()
    db.close()

    return jsonify({'reply': reply, 'session_id': session_id})

# ─── LEAD CAPTURE (public) ───
@app.route('/api/lead/<bot_token>', methods=['POST'])
def capture_lead(bot_token):
    db = get_db()
    bot = db.execute('SELECT * FROM bots WHERE token=?', (bot_token,)).fetchone()
    if not bot:
        db.close()
        return jsonify({'error': 'Bot not found'}), 404

    d = request.json
    db.execute('INSERT INTO leads (bot_id, name, email, phone, notes) VALUES (?, ?, ?, ?, ?)',
        (bot['id'], d.get('name'), d.get('email'), d.get('phone'), d.get('notes')))
    db.commit()

    # Get owner email and notify
    user = db.execute('SELECT * FROM users WHERE id=?', (bot['user_id'],)).fetchone()
    db.close()

    if user:
        send_email(user['email'], f'New lead from {bot["name"]}',
            f'''<h2>New Lead 🎉</h2>
            <p><b>Name:</b> {d.get('name', 'N/A')}</p>
            <p><b>Email:</b> {d.get('email', 'N/A')}</p>
            <p><b>Phone:</b> {d.get('phone', 'N/A')}</p>
            <p><b>Notes:</b> {d.get('notes', 'N/A')}</p>
            <p><small>Via Peekbot — peekbot.cana.chat</small></p>''')

    return jsonify({'success': True})

# ─── BOT CONFIG (public, for embed) ───
@app.route('/api/config/<bot_token>', methods=['GET'])
def get_config(bot_token):
    db = get_db()
    bot = db.execute('SELECT b.name, b.greeting, b.color, b.lead_capture, b.token, b.color_light, b.color_dark, u.plan FROM bots b JOIN users u ON b.user_id=u.id WHERE b.token=?', (bot_token,)).fetchone()
    db.close()
    if not bot: return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(bot))

# ─── PAYPAL ───
def get_paypal_token():
    creds = f'{PAYPAL_CLIENT_ID}:{PAYPAL_SECRET}'.encode()
    import base64
    auth = base64.b64encode(creds).decode()
    req = urllib.request.Request(
        f'{PAYPAL_BASE}/v1/oauth2/token',
        data=b'grant_type=client_credentials',
        headers={'Authorization': f'Basic {auth}', 'Content-Type': 'application/x-www-form-urlencoded'}
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())['access_token']

@app.route('/api/paypal/create-order', methods=['POST'])
def create_paypal_order():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    try:
        token = get_paypal_token()
        payload = json.dumps({
            'intent': 'CAPTURE',
            'purchase_units': [{'amount': {'currency_code': 'USD', 'value': '49.00'},
                                 'description': 'Peekbot Monthly Subscription'}],
            'application_context': {
                'return_url': 'https://peekbot.cana.chat/dashboard?payment=success',
                'cancel_url': 'https://peekbot.cana.chat/dashboard?payment=cancelled'
            }
        }).encode()
        req = urllib.request.Request(
            f'{PAYPAL_BASE}/v2/checkout/orders',
            data=payload,
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as r:
            order = json.loads(r.read())
        return jsonify(order)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/paypal/capture/<order_id>', methods=['POST'])
def capture_paypal_order(order_id):
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    try:
        token = get_paypal_token()
        req = urllib.request.Request(
            f'{PAYPAL_BASE}/v2/checkout/orders/{order_id}/capture',
            data=b'{}',
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
        if result.get('status') == 'COMPLETED':
            db = get_db()
            db.execute("UPDATE users SET plan='pro', active=1 WHERE id=?", (uid,))
            db.commit()
            db.close()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── EMBED SCRIPT ───
@app.route('/embed.js')
def embed_script():
    script = r"""
(function() {
  var t = document.currentScript.getAttribute('data-token');
  var base = 'https://peekbot.cana.chat';
  if (!t) return;

  var config = null;
  var history = [];
  var sessionId = 'pb_' + Math.random().toString(36).substr(2, 9);
  var leadCaptured = false;
  var open = false;

  fetch(base + '/api/config/' + t)
    .then(function(r) { return r.json(); })
    .then(function(c) { config = c; inject(); })
    .catch(function() {});

  function inject() {
    var darkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var bubbleBg = darkMode ? (config.color_dark || '#2a2a2a') : (config.color_light || '#ffffff');
    var bubbleText = darkMode ? '#eeeeee' : '#111111';
    var bubbleBorder = darkMode ? '#444444' : '#e5e5e5';
    var style = document.createElement('style');
    style.textContent = `
      #pb-widget { position:fixed; bottom:1.5rem; right:1.5rem; z-index:999999; font-family:system-ui,sans-serif; }
      #pb-btn { width:52px; height:52px; border-radius:50%; background:` + config.color + `; border:none; cursor:pointer;
        display:flex; align-items:center; justify-content:center; box-shadow:0 4px 20px rgba(0,0,0,0.2); transition:transform .2s; }
      #pb-btn:hover { transform:scale(1.08); }
      #pb-btn svg { width:22px; height:22px; fill:white; }
      #pb-dot { position:absolute; top:2px; right:2px; width:10px; height:10px; background:#4ade80;
        border-radius:50%; border:2px solid ` + config.color + `; }
      #pb-panel { position:absolute; bottom:4rem; right:0; width:320px; background:white;
        border-radius:16px; box-shadow:0 16px 48px rgba(0,0,0,0.15); display:none; flex-direction:column;
        overflow:hidden; border:1px solid rgba(0,0,0,0.08); max-height:480px; }
      #pb-panel.pb-open { display:flex; }
      #pb-head { background:` + config.color + `; padding:.85rem 1rem; display:flex; align-items:center; gap:.6rem; }
      #pb-head-name { font-size:.9rem; font-weight:600; color:white; }
      #pb-head-status { font-size:.65rem; color:rgba(255,255,255,.7); letter-spacing:.05em; }
      #pb-close { margin-left:auto; background:none; border:none; color:rgba(255,255,255,.7); cursor:pointer; font-size:1.1rem; }
      #pb-msgs { flex:1; overflow-y:auto; padding:.85rem; display:flex; flex-direction:column; gap:.6rem; background:#f9f9f9; }
      #pb-msgs::-webkit-scrollbar { width:3px; }
      .pb-msg { display:flex; gap:.4rem; align-items:flex-end; }
      .pb-msg.pb-user { flex-direction:row-reverse; }
      .pb-bubble { max-width:78%; padding:.5rem .75rem; border-radius:14px; font-size:.8rem; line-height:1.5; }
      .pb-bot .pb-bubble { background:white; color:#111; border:1px solid #e5e5e5; border-bottom-left-radius:3px; }
      .pb-user .pb-bubble { background:` + config.color + `; color:white; border-bottom-right-radius:3px; }
      .pb-av { width:24px; height:24px; border-radius:50%; background:` + config.color + `; flex-shrink:0;
        display:flex; align-items:center; justify-content:center; font-size:.65rem; color:white; font-weight:600; }
      .pb-typing { display:flex; gap:3px; align-items:center; padding:.5rem .75rem; background:white;
        border:1px solid #e5e5e5; border-radius:14px; border-bottom-left-radius:3px; width:fit-content; }
      .pb-typing span { width:5px; height:5px; border-radius:50%; background:#999; animation:pbDot 1.2s infinite; }
      .pb-typing span:nth-child(2) { animation-delay:.2s; }
      .pb-typing span:nth-child(3) { animation-delay:.4s; }
      @keyframes pbDot { 0%,60%,100%{transform:translateY(0);opacity:.4} 30%{transform:translateY(-4px);opacity:1} }
      #pb-chips { display:flex; flex-wrap:wrap; gap:.35rem; padding:.4rem .85rem 0; }
      .pb-chip { padding:.28rem .6rem; border:1px solid #e0e0e0; border-radius:20px; font-size:.7rem;
        cursor:pointer; background:white; color:#555; transition:all .2s; }
      .pb-chip:hover { background:` + config.color + `; color:white; border-color:` + config.color + `; }
      #pb-form { background:white; padding:.6rem .75rem; border-top:1px solid #f0f0f0; display:flex; gap:.4rem; }
      #pb-input { flex:1; border:1px solid #e5e5e5; border-radius:20px; padding:.42rem .85rem;
        font-size:.78rem; outline:none; background:#fafafa; }
      #pb-input:focus { border-color:` + config.color + `; }
      #pb-send { width:30px; height:30px; border-radius:50%; background:` + config.color + `; border:none;
        cursor:pointer; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
      #pb-send svg { width:12px; height:12px; fill:white; }
      #pb-lead-form { margin:.5rem .85rem; background:#f5f5f5; border-radius:10px; padding:.75rem; }
      #pb-lead-form p { font-size:.72rem; color:#666; margin-bottom:.5rem; }
      #pb-lead-form input { width:100%; border:1px solid #e0e0e0; border-radius:8px; padding:.38rem .65rem;
        font-size:.75rem; margin-bottom:.35rem; outline:none; background:white; box-sizing:border-box; }
      #pb-lead-btn { width:100%; padding:.42rem; background:` + config.color + `; color:white; border:none;
        border-radius:8px; font-size:.72rem; cursor:pointer; letter-spacing:.05em; }
      @media(max-width:400px) { #pb-panel { width:calc(100vw - 2rem); right:-0.5rem; } }
    `;
    document.head.appendChild(style);

    var widget = document.createElement('div');
    widget.id = 'pb-widget';
    widget.innerHTML = `
      <div id="pb-panel">
        <div id="pb-head">
          <div style="width:28px;height:28px;border-radius:50%;background:rgba(255,255,255,.2);
            display:flex;align-items:center;justify-content:center;font-size:.8rem;color:white;font-weight:700;">
            ${config.name.charAt(0)}
          </div>
          <div>
            <div id="pb-head-name">${config.name}</div>
            <div id="pb-head-status">Online now</div>
          </div>
          <button id="pb-close">✕</button>
        </div>
        <div id="pb-msgs"></div>
        <div id="pb-chips"></div>
        <div id="pb-lead-wrap"></div>
        <div id="pb-form">
          <input id="pb-input" type="text" placeholder="Type a message..." />
          <button id="pb-send"><svg viewBox="0 0 24 24"><path d="M2 21l21-9L2 3v7l15 2-15 2z"/></svg></button>
        </div>
      </div>
      <button id="pb-btn">
        <div id="pb-dot"></div>
        <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/></svg>
      </button>
    `;
    document.body.appendChild(widget);

    var msgs = document.getElementById('pb-msgs');
    var chips = document.getElementById('pb-chips');
    var input = document.getElementById('pb-input');
    var panel = document.getElementById('pb-panel');
    var started = false;

    document.getElementById('pb-btn').addEventListener('click', function() {
      open = !open;
      panel.classList.toggle('pb-open', open);
      if (open && !started) { started = true; initChat(); }
    });
    document.getElementById('pb-close').addEventListener('click', function() {
      open = false; panel.classList.remove('pb-open');
    });
    document.getElementById('pb-send').addEventListener('click', function() { send(input.value); });
    input.addEventListener('keypress', function(e) { if (e.key === 'Enter') send(input.value); });

    function initChat() {
      showTyping();
      setTimeout(function() {
        hideTyping();
        addMsg(config.greeting, 'bot');
      }, 800);
    }

    function addMsg(text, role) {
      var d = document.createElement('div');
      d.className = 'pb-msg pb-' + role;
      d.innerHTML = role === 'bot'
        ? '<div class="pb-av">' + config.name.charAt(0) + '</div><div class="pb-bubble">' + text + '</div>'
        : '<div class="pb-bubble">' + text + '</div>';
      msgs.appendChild(d);
      msgs.scrollTop = msgs.scrollHeight;
    }

    function showTyping() {
      var d = document.createElement('div');
      d.className = 'pb-msg pb-bot'; d.id = 'pb-typing';
      d.innerHTML = '<div class="pb-av">' + config.name.charAt(0) + '</div><div class="pb-typing"><span></span><span></span><span></span></div>';
      msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight;
    }
    function hideTyping() { var t = document.getElementById('pb-typing'); if(t) t.remove(); }

    function setChips(arr) {
      chips.innerHTML = '';
      arr.forEach(function(c) {
        var b = document.createElement('button');
        b.className = 'pb-chip'; b.textContent = c;
        b.onclick = function() { chips.innerHTML = ''; send(c); };
        chips.appendChild(b);
      });
    }

    function showLeadForm() {
      if (leadCaptured || !config.lead_capture) return;
      var wrap = document.getElementById('pb-lead-wrap');
      wrap.innerHTML = '<div id="pb-lead-form"><p>Leave your info and we\'ll follow up ✦</p>' +
        '<input id="pb-ln" placeholder="Your name" />' +
        '<input id="pb-le" placeholder="Email or phone" />' +
        '<button id="pb-lead-btn">Send →</button></div>';
      document.getElementById('pb-lead-btn').onclick = function() {
        var name = document.getElementById('pb-ln').value;
        var contact = document.getElementById('pb-le').value;
        if (!name || !contact) return;
        leadCaptured = true;
        var isEmail = contact.indexOf('@') > -1;
        fetch(base + '/api/lead/' + t, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name: name, email: isEmail ? contact : '', phone: isEmail ? '' : contact})
        });
        wrap.innerHTML = '';
        addMsg('Thanks ' + name + '! We\'ll be in touch soon. 👋', 'bot');
      };
    }

    async function send(text) {
      if (!text || !text.trim()) return;
      input.value = ''; chips.innerHTML = '';
      addMsg(text, 'user');
      history.push({role: 'user', content: text});
      showTyping();
      try {
        var res = await fetch(base + '/api/chat/' + t, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({messages: history, session_id: sessionId})
        });
        var data = await res.json();
        hideTyping();
        var reply = data.reply || 'Sorry, please try again!';
        history.push({role: 'assistant', content: reply});
        addMsg(reply, 'bot');
        if (history.filter(function(m){return m.role==='assistant';}).length >= 2) showLeadForm();
      } catch(e) {
        hideTyping();
        addMsg('Sorry, something went wrong!', 'bot');
      }
    }
  }
})();
"""
    return Response(script, mimetype='application/javascript')


# ─── EMAIL SEQUENCES ───
def send_sequence_email(to, subject, body):
    send_email(to, subject, body)

def check_email_sequences():
    db = get_db()
    users = db.execute("SELECT * FROM users WHERE plan='free' AND active=0").fetchall()
    now = datetime.datetime.utcnow()
    
    for user in users:
        created = datetime.datetime.strptime(user['created_at'], '%Y-%m-%d %H:%M:%S')
        days = (now - created).days
        email = user['email']
        name = user['name'] or 'there'
        
        # Day 1 - Welcome + setup tips
        if days == 1:
            send_sequence_email(email, 
                'Your Peekbot is ready to capture leads 🎯',
                f'''<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:2rem;">
                <h2 style="color:#7c6af7;">Hey {name}! Your bot is live.</h2>
                <p>Here's how to get your first lead in 24 hours:</p>
                <ol>
                    <li style="margin:8px 0;"><b>Customize your bot</b> — set your business name, color, and what it knows about you</li>
                    <li style="margin:8px 0;"><b>Copy your embed code</b> — paste it into your website footer</li>
                    <li style="margin:8px 0;"><b>Test it yourself</b> — visit your site and chat with it</li>
                </ol>
                <p>Login and get set up → <a href="https://peekbot.cana.chat" style="color:#7c6af7;">peekbot.cana.chat</a></p>
                <p style="color:#888;font-size:.85rem;">Questions? Just reply to this email.</p>
                </div>''')

        # Day 3 - Social proof nudge
        elif days == 3:
            send_sequence_email(email,
                'How a med spa captured 3 leads overnight with Peekbot',
                f'''<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:2rem;">
                <h2 style="color:#7c6af7;">Hey {name} 👋</h2>
                <p>A med spa in Portland added Peekbot to their site. By morning they had 3 new leads — people who were browsing at 11pm and had questions about Botox pricing.</p>
                <p>Without the bot, those leads would have bounced.</p>
                <p><b>Have you added your embed code yet?</b> It takes 2 minutes.</p>
                <p>→ <a href="https://peekbot.cana.chat" style="color:#7c6af7;">Log in and grab your embed code</a></p>
                <p style="color:#888;font-size:.85rem;">Still on the free plan — <a href="https://peekbot.cana.chat" style="color:#7c6af7;">upgrade to Pro</a> for unlimited messages + email alerts.</p>
                </div>''')

        # Day 7 - Upgrade push
        elif days == 7:
            send_sequence_email(email,
                'Your free plan expires in 23 days',
                f'''<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:2rem;">
                <h2 style="color:#7c6af7;">Hey {name},</h2>
                <p>You've been on Peekbot for a week. Here's what Pro unlocks:</p>
                <ul>
                    <li style="margin:6px 0;">✓ Unlimited messages (free plan caps at 50/mo)</li>
                    <li style="margin:6px 0;">✓ Email alert every time a lead is captured</li>
                    <li style="margin:6px 0;">✓ Full conversation history</li>
                    <li style="margin:6px 0;">✓ Priority support</li>
                </ul>
                <p>One new customer from your bot pays for 6 months of Pro.</p>
                <p>→ <a href="https://peekbot.cana.chat" style="color:#7c6af7;font-weight:bold;">Upgrade to Pro — $49/month</a></p>
                </div>''')

        # Day 14 - Need help?
        elif days == 14:
            send_sequence_email(email,
                'Need help setting up your Peekbot?',
                f'''<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:2rem;">
                <h2 style="color:#7c6af7;">Hey {name},</h2>
                <p>I noticed you haven't embedded your bot yet. I can do it for you — for free.</p>
                <p>Just reply to this email with your website URL and I'll personally install it and make sure it's working.</p>
                <p>Takes me 10 minutes. Zero cost to you.</p>
                <p style="color:#888;font-size:.85rem;">— Jackson, founder of Peekbot</p>
                </div>''')

        # Day 30 - Last chance
        elif days == 30:
            send_sequence_email(email,
                'Last email from us — still want your free bot?',
                f'''<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:2rem;">
                <h2 style="color:#7c6af7;">Hey {name},</h2>
                <p>It's been 30 days. Your free Peekbot account is still active but I want to make sure it's actually useful to you.</p>
                <p>Two options:</p>
                <p><b>1.</b> <a href="https://peekbot.cana.chat" style="color:#7c6af7;">Log in and set it up</a> — I'll personally help if you reply to this email.</p>
                <p><b>2.</b> If you're not interested anymore, just ignore this — no hard feelings.</p>
                <p style="color:#888;font-size:.85rem;">— Jackson</p>
                </div>''')

    db.close()

# Run sequence check on startup and every 12 hours
import threading

def sequence_loop():
    import time
    while True:
        try:
            check_email_sequences()
        except Exception as e:
            print(f"Sequence error: {e}")
        time.sleep(43200)  # 12 hours

sequence_thread = threading.Thread(target=sequence_loop, daemon=True)
sequence_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3005)

@app.route('/api/paypal/activate', methods=['POST'])
def activate_subscription():
    uid = verify_token(request)
    if not uid: return jsonify({'error': 'Unauthorized'}), 401
    d = request.json
    db = get_db()
    db.execute("UPDATE users SET plan='pro', active=1, paypal_sub_id=? WHERE id=?",
        (d.get('subscription_id'), uid))
    db.commit()
    db.close()
    return jsonify({'success': True})
