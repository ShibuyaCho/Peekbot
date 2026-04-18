import sqlite3, json, datetime, smtplib, urllib.request, urllib.parse, secrets, re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv('/home/jackson/OR-Compliance/.env')

app = Flask(__name__, static_folder='static')
app.secret_key = 'outreach_secret_2026'
CORS(app)

OPENAI_KEY = os.environ.get('OPENAI_API_KEY', '')
BRAVE_KEY  = os.environ.get('BRAVE_SEARCH_KEY', '')
SMTP_HOST  = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT  = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER  = os.environ.get('SMTP_USER', '')
SMTP_PASS  = os.environ.get('SMTP_PASS', '')

ADMIN_USER = 'dinofreud@gmail.com'
ADMIN_PASS = 'EleaCarson2025!'

DB = '/home/jackson/outreach.db'

CAMPAIGNS = {
    'peekbot': {
        'name': 'Peekbot — AI Chat Widget',
        'subject_prompt': 'Write a short email subject line (under 10 words) for a cold email pitching an AI chat widget called Peekbot to this business. Make it specific to their business type. No quotes.',
        'email_prompt': '''Write a short, personalized cold email pitching Peekbot to this business.

Peekbot is an AI chat widget that businesses embed on their website with one line of code. It answers questions, captures leads 24/7, and sends an email alert every time someone leaves their contact info. $49/month. Free to try at peekbot.cana.chat.

Business info: {business_info}

Rules:
- Address the owner by name if known, otherwise "Hi there"
- 3-4 short paragraphs max
- Reference something specific about their business
- End with a soft CTA asking for a 10-minute call
- Sign off as Jackson Mason with email jacksonmaverickmason@gmail.com
- Include this unsubscribe line at the bottom: "To unsubscribe reply STOP. Jackson Mason, Portland Oregon."
- Do not use subject line in the body
- Sound human, not salesy''',
    },
    'services': {
        'name': 'Web Design & AI Services',
        'subject_prompt': 'Write a short email subject line (under 10 words) for a cold email offering website redesign + AI chat services to this business. Make it specific. No quotes.',
        'email_prompt': '''Write a short, personalized cold email offering website redesign and AI chat services to this business.

Services offered by Jackson Mason (solo developer, Portland Oregon):
- Starter: $499 one-time + $49/mo — single page redesign + AI chat widget
- Standard: $999 one-time + $49/mo — up to 5 pages + SEO + AI chat
- Premium: $1,999 one-time + $49/mo — full rebuild + SEO + analytics
Portfolio and info: jackson.cana.chat

Business info: {business_info}

Rules:
- Address the owner by name if known, otherwise "Hi there"  
- 3-4 short paragraphs max
- Reference something specific about their business or website
- Mention one specific improvement that would help them
- Soft CTA for a 15-minute call
- Sign off as Jackson Mason, jacksonmaverickmason@gmail.com
- Include: "To unsubscribe reply STOP. Jackson Mason, Portland Oregon."
- Sound human, not like a template''',
    },
    'partner': {
        'name': 'Partner / Referral Program',
        'subject_prompt': 'Write a short email subject line (under 10 words) for a cold email offering a 30% recurring commission referral partnership for an AI chat widget to a web designer or agency. No quotes.',
        'email_prompt': '''Write a short, personalized cold email pitching a referral partnership to this web designer or agency.

The offer: refer clients to Peekbot (AI chat widget, $49/mo) and earn 30% recurring forever — $14.70/month per client. Or white-label it and charge more. Jackson Mason built Peekbot and handles all support/billing. Demo: peekbot.cana.chat

Business info: {business_info}

Rules:
- Address by name if known
- 3-4 short paragraphs
- Reference their design work specifically
- Focus on the passive recurring income angle
- Soft CTA for a quick call
- Sign off as Jackson Mason, jacksonmaverickmason@gmail.com  
- Include: "To unsubscribe reply STOP. Jackson Mason, Portland Oregon."
- Sound like a peer reaching out, not a sales pitch''',
    }
}

VERTICALS = {
    'med_spa': 'med spa Portland Oregon',
    'dental': 'dental office Portland Oregon',
    'hvac': 'HVAC company Portland Oregon',
    'law_firm': 'law firm Portland Oregon',
    'web_designer': 'web designer Portland Oregon freelance',
    'chiropractic': 'chiropractor Portland Oregon',
    'real_estate': 'real estate agent Portland Oregon',
    'salon': 'hair salon Portland Oregon',
    'plumbing': 'plumbing company Portland Oregon',
    'custom': '',
}

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS prospects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_name TEXT,
            website TEXT,
            email TEXT,
            owner_name TEXT,
            business_type TEXT,
            description TEXT,
            campaign TEXT,
            status TEXT DEFAULT 'pending',
            draft_subject TEXT,
            draft_email TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sent_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prospect_id INTEGER,
            campaign TEXT,
            subject TEXT,
            body TEXT,
            sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
            follow_up_due TEXT,
            status TEXT DEFAULT 'sent',
            FOREIGN KEY(prospect_id) REFERENCES prospects(id)
        );
        CREATE TABLE IF NOT EXISTS unsubscribes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    db.commit()
    db.close()

init_db()

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authed'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def brave_search(query, count=10):
    url = f'https://api.search.brave.com/res/v1/web/search?q={urllib.parse.quote(query)}&count={count}'
    req = urllib.request.Request(url, headers={
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip',
        'X-Subscription-Token': BRAVE_KEY
    })
    try:
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read())
            return data.get('web', {}).get('results', [])
    except:
        return []

def extract_email_from_text(text):
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    skip = ['example.com', 'domain.com', 'email.com', 'test.com', 'sentry.io', 'w3.org']
    for e in emails:
        if not any(s in e for s in skip):
            return e
    return None

def fetch_website_info(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            html = r.read().decode('utf-8', errors='ignore')[:8000]
        email = extract_email_from_text(html)
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text)[:2000]
        return {'text': text, 'email': email, 'url': url}
    except:
        return {'text': '', 'email': None, 'url': url}

def gpt(prompt, max_tokens=800):
    payload = json.dumps({
        'model': 'gpt-4o-mini',
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': max_tokens,
        'temperature': 0.8
    }).encode()
    req = urllib.request.Request(
        'https://api.openai.com/v1/chat/completions',
        data=payload,
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {OPENAI_KEY}'}
    )
    with urllib.request.urlopen(req) as r:
        result = json.loads(r.read())
        return result['choices'][0]['message']['content'].strip()

def send_email(to, subject, body):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f'Jackson Mason <{SMTP_USER}>'
    msg['To'] = to
    msg.attach(MIMEText(body, 'html'))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_USER, to, msg.as_string())

# ─── AUTH ───
@app.route('/admin/login', methods=['POST'])
def login():
    d = request.json
    if d.get('username') == ADMIN_USER and d.get('password') == ADMIN_PASS:
        session['authed'] = True
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/admin/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/admin/check')
def check_auth():
    return jsonify({'authed': bool(session.get('authed'))})

# ─── SEARCH ───
@app.route('/admin/api/search', methods=['POST'])
@require_auth
def search_prospects():
    d = request.json
    vertical = d.get('vertical', 'med_spa')
    campaign = d.get('campaign', 'peekbot')
    custom_query = d.get('custom_query', '')
    region = d.get('region', 'Portland Oregon')

    query = custom_query if custom_query else VERTICALS.get(vertical, '') + ' ' + region
    results = brave_search(query, count=15)

    db = get_db()
    added = 0

    for r in results:
        url = r.get('url', '')
        name = r.get('title', '').split(' - ')[0].split(' | ')[0][:80]
        desc = r.get('description', '')[:300]

        if not url or 'yelp.com' in url or 'google.com' in url or 'facebook.com' in url or 'yellowpages' in url:
            continue

        existing = db.execute('SELECT id FROM prospects WHERE website=?', (url,)).fetchone()
        if existing:
            continue

        site_data = fetch_website_info(url)
        email = site_data.get('email')

        business_info = f"Business: {name}\nWebsite: {url}\nDescription: {desc}\nSite content snippet: {site_data['text'][:500]}"

        try:
            camp = CAMPAIGNS[campaign]
            subject = gpt(camp['subject_prompt'] + f'\n\nBusiness: {name}, {desc}', max_tokens=50)
            body = gpt(camp['email_prompt'].format(business_info=business_info), max_tokens=600)
        except Exception as e:
            subject = f"Quick question about {name}"
            body = f"Hi,\n\nI came across {name} and wanted to reach out...\n\nJackson Mason"

        db.execute('''INSERT INTO prospects 
            (business_name, website, email, business_type, description, campaign, draft_subject, draft_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (name, url, email, vertical, desc, campaign, subject, body))
        added += 1

    db.commit()
    db.close()
    return jsonify({'added': added, 'query': query})

# ─── PROSPECTS ───
@app.route('/admin/api/prospects', methods=['GET'])
@require_auth
def get_prospects():
    status = request.args.get('status', 'pending')
    db = get_db()
    rows = db.execute('SELECT * FROM prospects WHERE status=? ORDER BY created_at DESC LIMIT 100', (status,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/admin/api/prospects/<int:pid>', methods=['PUT'])
@require_auth
def update_prospect(pid):
    d = request.json
    db = get_db()
    db.execute('UPDATE prospects SET email=?, owner_name=?, draft_subject=?, draft_email=?, status=? WHERE id=?',
        (d.get('email'), d.get('owner_name'), d.get('draft_subject'), d.get('draft_email'), d.get('status'), pid))
    db.commit()
    db.close()
    return jsonify({'success': True})

@app.route('/admin/api/prospects/<int:pid>/approve', methods=['POST'])
@require_auth
def approve_and_send(pid):
    db = get_db()
    p = db.execute('SELECT * FROM prospects WHERE id=?', (pid,)).fetchone()
    if not p:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    if not p['email']:
        db.close()
        return jsonify({'error': 'No email address for this prospect'}), 400

    unsub = db.execute('SELECT id FROM unsubscribes WHERE email=?', (p['email'],)).fetchone()
    if unsub:
        db.close()
        return jsonify({'error': 'Email unsubscribed'}), 400

    try:
        send_email(p['email'], p['draft_subject'], p['draft_email'])
        follow_up = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat()
        db.execute('UPDATE prospects SET status="sent" WHERE id=?', (pid,))
        db.execute('INSERT INTO sent_emails (prospect_id, campaign, subject, body, follow_up_due) VALUES (?, ?, ?, ?, ?)',
            (pid, p['campaign'], p['draft_subject'], p['draft_email'], follow_up))
        db.commit()
        db.close()
        return jsonify({'success': True})
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/prospects/<int:pid>/skip', methods=['POST'])
@require_auth
def skip_prospect(pid):
    db = get_db()
    db.execute('UPDATE prospects SET status="skipped" WHERE id=?', (pid,))
    db.commit()
    db.close()
    return jsonify({'success': True})

@app.route('/admin/api/prospects/<int:pid>/regenerate', methods=['POST'])
@require_auth
def regenerate_email(pid):
    db = get_db()
    p = db.execute('SELECT * FROM prospects WHERE id=?', (pid,)).fetchone()
    if not p:
        db.close()
        return jsonify({'error': 'Not found'}), 404
    camp = CAMPAIGNS.get(p['campaign'], CAMPAIGNS['peekbot'])
    business_info = f"Business: {p['business_name']}\nWebsite: {p['website']}\nDescription: {p['description']}"
    try:
        subject = gpt(camp['subject_prompt'] + f'\n\nBusiness: {p["business_name"]}', max_tokens=50)
        body = gpt(camp['email_prompt'].format(business_info=business_info), max_tokens=600)
        db.execute('UPDATE prospects SET draft_subject=?, draft_email=? WHERE id=?', (subject, body, pid))
        db.commit()
        db.close()
        return jsonify({'subject': subject, 'body': body})
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

# ─── SENT / STATS ───
@app.route('/admin/api/sent', methods=['GET'])
@require_auth
def get_sent():
    db = get_db()
    rows = db.execute('''SELECT s.*, p.business_name, p.website, p.email 
                         FROM sent_emails s JOIN prospects p ON s.prospect_id=p.id
                         ORDER BY s.sent_at DESC LIMIT 100''').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/admin/api/stats', methods=['GET'])
@require_auth
def get_stats():
    db = get_db()
    total = db.execute('SELECT COUNT(*) as c FROM prospects').fetchone()['c']
    pending = db.execute("SELECT COUNT(*) as c FROM prospects WHERE status='pending'").fetchone()['c']
    sent = db.execute("SELECT COUNT(*) as c FROM sent_emails").fetchone()['c']
    skipped = db.execute("SELECT COUNT(*) as c FROM prospects WHERE status='skipped'").fetchone()['c']
    followups = db.execute("SELECT COUNT(*) as c FROM sent_emails WHERE follow_up_due <= ?",
        (datetime.datetime.utcnow().isoformat(),)).fetchone()['c']
    db.close()
    return jsonify({'total': total, 'pending': pending, 'sent': sent, 'skipped': skipped, 'followups_due': followups})

# ─── UNSUBSCRIBE ───
@app.route('/unsubscribe')
def unsubscribe():
    email = request.args.get('email', '')
    if email:
        db = get_db()
        try:
            db.execute('INSERT OR IGNORE INTO unsubscribes (email) VALUES (?)', (email,))
            db.commit()
        except: pass
        db.close()
    return '<h2 style="font-family:sans-serif;text-align:center;padding:3rem;">You have been unsubscribed. You will receive no further emails.</h2>'

# ─── SERVE ADMIN ───
@app.route('/admin')
@app.route('/admin/')
def admin():
    return send_from_directory('static', 'admin.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3006)
