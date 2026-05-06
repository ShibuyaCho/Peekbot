from flask import Flask, request, jsonify, send_from_directory, Response, make_response, redirect
from flask_cors import CORS
import sqlite3, hashlib, hmac as _hmac, jwt, json, datetime, smtplib
import urllib.request, urllib.parse, os, secrets, base64, time, csv, io, re, bcrypt
import threading
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

DB         = '/home/jackson/peekbot.db'
UPLOAD_DIR = os.path.expanduser('~/Peekbot/uploads')
DOCS_DIR   = os.path.expanduser('~/Peekbot/documents')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)
ALLOWED_EXT = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg'}
FREE_MSG_LIMIT     = 10
AUTO_SYNC_INTERVAL = 7200

_rate = defaultdict(list)

def rate_ok(key, limit=20):
    now = time.time()
    _rate[key] = [t for t in _rate[key] if now - t < 60]
    if len(_rate[key]) >= limit: return False
    _rate[key].append(now); return True

def hash_pw(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pw(pw, stored):
    try:
        if stored.startswith('$2b$') or stored.startswith('$2a$'):
            return bcrypt.checkpw(pw.encode(), stored.encode())
        return secrets.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)
    except: return False

def get_db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL,
            qb_realm_id TEXT, qb_access_token TEXT, qb_refresh_token TEXT, qb_token_expires_at TEXT,
            commission_currency TEXT DEFAULT 'USD', created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
            name TEXT, plan TEXT DEFAULT 'free', org_id INTEGER, role TEXT DEFAULT 'agent',
            stripe_customer_id TEXT, stripe_sub_id TEXT, active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL, token TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT 'Assistant', greeting TEXT DEFAULT 'Hi! How can I help you today?',
            system_prompt TEXT DEFAULT 'You are a helpful assistant.', color TEXT DEFAULT '#7c6af7',
            avatar TEXT DEFAULT '', lead_capture INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bot_id INTEGER NOT NULL, session_id TEXT NOT NULL,
            role TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bot_id INTEGER NOT NULL, name TEXT, email TEXT,
            phone TEXT, notes TEXT, status TEXT DEFAULT 'new', assigned_to INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL, deal_name TEXT,
            property_address TEXT, buyer_name TEXT, buyer_email TEXT, seller_name TEXT, seller_email TEXT,
            purchase_price REAL, earnest_money REAL, closing_date TEXT, commission_amount REAL,
            deal_status TEXT DEFAULT 'lead', qb_invoice_id TEXT, contract_id TEXT, notes TEXT,
            source TEXT DEFAULT 'manual', session_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS deal_commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, deal_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            commission_amount REAL, commission_status TEXT DEFAULT 'pending', qb_bill_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, deal_id INTEGER NOT NULL, contract_type TEXT,
            pdf_path TEXT, status TEXT DEFAULT 'draft', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL, email TEXT NOT NULL,
            role TEXT DEFAULT 'agent', token TEXT UNIQUE NOT NULL, accepted INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS contract_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL, name TEXT NOT NULL,
            description TEXT, file_path TEXT, file_type TEXT, category TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS knowledge_base (
            id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL, content TEXT NOT NULL,
            source TEXT, source_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS generated_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL, doc_type TEXT, title TEXT,
            data_json TEXT, file_path TEXT, status TEXT DEFAULT 'draft', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS data_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT, bot_id INTEGER NOT NULL, source_type TEXT, name TEXT, url TEXT,
            instagram_handle TEXT, api_key TEXT, sync_status TEXT DEFAULT 'pending', item_count INTEGER DEFAULT 0,
            last_synced TEXT, last_error TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    for table, col, typedef in [
        ('leads','status','TEXT DEFAULT "new"'),('knowledge_base','source_id','INTEGER'),
        ('data_sources','item_count','INTEGER DEFAULT 0'),('data_sources','last_error','TEXT'),
        ('users','stripe_customer_id','TEXT'),('users','stripe_sub_id','TEXT'),
        ('deals','notes','TEXT'),('deals','deal_status','TEXT DEFAULT "lead"'),
        ('deals','source','TEXT DEFAULT "manual"'),('deals','session_id','TEXT'),
        ('deals','industry','TEXT'),('deals','deal_type','TEXT'),
        ('deals','jurisdiction','TEXT'),('deals','payment_terms','TEXT'),
        ('deals','contract_requirements','TEXT'),
    ]:
        try: db.execute(f'ALTER TABLE {table} ADD COLUMN {col} {typedef}'); db.commit()
        except: pass
    db.commit(); db.close()

init_db()

def make_token(user_id, email):
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    return jwt.encode({'user_id':user_id,'email':email,'exp':exp}, SECRET, algorithm='HS256')

def verify_token(req):
    auth = req.headers.get('Authorization','')
    if not auth.startswith('Bearer '): return None
    try: return jwt.decode(auth[7:], SECRET, algorithms=['HS256'])['user_id']
    except: return None

def get_user(uid, db): return db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
def _v(d, key, existing):
    """Return d[key] if present and non-None, else keep existing value."""
    return d[key] if key in d and d[key] is not None else existing
def get_org_bot(org_id, db): return db.execute('SELECT * FROM bots WHERE org_id=? ORDER BY id LIMIT 1',(org_id,)).fetchone()

def _contract_to_pdf(text, fp):
    """Render a contract with legal-grade formatting: centered title, ARTICLE headings,
    numbered subsections, justified body, WHEREAS recitals, and signature block."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
    import re as _re

    def _esc(s):
        return s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    def _fmt(s):
        e = _esc(s)
        e = _re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', e)
        e = _re.sub(r'__(.*?)__', r'<b>\1</b>', e)
        return e
    def _strip_md(s): return s  # unused, kept for safety

    title_st  = ParagraphStyle('ct',  fontName='Helvetica-Bold', fontSize=14, alignment=TA_CENTER,  spaceBefore=0, spaceAfter=4,  leading=18)
    sub_st    = ParagraphStyle('cs',  fontName='Helvetica',      fontSize=10, alignment=TA_CENTER,  spaceBefore=0, spaceAfter=18, leading=13)
    art_st    = ParagraphStyle('ca',  fontName='Helvetica-Bold', fontSize=11, alignment=TA_LEFT,    spaceBefore=16, spaceAfter=4,  leading=14)
    sec_st    = ParagraphStyle('sec', fontName='Helvetica-Bold', fontSize=10, alignment=TA_LEFT,    spaceBefore=8,  spaceAfter=2,  leading=13, leftIndent=0)
    body_st   = ParagraphStyle('cb',  fontName='Helvetica',      fontSize=10, alignment=TA_JUSTIFY, spaceBefore=2,  spaceAfter=3,  leading=14)
    recit_st  = ParagraphStyle('cr',  fontName='Helvetica',      fontSize=10, alignment=TA_JUSTIFY, spaceBefore=4,  spaceAfter=4,  leading=14, leftIndent=18, rightIndent=18)
    sig_st    = ParagraphStyle('sig', fontName='Helvetica',      fontSize=10, alignment=TA_LEFT,    spaceBefore=4,  spaceAfter=4,  leading=22)

    def _page_num(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColorRGB(0.55, 0.55, 0.55)
        canvas.drawCentredString(letter[0]/2, 0.55*inch, f'Page {doc.page}')
        canvas.restoreState()

    doc = SimpleDocTemplate(fp, pagesize=letter,
        topMargin=1.1*inch, bottomMargin=0.85*inch, leftMargin=1.25*inch, rightMargin=1.25*inch)

    story = []
    lines = text.split('\n')
    title_found = False
    in_sig = False

    for line in lines:
        raw = line.strip()
        if not raw:
            story.append(Spacer(1, 5))
            continue
        # clean = plain text for pattern matching; e = HTML-safe with bold tags for rendering
        clean = _re.sub(r'\*\*(.*?)\*\*', r'\1', _re.sub(r'__(.*?)__', r'\1', raw))
        e = _fmt(raw)

        # horizontal rule
        if _re.fullmatch(r'[-_*]{3,}', raw):
            story.append(Spacer(1,6)); story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#cccccc'))); story.append(Spacer(1,6))
            continue

        # Document title: first substantive line that is ALL CAPS and short
        if not title_found and _re.fullmatch(r'[A-Z][A-Z0-9 ,\(\)\-\/\&]{5,}', clean):
            story.append(Paragraph(e, title_st)); title_found=True; continue

        # "This [Contract Type] Agreement ("Agreement") is entered into as of..."  → subtitle/intro
        if _re.match(r'^This .{3,60}(?:Agreement|Contract|Note|Lease)\b', clean) and not in_sig:
            story.append(Paragraph(e, sub_st)); continue

        # ARTICLE X. / ARTICLE X: headings
        if _re.match(r'^ARTICLE\s+\d+[\.\:\s]', clean, _re.IGNORECASE):
            story.append(Paragraph(e.upper(), art_st)); in_sig=False; continue

        # Numbered subsections: "1.1 Heading." or "1.1."
        if _re.match(r'^\d+\.\d+[\s\.]', clean):
            story.append(Paragraph(f'<b>{e}</b>', sec_st)); continue

        # Single numbered sections when no ARTICLE style: "1. Definitions"
        if _re.match(r'^\d+\.\s+[A-Z]', clean) and len(clean) < 80:
            story.append(Paragraph(f'<b>{e}</b>', art_st)); continue

        # WHEREAS / NOW, THEREFORE recitals
        if _re.match(r'^(WHEREAS|NOW,?\s+THEREFORE)', clean):
            story.append(Paragraph(e, recit_st)); continue

        # RECITALS / DEFINITIONS / GENERAL PROVISIONS stand-alone headings
        if _re.fullmatch(r'[A-Z][A-Z\s]{3,40}', clean) and len(clean.split()) <= 5:
            story.append(Paragraph(e, art_st)); continue

        # Signature block
        if 'IN WITNESS WHEREOF' in clean.upper():
            in_sig = True
            story.append(Spacer(1,16))
            story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#cccccc')))
            story.append(Spacer(1,8))
            story.append(Paragraph(f'<b>{e}</b>', body_st)); continue

        if in_sig:
            story.append(Paragraph(e, sig_st)); continue

        story.append(Paragraph(e, body_st))

    if not story:
        story.append(Paragraph('(empty)', body_st))
    doc.build(story, onFirstPage=_page_num, onLaterPages=_page_num)

# keep alias for any legacy callers
_text_to_pdf = _contract_to_pdf

def _build_contract_prompt(suggestion, deal, transcript=''):
    """Return (system_msg, user_msg) for a legal-grade contract."""
    dd = deal if isinstance(deal, dict) else dict(deal)
    clauses_str = '\n'.join(f'  {i+1}. {c}' for i, c in enumerate(suggestion['clauses']))
    jurisdiction = dd.get('jurisdiction') or 'State of Oregon'
    today = datetime.datetime.now().strftime('%B %d, %Y')

    party_a = dd.get('seller_name') or dd.get('buyer_name') or '[PARTY A]'
    party_b = dd.get('buyer_name') if dd.get('seller_name') else '[PARTY B]'
    price_str = ('$' + '{:,.2f}'.format(float(dd['purchase_price']))) if dd.get('purchase_price') else '[CONSIDERATION AMOUNT]'

    system = (
        "You are a senior transactional attorney with 25 years of experience drafting "
        "commercial, real estate, employment, and regulatory contracts. "
        "You write complete, court-ready agreements with precise legal language, "
        "defined terms, enumerated obligations, and standard boilerplate. "
        "You always follow this structure:\n"
        "1. Document title in ALL CAPS (centered)\n"
        "2. Opening clause: 'This [Type] Agreement (\"Agreement\") is entered into as of [DATE]...'\n"
        "3. RECITALS section with WHEREAS clauses\n"
        "4. NOW, THEREFORE paragraph bridging recitals to operative terms\n"
        "5. ARTICLE 1. DEFINITIONS — define every capitalized term used\n"
        "6. Numbered ARTICLES for each major section (ARTICLE 2., ARTICLE 3., etc.)\n"
        "7. Subsections numbered 1.1, 1.2, 2.1, 2.2, etc. with bold lead-in terms\n"
        "8. ARTICLE on GENERAL PROVISIONS last — includes: Entire Agreement, Amendments, "
        "Severability, Waiver, Force Majeure, Counterparts, Electronic Signatures, "
        "Attorneys' Fees, Governing Law, Dispute Resolution\n"
        "9. IN WITNESS WHEREOF signature block for each party with: full name, title, date, signature line\n"
        "Use [BRACKETED PLACEHOLDERS] only for information not provided. "
        "Write every clause completely — never abbreviate or say 'as standard'. "
        "Do NOT include markdown headers (#, ##) or bullet points. Use plain text only."
    )

    user = f"""Draft a complete, legally enforceable {suggestion['label']} for the following deal.

PARTIES AND DEAL INFORMATION:
  Deal: {dd.get('deal_name') or 'N/A'}
  Industry: {dd.get('industry') or 'N/A'}
  Deal Type: {dd.get('deal_type') or 'N/A'}
  Property / Subject Matter: {dd.get('property_address') or 'N/A'}
  Party A (Seller/Provider): {party_a}{(' (' + dd['seller_email'] + ')') if dd.get('seller_email') else ''}
  Party B (Buyer/Client): {party_b}{(' (' + dd.get('buyer_email','') + ')') if dd.get('buyer_email') else ''}
  Consideration / Price: {price_str}
  Deposit / Earnest Money: {'$' + str(dd['earnest_money']) if dd.get('earnest_money') else 'N/A'}
  Closing / Completion Date: {dd.get('closing_date') or '[TO BE DETERMINED]'}
  Governing Jurisdiction: {jurisdiction}
  Payment Terms: {dd.get('payment_terms') or 'Net 30'}
  Special Requirements: {dd.get('contract_requirements') or 'None'}
  Additional Notes: {dd.get('notes') or 'None'}
  Date of Agreement: {today}
{('  Chat Context:\n' + transcript[:1200]) if transcript else ''}

REQUIRED SECTIONS — every numbered item below MUST appear as a fully drafted article or subsection:
{clauses_str}

MANDATORY BOILERPLATE (include in GENERAL PROVISIONS article):
  - Entire Agreement and Integration
  - Amendments Must Be in Writing
  - Severability
  - No Waiver
  - Force Majeure
  - Counterparts and Electronic Signatures
  - Attorneys' Fees
  - Governing Law: {jurisdiction}
  - Dispute Resolution (mediation then binding arbitration or litigation — specify)
  - Notices (addresses and method)

Write the complete contract now. Every section must be fully drafted — no abbreviations, no "standard terms apply." Use [BRACKETED PLACEHOLDERS] for any missing party-specific information."""

    return system, user

def _invoice_to_pdf(fp, inv_num, date_str, due_date, from_name, client_name, client_email, description, amount, tax_rate, total, terms):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as rc
    cv = rc.Canvas(fp, pagesize=letter)
    w, h = letter; m = 72
    cv.setFillColorRGB(0.49,0.42,0.97); cv.rect(0,h-90,w,90,fill=True,stroke=False)
    cv.setFillColorRGB(1,1,1); cv.setFont('Helvetica-Bold',32); cv.drawString(m,h-58,'INVOICE')
    cv.setFont('Helvetica',10)
    cv.drawRightString(w-m,h-35,f'Invoice #{inv_num}')
    cv.drawRightString(w-m,h-52,f'Date: {date_str}')
    if due_date: cv.drawRightString(w-m,h-69,f'Due: {due_date}')
    y=h-130; cv.setFillColorRGB(0.1,0.1,0.1)
    cv.setFont('Helvetica-Bold',9); cv.drawString(m,y,'FROM'); cv.drawString(m+220,y,'BILL TO')
    y-=16; cv.setFont('Helvetica',10)
    cv.drawString(m,y,from_name or ''); cv.drawString(m+220,y,client_name or '')
    y-=14
    if client_email: cv.drawString(m+220,y,client_email)
    y-=40; cv.setFillColorRGB(0.95,0.95,0.95); cv.rect(m,y-20,w-2*m,24,fill=True,stroke=False)
    cv.setFillColorRGB(0.1,0.1,0.1); cv.setFont('Helvetica-Bold',9)
    cv.drawString(m+8,y-12,'DESCRIPTION'); cv.drawRightString(w-m-8,y-12,'AMOUNT'); y-=40
    cv.setFont('Helvetica',10); words=(description or '').split(); line=''
    for word in words:
        test=(line+' '+word).strip()
        if cv.stringWidth(test,'Helvetica',10)>w-2*m-90:
            if line: cv.drawString(m+8,y,line); y-=14; line=word
            else: cv.drawString(m+8,y,word); y-=14
        else: line=test
    if line: cv.drawString(m+8,y,line); y-=14
    cv.drawRightString(w-m,y+14,f'${amount:.2f}')
    y-=20; cv.setStrokeColorRGB(0.8,0.8,0.8); cv.line(m,y,w-m,y); y-=16
    cv.setFont('Helvetica',10); cv.setFillColorRGB(0.1,0.1,0.1)
    cv.drawString(w-m-180,y,'Subtotal:'); cv.drawRightString(w-m,y,f'${amount:.2f}'); y-=14
    tax_amt=amount*tax_rate/100
    cv.drawString(w-m-180,y,f'Tax ({tax_rate:.0f}%):'); cv.drawRightString(w-m,y,f'${tax_amt:.2f}'); y-=14
    cv.line(w-m-180,y,w-m,y); y-=16
    cv.setFont('Helvetica-Bold',12); cv.setFillColorRGB(0.49,0.42,0.97)
    cv.drawString(w-m-180,y,'TOTAL DUE:'); cv.drawRightString(w-m,y,f'${total:.2f}'); y-=40
    cv.setFillColorRGB(0.5,0.5,0.5); cv.setFont('Helvetica',9); cv.drawString(m,y,f'Terms: {terms}')
    cv.save()

CONTRACT_LIBRARY = {
    'real_estate': {
        'label': 'Real Estate',
        'types': {
            'purchase_agreement': {
                'label': 'Residential Purchase Agreement',
                'description': 'Home or land purchase contract',
                'clauses': ['Full legal names and addresses of all parties','Complete property legal description, address, and APN','Purchase price, financing method, and down payment amount','Earnest money deposit amount, escrow holder, and forfeiture conditions','Inspection contingency period, scope, and resolution process','Financing contingency with loan type, amount, interest rate cap, and deadline','Appraisal contingency and low-appraisal gap terms','Title insurance requirement (ALTA/CLTA) and clear title delivery','Closing date, escrow agent, and time-is-of-the-essence provision','Possession date, pro-rations, and daily holdover rate','Closing cost allocations between buyer and seller','Included and excluded personal property, fixtures, and appliances','Property condition disclosure and AS-IS or repair obligation terms','HOA existence, transfer fee, and document delivery if applicable','Lead paint, natural hazard, and all required statutory disclosures','Default remedies for buyer and seller (liquidated damages)','Dispute resolution, mediation, and arbitration clause','Entire agreement clause, amendment process, and governing law','Notarized signature blocks with date and acknowledgment'],
            },
            'commercial_purchase': {
                'label': 'Commercial Purchase Agreement',
                'description': 'Commercial, investment, or multi-family property',
                'clauses': ['Entity names, state of formation, and authorized signatories','Property legal description, zoning classification, and permitted uses','Purchase price, allocation, and financing structure','Due diligence period (30–90 days), scope, and termination rights','Environmental assessment (Phase I/II) contingency','Tenant estoppels, SNDA agreements, and rent roll review','Financial statement and operating history review','Title insurance (extended ALTA) and survey requirements','Prorations for rent, taxes, deposits, and operating expenses','Lease assignment and assumption terms','Seller representations and warranties','Indemnification provisions and survival period','Default remedies and liquidated damages','Closing conditions and cost allocations','Post-closing obligations'],
            },
            'lease_agreement': {
                'label': 'Lease Agreement',
                'description': 'Residential or commercial property lease',
                'clauses': ['Full names and addresses of landlord and all tenants','Complete premises description including unit, building, and parking','Lease commencement and termination dates','Monthly rent amount, due date, grace period, and late fee amount','Security deposit amount, permitted uses, and return timeline','Utility responsibilities for each party','Maintenance and repair obligations','Tenant alteration and improvement policy with restoration requirement','Subletting and assignment restrictions','Landlord right of entry with required notice period','Pet policy, restrictions, and pet deposit','Authorized occupants and occupancy limits','Prohibited uses and nuisance clause','Renter\'s insurance requirement and minimum coverage','Default, cure period, and eviction procedures','Lease renewal options and rent increase terms','Move-out inspection process and condition standards','Governing law and jurisdiction'],
            },
            'listing_agreement': {
                'label': 'Listing Agreement',
                'description': 'Seller representation / listing contract',
                'clauses': ['Broker and agent identification with license numbers','Seller identification and property legal description','Listing price and authorization to market','Listing term, start date, and expiration date','Listing type (exclusive right to sell)','Commission rate and cooperating broker split','MLS participation authorization and marketing plan','Seller disclosure obligations','Lockbox and showing authorization','Dual agency disclosure and consent','Protection/carryover clause after expiration','Cancellation conditions and process'],
            },
            'commission_agreement': {
                'label': 'Commission Split Agreement',
                'description': 'Agent or broker commission division',
                'clauses': ['Parties: brokerage, lead agent, and co-agent or referral agent','Property or deal identification','Gross commission amount and percentage','Commission split percentage for each party','Payment trigger (closing date) and disbursement method','Conditions that void or reduce commission','Referral fee terms if applicable','Applicable brokerage policy acknowledgment','Signatures and effective date'],
            },
        }
    },
    'services': {
        'label': 'Services & Consulting',
        'types': {
            'service_agreement': {
                'label': 'Service Agreement',
                'description': 'General or professional services contract',
                'clauses': ['Full legal names and addresses of provider and client','Detailed scope of services and deliverables','Project timeline, milestones, and completion date','Compensation: rate, total, payment schedule, and invoicing terms','Late payment interest rate and collection rights','Change order process for scope modifications','Client responsibilities and required access or resources','Intellectual property ownership of all work product','Confidentiality and non-disclosure obligations','Non-solicitation of employees and clients','Independent contractor status (not employee)','Limitation of liability cap and mutual indemnification','Insurance requirements (GL, E&O)','Termination for convenience (30-day notice) and for cause','Dispute resolution and governing law','Entire agreement and amendment clause'],
            },
            'consulting_agreement': {
                'label': 'Consulting Agreement',
                'description': 'Business or management consulting engagement',
                'clauses': ['Consultant identification, firm, and qualifications','Consulting scope and specific advisory deliverables','Engagement term and renewal options','Retainer or hourly rate and expense reimbursement policy','Reporting cadence and deliverable format','Access to confidential company information','Conflicts of interest disclosure and ongoing restrictions','Non-compete scope, geography, and duration','Confidentiality and trade secret protection','Work product ownership and license-back rights','Independent contractor tax responsibility (1099)','Termination notice period and wind-down obligations','Indemnification for consultant acts or omissions'],
            },
            'saas_agreement': {
                'label': 'Software / SaaS Agreement',
                'description': 'Software-as-a-service or software license',
                'clauses': ['Parties and authorized user count','License grant, scope, and permitted use restrictions','Subscription term, auto-renewal terms, and cancellation notice','Fees, payment terms, and annual price adjustment rights','Service level agreement (uptime %) and downtime credits','Data privacy, security standards, and breach notification','GDPR / CCPA compliance obligations','Customer data ownership and portability rights','IP ownership: platform vs. customer data','Acceptable use policy and prohibited uses','Suspension rights for non-payment or policy violation','Limitation of liability cap (12 months of fees)','Disclaimer of warranties (AS-IS, no implied warranties)','IP indemnification for infringement claims','Termination, data export window, and deletion obligations','Governing law and venue'],
            },
        }
    },
    'employment': {
        'label': 'Employment & HR',
        'types': {
            'offer_letter': {
                'label': 'Employment Offer Letter',
                'description': 'Formal job offer with employment terms',
                'clauses': ['Position title, department, and direct manager','Start date, work location, and schedule (on-site/remote/hybrid)','Base salary or hourly rate and pay frequency','Bonus structure, target, and eligibility conditions','Equity or stock option grant if applicable','Benefits enrollment: health, dental, vision, 401k, and effective dates','PTO accrual, sick leave, and paid holiday schedule','At-will employment statement and termination rights','Background check and drug screening contingency','I-9 work authorization requirement','Reference to confidentiality and IP assignment agreement','Non-solicitation obligations during and after employment','Offer expiration date and acceptance instructions'],
            },
            'independent_contractor': {
                'label': 'Independent Contractor Agreement',
                'description': '1099 contractor or freelancer agreement',
                'clauses': ['Contractor and client full legal names and addresses','Detailed services description and project deliverables','Payment rate (hourly/fixed), invoicing schedule, and net payment terms','Expense reimbursement policy and pre-approval requirement','Independent contractor classification and IRS factor acknowledgment','No benefits, no withholding, self-employment tax responsibility','Contractor\'s right to control means and methods of work','Right to work for other clients without restriction','Equipment, workspace, and tools provision','Intellectual property assignment to client upon payment','Confidentiality and non-disclosure obligations','Term, project completion, and termination with notice period','Indemnification for contractor\'s acts, errors, or omissions'],
            },
            'nda': {
                'label': 'Non-Disclosure Agreement (NDA)',
                'description': 'Confidentiality agreement protecting proprietary information',
                'clauses': ['Parties and the purpose of their relationship','Definition of Confidential Information (broad and specific)','Explicit exclusions from confidential information','Receiving party\'s obligations of care and non-disclosure','Permitted disclosures to employees, advisors, or legal counsel','Non-use obligation beyond the stated purpose','Term of the confidentiality obligation post-disclosure','Return or certified destruction of confidential materials','Right to seek injunctive relief for irreparable harm','No license grant implied by disclosure','Mutual vs. one-way designation','Governing law and venue'],
            },
        }
    },
    'construction': {
        'label': 'Construction & Contracting',
        'types': {
            'general_contractor': {
                'label': 'General Contractor Agreement',
                'description': 'Owner-to-GC construction project contract',
                'clauses': ['Owner and contractor identification with contractor license number','Project description, scope, and site address','Contract documents: plans, specifications, and incorporated exhibits','Contract price: fixed-sum, cost-plus, or GMP with contingency','Draw schedule tied to construction milestones','Retainage percentage (typically 10%) and release conditions','Project schedule, substantial completion date, and punch list process','Liquidated damages for schedule delay','Change order process, pricing, and authorization thresholds','Subcontractor and material supplier approval rights','Contractor insurance requirements: GL, workers comp, builders risk','Lien waiver delivery requirements (conditional and unconditional)','OSHA and site safety compliance obligations','One-year workmanship warranty','Substantial completion, final completion, and acceptance process','Permit responsibility and code compliance','Dispute resolution and mechanics lien rights','Termination for default and for convenience'],
            },
            'subcontractor': {
                'label': 'Subcontractor Agreement',
                'description': 'GC-to-sub scope-of-work agreement',
                'clauses': ['GC and subcontractor identification with license numbers','Detailed subcontract scope of work','Subcontract price and unit rates','Pay-when-paid or pay-if-paid clause with timing','Project schedule compliance and coordination obligations','Insurance requirements matching or exceeding prime contract','Flow-down provisions incorporating prime contract obligations','Lien waiver delivery prior to each payment','Back-charge rights and process','Defective work correction obligations','Termination for default with cure period','Governing law and dispute resolution'],
            },
        }
    },
    'business': {
        'label': 'Business & M&A',
        'types': {
            'letter_of_intent': {
                'label': 'Letter of Intent (LOI)',
                'description': 'Preliminary non-binding M&A or business acquisition agreement',
                'clauses': ['Buyer and seller entity identification','Business description and what is being acquired (assets vs. stock)','Proposed purchase price range and payment structure','Earnest or good-faith deposit amount and conditions','Due diligence period, scope, and access rights','Exclusivity/no-shop period duration','Key conditions to closing','Explicitly binding provisions (confidentiality, exclusivity, break-up fee)','Non-binding nature of all other terms','Target closing timeline','Expiration date and extension rights'],
            },
            'asset_purchase': {
                'label': 'Asset Purchase Agreement',
                'description': 'Business asset acquisition and transfer',
                'clauses': ['Buyer and seller entity identification and authorization','Purchased assets schedule (tangible, intangible, IP)','Excluded assets and retained liabilities','Assumed liabilities schedule','Purchase price and payment terms','Purchase price allocation per IRS Form 8594','Working capital target, measurement, and adjustment mechanism','Seller representations and warranties (operational, financial, legal)','Buyer representations and warranties','Indemnification obligations, baskets, caps, and survival period','Closing conditions: material adverse change, consents, regulatory','Employee offers, WARN Act compliance, and benefit plan treatment','Seller non-compete and non-solicitation (scope and duration)','Transition services agreement terms','Closing deliverables checklist','Governing law and dispute resolution'],
            },
            'operating_agreement': {
                'label': 'LLC Operating Agreement',
                'description': 'LLC membership and governance structure',
                'clauses': ['Member names, addresses, and ownership percentages','Business name, purpose, and formation state','Initial capital contributions and future contribution obligations','Profit and loss allocation percentages','Distribution priority, timing, and restrictions','Management structure: member-managed or manager-managed','Manager appointment, authority, and removal','Voting rights and required majority thresholds','Admission of new members and dilution process','Transfer restrictions and right of first refusal','Buy-sell provisions triggering events (death, disability, withdrawal, deadlock)','Buy-sell valuation methodology','Non-compete obligations of members','Books, records, and audit rights','Tax elections (S-corp, fiscal year) and allocations','Dissolution triggers and winding-up procedures'],
            },
        }
    },
    'cannabis': {
        'label': 'Cannabis / OLCC',
        'types': {
            'production_agreement': {
                'label': 'Producer / Processor Agreement',
                'description': 'Oregon cannabis production or processing contract',
                'clauses': ['OLCC license numbers and license types for all parties','Compliance acknowledgment: ORS 475C and OAR 845-025','Product specifications: strain, form, and target cannabinoid profile','Production volume commitments and delivery schedule','Pricing, payment terms, and price adjustment mechanism','Metrc tracking tag requirements for all plant material and transfers','Certificate of Analysis (COA) delivery requirement per batch','Approved testing laboratory and required test panels','Pesticide compliance and prohibited substance list acknowledgment','Packaging and labeling standards per current OLCC rules','Product recall and remediation procedures','Quality control inspection rights','License suspension or revocation automatic termination clause','Confidentiality of proprietary genetics and cultivation methods','Dispute resolution under Oregon law'],
            },
            'distribution_agreement': {
                'label': 'Cannabis Distribution Agreement',
                'description': 'Wholesale cannabis distribution between licensees',
                'clauses': ['OLCC license numbers and license types (producer, processor, wholesaler, retailer)','Territory definition and exclusivity terms','Product catalog, pricing schedule, and minimum order quantities','Minimum purchase commitments and take-or-pay provisions','Metrc manifest compliance for all wholesale transfers','COA delivery requirement with each shipment','Payment terms and accepted payment methods','Returns, damaged goods, and failed-test product policy','Promotional and marketing cooperation obligations','License compliance ongoing representations and warranties','Termination upon license suspension, revocation, or expiration','No assignment without regulatory approval','Governing law: State of Oregon, Marion County venue'],
            },
            'services_agreement': {
                'label': 'Cannabis Services Agreement',
                'description': 'Technology, consulting, or management services for licensees',
                'clauses': ['OLCC licensee identification and license number','Services scope (technology, consulting, marketing, staffing)','No management contract structure acknowledgment (OAR 845-025-7580)','Service fees, payment terms, and expense reimbursement','Compliance advisory scope and limitations (not legal advice)','Confidentiality of customer data, sales data, and financial records','Data security, access controls, and breach notification','Background check compliance for all service personnel','Term, renewal, and termination with notice period','Limitation of liability for regulatory outcomes','Oregon governing law'],
            },
        }
    },
    'finance': {
        'label': 'Finance & Lending',
        'types': {
            'promissory_note': {
                'label': 'Promissory Note',
                'description': 'Loan or debt instrument',
                'clauses': ['Borrower and lender full legal names and addresses','Principal loan amount in words and figures','Interest rate (fixed or variable), calculation method (simple/compound), and basis (365/360)','Payment schedule: amount, frequency, due date, and first payment date','Maturity date and balloon payment if applicable','Prepayment rights and any prepayment penalty schedule','Default: definition, cure period, and automatic acceleration','Late payment penalty amount or percentage','Collateral description and security agreement reference if secured','Guarantor obligations and guarantee terms if applicable','Usury law compliance acknowledgment','Waiver of presentment, demand, protest, and notice of dishonor','Governing law and venue','Attorney fees clause for collection'],
            },
            'loan_agreement': {
                'label': 'Loan Agreement',
                'description': 'Comprehensive lending agreement with covenants',
                'clauses': ['Lender and borrower identification','Loan amount, purpose, and disbursement conditions','Interest rate, default rate, and calculation','Repayment schedule and amortization','Conditions precedent to funding','Financial covenants (DSCR, LTV, working capital minimums)','Affirmative covenants (financial reporting, insurance, taxes)','Negative covenants (no additional debt, no asset sale, no liens)','Events of default and cross-default provisions','Remedies and acceleration rights','Collateral, lien priority, and security agreement','Guaranty requirements','Loan fee schedule','Governing law and jurisdiction'],
            },
        }
    },
    'licensing': {
        'label': 'Licensing & IP',
        'types': {
            'ip_license': {
                'label': 'IP License Agreement',
                'description': 'Intellectual property license or brand license',
                'clauses': ['Licensor and licensee full legal identification','IP description: trademark registrations, patent numbers, copyrighted works, or trade secrets','License grant: exclusive or non-exclusive, field of use, and territory','Sublicense rights and restrictions','Royalty rate, minimum annual guarantee, and payment frequency','Royalty reporting timeline and format','Audit rights and under-reporting penalties','Quality standards, approval rights, and style guide compliance','IP ownership: licensor retains all rights; improvements ownership','Sublicense restrictions and flow-down requirements','Infringement notification obligation and enforcement cooperation','Term, renewal conditions, and renewal royalty adjustments','Termination for breach, insolvency, or IP challenge','Post-termination sell-off period and obligations','Governing law and venue'],
            },
        }
    },
    'other': {
        'label': 'General / Other',
        'types': {
            'general_agreement': {
                'label': 'General Agreement',
                'description': 'Custom agreement for any industry or situation',
                'clauses': ['Full legal identification of all parties with addresses','Recitals describing the background, relationship, and purpose','Definitions section for all key terms used','Core obligations of each party stated clearly','Consideration and compensation terms','Term, commencement, and expiration with renewal options','Representations and warranties by each party','Confidentiality and non-disclosure obligations','Limitation of liability and indemnification','Force majeure clause','Amendment process and waiver requirements','Severability of provisions','Entire agreement and integration clause','Counterparts and electronic signature acceptance','Governing law, venue, and dispute resolution process','Signature blocks with printed name, title, and date'],
            },
        }
    },
}

_INDUSTRY_PAYMENT_DEFAULTS = {
    'real_estate':'At Closing','services':'Net 30','employment':'Bi-weekly',
    'construction':'Draw schedule per milestones','business':'At Closing',
    'cannabis':'Net 15','finance':'Monthly installments','licensing':'Monthly royalty','other':'Net 30',
}
_STATE_ABBREVS = {
    'AL':'Alabama','AK':'Alaska','AZ':'Arizona','AR':'Arkansas','CA':'California','CO':'Colorado',
    'CT':'Connecticut','DE':'Delaware','FL':'Florida','GA':'Georgia','HI':'Hawaii','ID':'Idaho',
    'IL':'Illinois','IN':'Indiana','IA':'Iowa','KS':'Kansas','KY':'Kentucky','LA':'Louisiana',
    'ME':'Maine','MD':'Maryland','MA':'Massachusetts','MI':'Michigan','MN':'Minnesota','MS':'Mississippi',
    'MO':'Missouri','MT':'Montana','NE':'Nebraska','NV':'Nevada','NH':'New Hampshire','NJ':'New Jersey',
    'NM':'New Mexico','NY':'New York','NC':'North Carolina','ND':'North Dakota','OH':'Ohio','OK':'Oklahoma',
    'OR':'Oregon','PA':'Pennsylvania','RI':'Rhode Island','SC':'South Carolina','SD':'South Dakota',
    'TN':'Tennessee','TX':'Texas','UT':'Utah','VT':'Vermont','VA':'Virginia','WA':'Washington',
    'WV':'West Virginia','WI':'Wisconsin','WY':'Wyoming',
}

def _detect_jurisdiction(deal):
    text = ' '.join(filter(None,[deal.get('property_address'),deal.get('notes'),deal.get('deal_name'),deal.get('contract_requirements')]))
    for abbr, full in _STATE_ABBREVS.items():
        if re.search(rf'\b{abbr}\b', text) or re.search(rf'\b{full}\b', text, re.IGNORECASE):
            return full
    return 'Oregon'

def _quick_classify(deal):
    text = ' '.join(filter(None,[deal.get('deal_name'),deal.get('notes'),deal.get('property_address'),deal.get('deal_type')])).lower()
    patterns = [
        (['purchase agreement','purchase price','real estate purchase','home purchase','property purchase','buy the property','sale of property'], 'real_estate','purchase_agreement'),
        (['commercial purchase','commercial property','investment property','multi-family'], 'real_estate','commercial_purchase'),
        (['lease','rental agreement','month-to-month','tenant','landlord','rent per month'], 'real_estate','lease_agreement'),
        (['listing agreement','list the property','mls listing','right to sell'], 'real_estate','listing_agreement'),
        (['commission split','commission agreement','referral fee','co-broke'], 'real_estate','commission_agreement'),
        (['saas','software license','software as a service','subscription agreement','api access'], 'services','saas_agreement'),
        (['consulting agreement','consulting services','management consulting','advisory services'], 'services','consulting_agreement'),
        (['service agreement','service contract','professional services','scope of work'], 'services','service_agreement'),
        (['offer letter','employment offer','job offer','start date','salary offer'], 'employment','offer_letter'),
        (['independent contractor','freelance','1099','contractor agreement'], 'employment','independent_contractor'),
        (['non-disclosure','nda','confidentiality agreement','trade secret'], 'employment','nda'),
        (['subcontract','subcontractor agreement'], 'construction','subcontractor'),
        (['construction contract','general contractor','build','renovation','remodel','contractor agreement'], 'construction','general_contractor'),
        (['letter of intent','loi','intent to acquire','intent to purchase business'], 'business','letter_of_intent'),
        (['asset purchase','business acquisition','buy the business','purchase of assets'], 'business','asset_purchase'),
        (['operating agreement','llc agreement','partnership agreement','member agreement'], 'business','operating_agreement'),
        (['cannabis','olcc','hemp','dispensary','producer','processor','marijuana'], 'cannabis','production_agreement'),
        (['distribution agreement','wholesale','distributor','distribute cannabis'], 'cannabis','distribution_agreement'),
        (['promissory note','loan agreement','personal loan','business loan','lender','borrower'], 'finance','promissory_note'),
        (['ip license','trademark license','patent license','brand license','franchise'], 'licensing','ip_license'),
    ]
    for keywords, industry, contract_type in patterns:
        if any(kw in text for kw in keywords):
            ct = CONTRACT_LIBRARY[industry]['types'][contract_type]
            return [{'industry':industry,'type':contract_type,'label':ct['label'],'description':ct['description'],'reason':'Detected from deal details','clauses':ct['clauses']}]
    return None

def _classify_contract(deal):
    # Fast: pattern matching first (no API)
    quick = _quick_classify(deal)
    if quick: return quick
    industry = (deal.get('industry') or '').strip()
    deal_type = (deal.get('deal_type') or '').strip()
    context = f"""Deal: {deal.get('deal_name','')}
Industry: {industry}
Deal Type: {deal_type}
Item/Property: {deal.get('property_address','')}
Price: {deal.get('purchase_price','')}
Notes: {deal.get('notes','')}
Contract Requirements: {deal.get('contract_requirements','')}
Jurisdiction: {deal.get('jurisdiction','')}"""
    types_list = []
    for ind_key, ind_val in CONTRACT_LIBRARY.items():
        for type_key, type_val in ind_val['types'].items():
            types_list.append(f'{ind_key}/{type_key}: {type_val["label"]} — {type_val["description"]}')
    prompt = f"""Based on this deal, determine which contract(s) need to be drafted. Return ONLY valid JSON array.

{context}

Available contract types:
{chr(10).join(types_list)}

Return JSON array (1-3 contracts): [{{"industry":"<key>","type":"<key>","reason":"<one sentence why this contract fits>"}}]
Use exact keys from the list. No other text."""
    try:
        raw = openai_call([{'role':'user','content':prompt}], max_tokens=400)
        suggestions = json.loads(re.sub(r'```[a-z]*','',raw).strip())
        result = []
        for s in suggestions[:3]:
            ind = s.get('industry',''); typ = s.get('type','')
            if ind in CONTRACT_LIBRARY and typ in CONTRACT_LIBRARY[ind]['types']:
                ct = CONTRACT_LIBRARY[ind]['types'][typ]
                result.append({'industry':ind,'type':typ,'label':ct['label'],'description':ct['description'],'reason':s.get('reason',''),'clauses':ct['clauses']})
        return result if result else _fallback_classification(deal)
    except Exception as e:
        print(f'[classify] {e}'); return _fallback_classification(deal)

def _fallback_classification(deal):
    name = (deal.get('deal_name') or '').lower()
    ind = deal.get('industry') or 'other'
    if ind in CONTRACT_LIBRARY:
        first_type = next(iter(CONTRACT_LIBRARY[ind]['types']))
        ct = CONTRACT_LIBRARY[ind]['types'][first_type]
        return [{'industry':ind,'type':first_type,'label':ct['label'],'description':ct['description'],'reason':'Based on selected industry','clauses':ct['clauses']}]
    if any(w in name for w in ('lease','rent','tenant')): ind,typ = 'real_estate','lease_agreement'
    elif any(w in name for w in ('purchase','buy','sale','selling')): ind,typ = 'real_estate','purchase_agreement'
    elif any(w in name for w in ('consult','advisory')): ind,typ = 'services','consulting_agreement'
    elif any(w in name for w in ('cannabis','olcc','dispensary','hemp')): ind,typ = 'cannabis','distribution_agreement'
    else: ind,typ = 'other','general_agreement'
    ct = CONTRACT_LIBRARY[ind]['types'][typ]
    return [{'industry':ind,'type':typ,'label':ct['label'],'description':ct['description'],'reason':'Based on deal name','clauses':ct['clauses']}]

def send_email(to, subject, body):
    if not SMTP_USER or not SMTP_PASS: return
    try:
        msg = MIMEText(body,'html'); msg['Subject']=subject; msg['From']=SMTP_USER; msg['To']=to
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.sendmail(SMTP_USER, to, msg.as_string())
    except Exception as e: print(f'[email] {e}')

def openai_call(messages, max_tokens=500, model='gpt-4o-mini'):
    payload = json.dumps({'model':model,'messages':messages,'max_tokens':max_tokens}).encode()
    req = urllib.request.Request('https://api.openai.com/v1/chat/completions', data=payload,
        headers={'Content-Type':'application/json','Authorization':f'Bearer {OPENAI_KEY}'})
    timeout = 120 if max_tokens > 1000 else 30
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())['choices'][0]['message']['content']

def monthly_msg_count(bot_id, db):
    start = datetime.datetime.now().replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat()
    return db.execute("SELECT COUNT(*) FROM conversations WHERE bot_id=? AND role='user' AND created_at>=?",(bot_id,start)).fetchone()[0]

# ── DEEP SCRAPER ──────────────────────────────────────────────────────────────
class _Extractor(HTMLParser):
    SKIP = {'script','style','noscript','nav','footer','head','iframe','svg'}
    def __init__(self): super().__init__(); self._depth=0; self.parts=[]; self._links=[]
    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP: self._depth += 1
        if tag == 'a':
            for k,v in attrs:
                if k=='href' and v: self._links.append(v)
    def handle_endtag(self, tag):
        if tag in self.SKIP and self._depth > 0: self._depth -= 1
    def handle_data(self, data):
        if not self._depth:
            s = ' '.join(data.split())
            if len(s) > 20: self.parts.append(s)

def _normalize_url(href, base):
    if href.startswith('http'): return href
    if href.startswith('//'): return base.split('://')[0]+':'+href
    if href.startswith('/'): return '/'.join(base.split('/')[:3])+href
    return None

def _same_origin(url, base):
    try: return base.split('/')[2]==url.split('/')[2]
    except: return False

def _chunk_text(text, max_total=20000, chunk_size=800):
    chunks = []
    for i in range(0, min(len(text),max_total), chunk_size):
        c = text[i:i+chunk_size].strip()
        if c: chunks.append(c)
    return chunks

def scrape_url(url, deep=True, max_pages=12):
    visited=set(); parts=[]
    def get_links(html, base):
        p = _Extractor(); p.feed(html); out=[]
        for href in p._links:
            full = _normalize_url(href,base)
            if full and _same_origin(full,base):
                clean = full.split('#')[0].split('?')[0].rstrip('/')
                if clean and clean not in visited: out.append(clean)
        return out
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page(user_agent='Mozilla/5.0 Peekbot/2.0')
            queue = [url.rstrip('/')]
            while queue and len(visited) < max_pages:
                cur = queue.pop(0)
                if cur in visited: continue
                visited.add(cur); print(f'[scraper] {cur}')
                try:
                    page.goto(cur, wait_until='networkidle', timeout=20000)
                    page.wait_for_timeout(1200)
                    text = page.inner_text('body'); html = page.content()
                    if text: parts.append(f'=== {cur} ===\n'+re.sub(r'\n{3,}','\n\n',text).strip())
                    if deep and html:
                        for lnk in get_links(html,url):
                            if lnk not in visited: queue.append(lnk)
                except Exception as e: print(f'[scraper] {cur}: {e}')
            browser.close()
        return _chunk_text('\n\n'.join(parts)), None
    except ImportError: pass
    except Exception as e: return [], f'Playwright error: {e}'
    try:
        queue=[url.rstrip('/')]
        while queue and len(visited)<max_pages:
            cur=queue.pop(0)
            if cur in visited: continue
            visited.add(cur)
            try:
                req=urllib.request.Request(cur,headers={'User-Agent':'Mozilla/5.0 Peekbot/1.0'})
                with urllib.request.urlopen(req,timeout=12) as r: raw=r.read(500_000).decode('utf-8',errors='ignore')
                p=_Extractor(); p.feed(raw)
                parts.append(f'=== {cur} ===\n'+'\n'.join(p.parts))
                if deep:
                    for href in p._links:
                        full=_normalize_url(href,url)
                        if full and _same_origin(full,url):
                            clean=full.split('#')[0].split('?')[0].rstrip('/')
                            if clean not in visited: queue.append(clean)
            except: continue
        return _chunk_text('\n\n'.join(parts)), None
    except Exception as e: return [], str(e)

def _do_sync(src, org_id, db):
    sid=src['id']
    db.execute("UPDATE data_sources SET sync_status='syncing' WHERE id=?",(sid,)); db.commit()
    chunks,err=[],None
    if src['source_type'] in ('website','mls') and src['url']:
        chunks,err=scrape_url(src['url'],deep=True)
    elif src['source_type']=='instagram': err='Instagram not supported; use website URL.'
    else: err='No URL configured'
    if chunks:
        db.execute('DELETE FROM knowledge_base WHERE source_id=? AND org_id=?',(sid,org_id))
        for chunk in chunks:
            db.execute('INSERT INTO knowledge_base (org_id,content,source,source_id) VALUES (?,?,?,?)',(org_id,chunk,src['name'],sid))
        db.execute("UPDATE data_sources SET sync_status='synced',last_synced=CURRENT_TIMESTAMP,item_count=?,last_error=NULL WHERE id=?",(len(chunks),sid))
    elif err: db.execute("UPDATE data_sources SET sync_status='error',last_error=? WHERE id=?",(err[:500],sid))
    else: db.execute("UPDATE data_sources SET sync_status='synced',last_synced=CURRENT_TIMESTAMP,item_count=0 WHERE id=?",(sid,))
    db.commit(); return len(chunks), err

def _auto_draft_contracts(deal_id, org_id):
    try:
        time.sleep(1)  # ensure DB commit is visible
        db=get_db()
        deal=db.execute('SELECT * FROM deals WHERE id=?',(deal_id,)).fetchone()
        if not deal: db.close(); return
        dd=dict(deal)
        suggestions=_classify_contract(dd)
        transcript=''
        if dd.get('session_id'):
            msgs=db.execute('SELECT role,message FROM conversations WHERE session_id=? ORDER BY created_at',(dd['session_id'],)).fetchall()
            if msgs: transcript='\n'.join(f"{m['role'].upper()}: {m['message']}" for m in msgs)
        for s in suggestions[:2]:
            try:
                sys_msg, user_msg = _build_contract_prompt(s, dd, transcript)
                text=openai_call([{'role':'system','content':sys_msg},{'role':'user','content':user_msg}],
                                 max_tokens=8000, model='gpt-4o')
                title=f'{s["label"]} — {dd["deal_name"]}'
                fp=os.path.join(DOCS_DIR,f'contract_{s["type"]}_{deal_id}_{int(time.time())}.pdf')
                _contract_to_pdf(text,fp)
                db.execute('INSERT INTO generated_documents (org_id,doc_type,title,data_json,file_path,status) VALUES (?,?,?,?,?,?)',
                    (org_id,'contract',title,json.dumps(dd),fp,'draft')); db.commit()
                print(f'[auto-contract] deal={deal_id} type={s["type"]} → {title}')
            except Exception as e: print(f'[auto-contract] deal={deal_id} {s["type"]}: {e}')
        db.close()
    except Exception as e: print(f'[auto-contract] outer: {e}')

def _auto_draft_invoice(deal_id, org_id):
    try:
        time.sleep(1)
        db=get_db()
        deal=db.execute('SELECT * FROM deals WHERE id=?',(deal_id,)).fetchone()
        if not deal: db.close(); return
        dd=dict(deal)
        amount=float(dd.get('purchase_price') or 0)
        if amount<=0: db.close(); return  # no price — skip invoice
        org=db.execute('SELECT * FROM organizations WHERE id=?',(org_id,)).fetchone()
        from_name=(dict(org).get('name') if org else None) or 'Your Company'
        import secrets as _sec
        inv_num=_sec.token_hex(4).upper()
        import datetime as _dt
        date_str=_dt.datetime.now().strftime('%B %d, %Y')
        payment_terms=dd.get('payment_terms') or 'Net 30'
        try:
            days=int(''.join(filter(str.isdigit, payment_terms)) or '30')
        except: days=30
        due=(_dt.datetime.now()+_dt.timedelta(days=days)).strftime('%B %d, %Y')
        description=dd.get('deal_name') or 'Services'
        if dd.get('property_address'): description+=f' — {dd["property_address"]}'
        fp=os.path.join(DOCS_DIR,f'invoice_{deal_id}_{int(time.time())}.pdf')
        _invoice_to_pdf(fp,inv_num,date_str,due,from_name,
                        dd.get('buyer_name',''),dd.get('buyer_email',''),
                        description,amount,0,amount,payment_terms)
        title=f'Invoice #{inv_num} — {dd["deal_name"]}'
        db.execute('INSERT INTO generated_documents (org_id,doc_type,title,data_json,file_path,status) VALUES (?,?,?,?,?,?)',
            (org_id,'invoice',title,json.dumps(dd),fp,'draft')); db.commit()
        print(f'[auto-invoice] deal={deal_id} inv={inv_num} amount=${amount}')
        db.close()
    except Exception as e: print(f'[auto-invoice] outer: {e}')

def _auto_sync_loop():
    print(f'[auto-sync] started interval={AUTO_SYNC_INTERVAL}s')
    while True:
        time.sleep(AUTO_SYNC_INTERVAL); print('[auto-sync] running...')
        try:
            db=get_db()
            sources=db.execute("SELECT ds.*,b.org_id FROM data_sources ds JOIN bots b ON ds.bot_id=b.id WHERE ds.source_type IN ('website','mls') AND ds.url IS NOT NULL").fetchall()
            db.close()
            for src in sources:
                try:
                    db=get_db(); count,err=_do_sync(src,src['org_id'],db); db.close()
                    print(f'[auto-sync] {src["name"]}: {count} chunks' if not err else f'[auto-sync] {src["name"]}: {err}')
                except Exception as e: print(f'[auto-sync] {e}')
        except Exception as e: print(f'[auto-sync] outer: {e}')

threading.Thread(target=_auto_sync_loop,daemon=True,name='auto-sync').start()

def stripe_post(path, params):
    data=urllib.parse.urlencode(params).encode()
    auth=base64.b64encode(f'{STRIPE_SECRET}:'.encode()).decode()
    req=urllib.request.Request(f'https://api.stripe.com/v1/{path}',data=data,
        headers={'Authorization':f'Basic {auth}','Content-Type':'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req,timeout=15) as r: return json.loads(r.read())

def verify_stripe_sig(payload_bytes, sig_header):
    try:
        ts=[p.split('=')[1] for p in sig_header.split(',') if p.startswith('t=')][0]
        sigs=[p.split('=',1)[1] for p in sig_header.split(',') if p.startswith('v1=')]
        expected=_hmac.new(STRIPE_WEBHOOK.encode(),f'{ts}.'.encode()+payload_bytes,hashlib.sha256).hexdigest()
        return any(secrets.compare_digest(expected,s) for s in sigs)
    except: return False

@app.route('/') 
def index(): return send_from_directory('static','index.html')
@app.route('/dashboard')
@app.route('/accept-invite')
def spa(): return send_from_directory('static','index.html')
@app.route('/static/<path:path>')
def static_files(path): return send_from_directory('static',path)
@app.route('/health')
def health(): return jsonify({'status':'ok','ts':datetime.datetime.utcnow().isoformat()})

@app.route('/api/register', methods=['POST'])
def register():
    d=request.json or {}
    email=(d.get('email') or '').lower().strip(); password=d.get('password',''); name=d.get('name','').strip()
    if not email or not password: return jsonify({'error':'Email and password required'}),400
    db=get_db()
    try:
        db.execute('INSERT INTO users (email,password,name,plan) VALUES (?,?,?,?)',(email,hash_pw(password),name,'free')); db.commit()
        user=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        db.execute('INSERT INTO organizations (owner_id,name) VALUES (?,?)',(user['id'],(name or email.split('@')[0])+' Organization')); db.commit()
        org=db.execute('SELECT * FROM organizations WHERE owner_id=?',(user['id'],)).fetchone()
        db.execute('UPDATE users SET org_id=?,role=? WHERE id=?',(org['id'],'owner',user['id']))
        tok=secrets.token_hex(16)
        db.execute('INSERT INTO bots (org_id,token,name) VALUES (?,?,?)',(org['id'],tok,(name or 'My')+"'s Bot")); db.commit(); db.close()
        return jsonify({'token':make_token(user['id'],email),'email':email,'name':name,'plan':'free','role':'owner'})
    except: db.close(); return jsonify({'error':'Email already registered'}),400

@app.route('/api/login', methods=['POST'])
def login():
    d=request.json or {}; email=(d.get('email') or '').lower().strip(); pw=d.get('password','')
    db=get_db(); user=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if not user or not check_pw(pw,user['password']): db.close(); return jsonify({'error':'Invalid credentials'}),401
    if not (user['password'].startswith('$2b$') or user['password'].startswith('$2a$')):
        db.execute('UPDATE users SET password=? WHERE id=?',(hash_pw(pw),user['id'])); db.commit()
    db.close()
    return jsonify({'token':make_token(user['id'],user['email']),'email':user['email'],'name':user['name'] or '',
                    'plan':user['plan'] or 'free','role':user['role'] or 'agent','org_id':user['org_id']})

@app.route('/api/me', methods=['GET'])
def me():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    if not user: db.close(); return jsonify({'error':'Not found'}),404
    org=db.execute('SELECT * FROM organizations WHERE id=?',(user['org_id'],)).fetchone()
    bot=get_org_bot(user['org_id'],db) if user['org_id'] else None; db.close()
    return jsonify({'id':user['id'],'email':user['email'],'name':user['name'] or '','plan':user['plan'] or 'free',
                    'role':user['role'] or 'agent','org_id':user['org_id'],'org_name':org['name'] if org else '','bot_token':bot['token'] if bot else ''})

@app.route('/api/bot', methods=['GET'])
def get_bot():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db); bot=get_org_bot(user['org_id'],db); db.close()
    if not bot: return jsonify({'error':'No bot found'}),404
    return jsonify({**dict(bot),'role':user['role']})

@app.route('/api/bot', methods=['PUT'])
def update_bot():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}; db=get_db(); user=get_user(uid,db); bot=get_org_bot(user['org_id'],db)
    if not bot:
        tok=secrets.token_hex(16)
        db.execute('INSERT INTO bots (org_id,token,name,greeting,system_prompt,color,lead_capture) VALUES (?,?,?,?,?,?,?)',
            (user['org_id'],tok,d.get('name','My Bot'),d.get('greeting','Hi!'),d.get('system_prompt',''),d.get('color','#7c6af7'),d.get('lead_capture',1)))
    else:
        db.execute('UPDATE bots SET name=?,greeting=?,system_prompt=?,color=?,lead_capture=? WHERE org_id=?',
            (d.get('name'),d.get('greeting'),d.get('system_prompt'),d.get('color','#7c6af7'),d.get('lead_capture',1),user['org_id']))
    db.commit(); bot=get_org_bot(user['org_id'],db); db.close(); return jsonify(dict(bot))

@app.route('/api/bots', methods=['GET'])
def get_bots():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    bots=db.execute('SELECT * FROM bots WHERE org_id=? ORDER BY id',(user['org_id'],)).fetchall()
    db.close(); return jsonify({'bots':[dict(b) for b in bots],'role':user['role']})

def _get_bot_for_user(uid,db): user=get_user(uid,db); return get_org_bot(user['org_id'],db),user

@app.route('/api/data-sources', methods=['GET'])
def get_data_sources():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); bot,_=_get_bot_for_user(uid,db)
    if not bot: db.close(); return jsonify([])
    sources=db.execute('SELECT * FROM data_sources WHERE bot_id=? ORDER BY created_at DESC',(bot['id'],)).fetchall()
    db.close(); return jsonify([dict(s) for s in sources])

@app.route('/api/data-sources', methods=['POST'])
def add_data_source():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); bot,_=_get_bot_for_user(uid,db)
    if not bot: db.close(); return jsonify({'error':'No bot found'}),404
    d=request.json or {}
    if not d.get('source_type') or not d.get('name'): db.close(); return jsonify({'error':'source_type and name required'}),400
    try:
        db.execute("INSERT INTO data_sources (bot_id,source_type,name,url,instagram_handle,api_key,sync_status) VALUES (?,?,?,?,?,?,'pending')",
            (bot['id'],d['source_type'],d['name'],d.get('url'),d.get('instagram_handle'),d.get('api_key'))); db.commit()
        sid=db.execute('SELECT last_insert_rowid()').fetchone()[0]
        src=db.execute('SELECT * FROM data_sources WHERE id=?',(sid,)).fetchone(); db.close()
        return jsonify(dict(src)),201
    except Exception as e: db.close(); return jsonify({'error':str(e)}),400

@app.route('/api/data-sources/<int:sid>', methods=['DELETE'])
def delete_data_source(sid):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); bot,user=_get_bot_for_user(uid,db)
    if not bot: db.close(); return jsonify({'error':'Not found'}),404
    src=db.execute('SELECT * FROM data_sources WHERE id=? AND bot_id=?',(sid,bot['id'])).fetchone()
    if not src: db.close(); return jsonify({'error':'Not found'}),404
    db.execute('DELETE FROM knowledge_base WHERE source_id=? AND org_id=?',(sid,user['org_id']))
    db.execute('DELETE FROM data_sources WHERE id=?',(sid,)); db.commit(); db.close()
    return jsonify({'success':True})

@app.route('/api/data-sources/<int:sid>/sync', methods=['POST'])
def sync_data_source(sid):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); bot,user=_get_bot_for_user(uid,db)
    if not bot: db.close(); return jsonify({'error':'Not found'}),404
    src=db.execute('SELECT * FROM data_sources WHERE id=? AND bot_id=?',(sid,bot['id'])).fetchone()
    if not src: db.close(); return jsonify({'error':'Not found'}),404
    count,err=_do_sync(src,user['org_id'],db); db.close()
    return jsonify({'success':True,'chunks':count,'error':err})

@app.route('/api/knowledge', methods=['GET'])
def get_knowledge():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    kb=db.execute('SELECT * FROM knowledge_base WHERE org_id=? ORDER BY created_at DESC',(user['org_id'],)).fetchall()
    db.close(); return jsonify([dict(k) for k in kb])

@app.route('/api/knowledge', methods=['POST'])
def add_knowledge():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}
    if not d.get('content'): return jsonify({'error':'content required'}),400
    db=get_db(); user=get_user(uid,db)
    db.execute('INSERT INTO knowledge_base (org_id,content,source) VALUES (?,?,?)',(user['org_id'],d['content'][:2000],d.get('source','manual'))); db.commit()
    kb=db.execute('SELECT * FROM knowledge_base WHERE org_id=? ORDER BY id DESC LIMIT 1',(user['org_id'],)).fetchone()
    db.close(); return jsonify(dict(kb)),201

@app.route('/api/knowledge/<int:kb_id>', methods=['DELETE'])
def delete_knowledge(kb_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    kb=db.execute('SELECT * FROM knowledge_base WHERE id=? AND org_id=?',(kb_id,user['org_id'])).fetchone()
    if not kb: db.close(); return jsonify({'error':'Not found'}),404
    db.execute('DELETE FROM knowledge_base WHERE id=?',(kb_id,)); db.commit(); db.close()
    return jsonify({'success':True})

@app.route('/api/leads', methods=['GET'])
def get_leads():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    bots=db.execute('SELECT id FROM bots WHERE org_id=?',(user['org_id'],)).fetchall()
    if not bots: db.close(); return jsonify([])
    ids=[b['id'] for b in bots]; ph=','.join('?'*len(ids))
    leads=db.execute(f'SELECT * FROM leads WHERE bot_id IN ({ph}) ORDER BY created_at DESC',ids).fetchall()
    db.close(); return jsonify([dict(l) for l in leads])

@app.route('/api/leads/<int:lead_id>', methods=['PATCH'])
def update_lead(lead_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}; db=get_db(); user=get_user(uid,db)
    bots=db.execute('SELECT id FROM bots WHERE org_id=?',(user['org_id'],)).fetchall()
    ids=[b['id'] for b in bots]; ph=','.join('?'*len(ids))
    lead=db.execute(f'SELECT * FROM leads WHERE id=? AND bot_id IN ({ph})',[lead_id]+ids).fetchone()
    if not lead: db.close(); return jsonify({'error':'Not found'}),404
    fields={k:d[k] for k in ('status','notes','assigned_to','name','email','phone') if k in d}
    if fields:
        db.execute(f'UPDATE leads SET {", ".join(f"{k}=?" for k in fields)} WHERE id=?',list(fields.values())+[lead_id]); db.commit()
    lead=db.execute('SELECT * FROM leads WHERE id=?',(lead_id,)).fetchone(); db.close()
    return jsonify(dict(lead))

@app.route('/api/leads/export', methods=['GET'])
def export_leads():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    bots=db.execute('SELECT id FROM bots WHERE org_id=?',(user['org_id'],)).fetchall()
    if not bots: db.close(); return Response('',mimetype='text/csv')
    ids=[b['id'] for b in bots]; ph=','.join('?'*len(ids))
    leads=db.execute(f'SELECT * FROM leads WHERE bot_id IN ({ph}) ORDER BY created_at DESC',ids).fetchall(); db.close()
    out=io.StringIO(); w=csv.writer(out); w.writerow(['id','name','email','phone','status','notes','created_at'])
    for l in leads: w.writerow([l['id'],l['name'],l['email'],l['phone'],l['status'],l['notes'],l['created_at']])
    resp=make_response(out.getvalue()); resp.headers['Content-Type']='text/csv'
    resp.headers['Content-Disposition']='attachment; filename=leads.csv'; return resp

@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    bots=db.execute('SELECT id FROM bots WHERE org_id=?',(user['org_id'],)).fetchall()
    if not bots: db.close(); return jsonify([])
    ids=[b['id'] for b in bots]; ph=','.join('?'*len(ids))
    convos=db.execute(f'SELECT session_id,MIN(created_at) as started,COUNT(*) as messages FROM conversations WHERE bot_id IN ({ph}) GROUP BY session_id ORDER BY started DESC LIMIT 100',ids).fetchall()
    db.close(); return jsonify([dict(c) for c in convos])

@app.route('/api/conversations/<session_id>', methods=['GET'])
def get_conversation(session_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    msgs=db.execute('SELECT c.* FROM conversations c JOIN bots b ON c.bot_id=b.id WHERE b.org_id=? AND c.session_id=? ORDER BY c.created_at',(user['org_id'],session_id)).fetchall()
    db.close(); return jsonify([dict(m) for m in msgs])

@app.route('/api/deals', methods=['GET'])
def get_deals():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deals=db.execute('SELECT * FROM deals WHERE org_id=? ORDER BY created_at DESC',(user['org_id'],)).fetchall()
    db.close(); return jsonify([dict(d) for d in deals])

@app.route('/api/deals', methods=['POST'])
def create_deal():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db); d=request.json or {}
    try:
        industry=d.get('industry'); deal_type_val=d.get('deal_type')
        jurisdiction=d.get('jurisdiction'); payment_terms=d.get('payment_terms')
        if not industry:
            _tmp={'deal_name':d.get('deal_name',''),'property_address':d.get('property_address',''),'notes':d.get('notes','')}
            _s=_quick_classify(_tmp)
            if _s:
                industry=industry or _s[0]['industry']; deal_type_val=deal_type_val or _s[0]['label']
        jurisdiction=jurisdiction or _detect_jurisdiction({'property_address':d.get('property_address',''),'notes':d.get('notes','')})
        payment_terms=payment_terms or _INDUSTRY_PAYMENT_DEFAULTS.get(industry or 'other','Net 30')
        db.execute('INSERT INTO deals (org_id,deal_name,property_address,buyer_name,buyer_email,seller_name,seller_email,purchase_price,earnest_money,closing_date,commission_amount,deal_status,notes,source,session_id,industry,deal_type,jurisdiction,payment_terms,contract_requirements) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (user['org_id'],d.get('deal_name'),d.get('property_address'),d.get('buyer_name'),d.get('buyer_email'),
             d.get('seller_name'),d.get('seller_email'),d.get('purchase_price'),d.get('earnest_money'),d.get('closing_date'),
             d.get('commission_amount'),d.get('deal_status','lead'),d.get('notes'),d.get('source','manual'),d.get('session_id'),
             industry,deal_type_val,jurisdiction,payment_terms,d.get('contract_requirements'))); db.commit()
        deal_id=db.execute('SELECT last_insert_rowid()').fetchone()[0]
        deal=db.execute('SELECT * FROM deals WHERE id=?',(deal_id,)).fetchone()
        db.close()
        threading.Thread(target=_auto_draft_contracts,args=(deal_id,user['org_id']),daemon=True).start()
        threading.Thread(target=_auto_draft_invoice,args=(deal_id,user['org_id']),daemon=True).start()
        return jsonify(dict(deal)),201
    except Exception as e: db.close(); return jsonify({'error':str(e)}),400

@app.route('/api/deals/<int:deal_id>', methods=['PUT'])
def update_deal(deal_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deal=db.execute('SELECT * FROM deals WHERE id=? AND org_id=?',(deal_id,user['org_id'])).fetchone()
    if not deal: db.close(); return jsonify({'error':'Not found'}),404
    d=request.json or {}
    db.execute('UPDATE deals SET deal_name=?,property_address=?,buyer_name=?,buyer_email=?,seller_name=?,seller_email=?,purchase_price=?,earnest_money=?,closing_date=?,commission_amount=?,deal_status=?,notes=?,industry=?,deal_type=?,jurisdiction=?,payment_terms=?,contract_requirements=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (_v(d,'deal_name',deal['deal_name']),_v(d,'property_address',deal['property_address']),
         _v(d,'buyer_name',deal['buyer_name']),_v(d,'buyer_email',deal['buyer_email']),
         _v(d,'seller_name',deal['seller_name']),_v(d,'seller_email',deal['seller_email']),
         _v(d,'purchase_price',deal['purchase_price']),_v(d,'earnest_money',deal['earnest_money']),
         _v(d,'closing_date',deal['closing_date']),_v(d,'commission_amount',deal['commission_amount']),
         _v(d,'deal_status',deal['deal_status']),_v(d,'notes',deal['notes']),
         _v(d,'industry',deal['industry']),_v(d,'deal_type',deal['deal_type']),
         _v(d,'jurisdiction',deal['jurisdiction']),_v(d,'payment_terms',deal['payment_terms']),
         _v(d,'contract_requirements',deal['contract_requirements']),deal_id))
    db.commit(); deal=db.execute('SELECT * FROM deals WHERE id=?',(deal_id,)).fetchone(); db.close()
    return jsonify(dict(deal))

@app.route('/api/deals/<int:deal_id>', methods=['DELETE'])
def delete_deal(deal_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deal=db.execute('SELECT * FROM deals WHERE id=? AND org_id=?',(deal_id,user['org_id'])).fetchone()
    if not deal: db.close(); return jsonify({'error':'Not found'}),404
    db.execute('DELETE FROM deals WHERE id=?',(deal_id,)); db.commit(); db.close()
    return jsonify({'success':True})

@app.route('/api/deals/<int:deal_id>/commission', methods=['POST'])
def add_commission(deal_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deal=db.execute('SELECT * FROM deals WHERE id=? AND org_id=?',(deal_id,user['org_id'])).fetchone()
    if not deal: db.close(); return jsonify({'error':'Not found'}),404
    d=request.json or {}
    db.execute('INSERT INTO deal_commissions (deal_id,user_id,commission_amount) VALUES (?,?,?)',(deal_id,d.get('user_id'),d.get('commission_amount'))); db.commit()
    comm=db.execute('SELECT * FROM deal_commissions WHERE deal_id=? ORDER BY id DESC LIMIT 1',(deal_id,)).fetchone()
    db.close(); return jsonify(dict(comm)),201

@app.route('/api/deals/from-chat/<bot_token>', methods=['POST'])
def deal_from_chat(bot_token):
    db=get_db(); bot=db.execute('SELECT * FROM bots WHERE token=?',(bot_token,)).fetchone()
    if not bot: db.close(); return jsonify({'error':'Bot not found'}),404
    org=db.execute('SELECT * FROM organizations WHERE id=?',(bot['org_id'],)).fetchone()
    owner=db.execute('SELECT * FROM users WHERE id=?',(org['owner_id'],)).fetchone()
    d=request.json or {}; messages=d.get('messages',[])
    deal_data={'deal_name':d.get('deal_name',''),'property_address':d.get('property_address',''),
               'buyer_name':d.get('buyer_name',''),'buyer_email':d.get('buyer_email',''),
               'purchase_price':d.get('purchase_price'),'notes':d.get('notes',''),'session_id':d.get('session_id','')}
    if messages and not deal_data['deal_name']:
        conv='\n'.join(f"{m['role'].upper()}: {m['content']}" for m in messages[-20:])
        try:
            raw=openai_call([{'role':'system','content':'Extract deal info from this chat. Return ONLY valid JSON with keys: deal_name, property_address, buyer_name, buyer_email, purchase_price, notes. deal_name like "Inquiry: OLCC Producer License". No other text.'},{'role':'user','content':conv}],max_tokens=300)
            ext=json.loads(re.sub(r'```[a-z]*','',raw).strip())
            for k in deal_data:
                if not deal_data[k] and ext.get(k): deal_data[k]=ext[k]
        except Exception as e: print(f'[deal-from-chat] {e}')
    if not deal_data['deal_name']: deal_data['deal_name']=f'Chat Inquiry — {datetime.datetime.now().strftime("%b %d %Y")}'
    db.execute('INSERT INTO deals (org_id,deal_name,property_address,buyer_name,buyer_email,purchase_price,notes,deal_status,source,session_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
        (bot['org_id'],deal_data['deal_name'],deal_data['property_address'],deal_data['buyer_name'],deal_data['buyer_email'],deal_data['purchase_price'],deal_data['notes'],'lead','chat',deal_data['session_id'])); db.commit()
    deal_id=db.execute('SELECT last_insert_rowid()').fetchone()[0]
    if deal_data['buyer_name'] or deal_data['buyer_email']:
        db.execute('INSERT INTO leads (bot_id,name,email,notes,status) VALUES (?,?,?,?,?)',
            (bot['id'],deal_data['buyer_name'],deal_data['buyer_email'],f'From chat: {deal_data["deal_name"]}','new')); db.commit()
    db.close()
    threading.Thread(target=_auto_draft_contracts,args=(deal_id,bot['org_id']),daemon=True).start()
    threading.Thread(target=_auto_draft_invoice,args=(deal_id,bot['org_id']),daemon=True).start()
    link=f'{BASE_URL}/dashboard?deal={deal_id}'
    if owner:
        send_email(owner['email'],f'New Chat Deal: {deal_data["deal_name"]}',
            f'<h2>New deal from chat</h2><p><b>Deal:</b> {deal_data["deal_name"]}</p><p><b>Buyer:</b> {deal_data["buyer_name"] or "Unknown"} ({deal_data["buyer_email"] or "no email"})</p>'
            f'<p><b>Item:</b> {deal_data["property_address"] or "—"}</p><p><a href="{link}" style="background:#7c6af7;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;display:inline-block;">View Deal →</a></p>')
    return jsonify({'success':True,'deal_id':deal_id,'dashboard_link':link})

@app.route('/api/deals/<int:deal_id>/auto-classify', methods=['POST'])
def auto_classify_deal(deal_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deal=db.execute('SELECT * FROM deals WHERE id=? AND org_id=?',(deal_id,user['org_id'])).fetchone()
    if not deal: db.close(); return jsonify({'error':'Not found'}),404
    dd=dict(deal)
    suggestions=_classify_contract(dd)
    s=suggestions[0] if suggestions else {'industry':'other','type':'general_agreement','label':'General Agreement'}
    industry   = dd.get('industry')  or s['industry']
    deal_type  = dd.get('deal_type') or s['label']
    jurisdiction = dd.get('jurisdiction')  or _detect_jurisdiction(dd)
    payment_terms= dd.get('payment_terms') or _INDUSTRY_PAYMENT_DEFAULTS.get(industry,'Net 30')
    db.execute('UPDATE deals SET industry=?,deal_type=?,jurisdiction=?,payment_terms=? WHERE id=?',
        (industry,deal_type,jurisdiction,payment_terms,deal_id)); db.commit()
    deal=db.execute('SELECT * FROM deals WHERE id=?',(deal_id,)).fetchone()
    db.close(); return jsonify(dict(deal))

@app.route('/api/deals/<int:deal_id>/suggest-contracts', methods=['GET'])
def suggest_contracts(deal_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deal=db.execute('SELECT * FROM deals WHERE id=? AND org_id=?',(deal_id,user['org_id'])).fetchone()
    db.close()
    if not deal: return jsonify({'error':'Not found'}),404
    suggestions=_classify_contract(dict(deal))
    library={ind:{'label':val['label'],'types':{k:{'label':v['label'],'description':v['description']} for k,v in val['types'].items()}} for ind,val in CONTRACT_LIBRARY.items()}
    return jsonify({'suggestions':suggestions,'library':library})

@app.route('/api/generate-contract-for-deal/<int:deal_id>', methods=['POST'])
def generate_contract_for_deal(deal_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    deal=db.execute('SELECT * FROM deals WHERE id=? AND org_id=?',(deal_id,user['org_id'])).fetchone()
    if not deal: db.close(); return jsonify({'error':'Not found'}),404
    d=request.json or {}
    # Resolve contract type: use explicit selection or classify from deal data
    ct_key=d.get('contract_type','')
    if ct_key and '/' in ct_key:
        ind,typ=ct_key.split('/',1)
        if ind in CONTRACT_LIBRARY and typ in CONTRACT_LIBRARY[ind]['types']:
            ct=CONTRACT_LIBRARY[ind]['types'][typ]
            suggestion={'industry':ind,'type':typ,'label':ct['label'],'clauses':ct['clauses']}
        else: suggestion=_classify_contract(dict(deal))[0]
    else: suggestion=_classify_contract(dict(deal))[0]
    transcript=''
    if deal['session_id']:
        msgs=db.execute('SELECT role,message FROM conversations WHERE session_id=? ORDER BY created_at',(deal['session_id'],)).fetchall()
        if msgs: transcript='\n'.join(f"{m['role'].upper()}: {m['message']}" for m in msgs)
    sys_msg, user_msg = _build_contract_prompt(suggestion, dict(deal), transcript)
    try: text=openai_call([{'role':'system','content':sys_msg},{'role':'user','content':user_msg}],
                          max_tokens=8000, model='gpt-4o')
    except Exception as e: db.close(); return jsonify({'error':str(e)}),500
    title=f'{suggestion["label"]} — {deal["deal_name"]}'
    fp=os.path.join(DOCS_DIR,f'contract_{suggestion["type"]}_{deal_id}_{int(time.time())}.pdf')
    _contract_to_pdf(text,fp)
    db.execute('INSERT INTO generated_documents (org_id,doc_type,title,data_json,file_path,status) VALUES (?,?,?,?,?,?)',
        (user['org_id'],'contract',title,json.dumps(dict(deal)),fp,'draft')); db.commit()
    doc=db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY id DESC LIMIT 1',(user['org_id'],)).fetchone()
    db.close(); return jsonify({'success':True,'doc_id':doc['id'],'title':title,'content':text}),201

@app.route('/api/team', methods=['GET'])
def get_team():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    team=db.execute('SELECT id,email,name,role,created_at FROM users WHERE org_id=?',(user['org_id'],)).fetchall()
    invites=db.execute("SELECT * FROM invitations WHERE org_id=? AND accepted=0",(user['org_id'],)).fetchall()
    db.close(); return jsonify({'members':[dict(t) for t in team],'pending':[dict(i) for i in invites]})

@app.route('/api/team/invite', methods=['POST'])
def invite_team():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    if user['role'] not in ('owner','admin'): db.close(); return jsonify({'error':'Must be org owner'}),403
    org=db.execute('SELECT * FROM organizations WHERE id=?',(user['org_id'],)).fetchone()
    d=request.json or {}; invite_email=(d.get('email') or '').lower().strip()
    if not invite_email: db.close(); return jsonify({'error':'Email required'}),400
    tok=secrets.token_hex(20)
    try:
        db.execute('INSERT INTO invitations (org_id,email,role,token) VALUES (?,?,?,?)',(user['org_id'],invite_email,d.get('role','agent'),tok)); db.commit()
        link=f'{BASE_URL}/accept-invite?token={tok}'
        send_email(invite_email,f"You're invited to {org['name']} on Peekbot",f'<h2>Join {org["name"]}</h2><p>Role: <b>{d.get("role","agent")}</b></p><p><a href="{link}">Accept</a></p>')
        db.close(); return jsonify({'success':True})
    except Exception as e: db.close(); return jsonify({'error':str(e)}),400

@app.route('/api/team/accept-invite', methods=['POST'])
def accept_invitation():
    d=request.json or {}; tok=d.get('token',''); email=(d.get('email') or '').lower().strip()
    password=d.get('password',''); name=d.get('name','').strip()
    db=get_db(); invite=db.execute('SELECT * FROM invitations WHERE token=? AND accepted=0',(tok,)).fetchone()
    if not invite: db.close(); return jsonify({'error':'Invalid or expired invitation'}),400
    try:
        db.execute('INSERT INTO users (email,password,name,org_id,role) VALUES (?,?,?,?,?)',(email,hash_pw(password),name,invite['org_id'],invite['role'])); db.commit()
        user=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        db.execute('UPDATE invitations SET accepted=1 WHERE token=?',(tok,)); db.commit(); db.close()
        return jsonify({'token':make_token(user['id'],user['email']),'email':user['email'],'name':user['name'],'plan':'free','role':user['role']})
    except Exception as e: db.close(); return jsonify({'error':str(e)}),400

@app.route('/api/team/<int:member_id>', methods=['DELETE'])
def remove_team_member(member_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    if user['role'] not in ('owner','admin'): db.close(); return jsonify({'error':'Must be org owner'}),403
    member=db.execute('SELECT * FROM users WHERE id=? AND org_id=?',(member_id,user['org_id'])).fetchone()
    if not member or member['role']=='owner': db.close(); return jsonify({'error':'Cannot remove this member'}),400
    db.execute('DELETE FROM users WHERE id=?',(member_id,)); db.commit(); db.close()
    return jsonify({'success':True})

@app.route('/api/templates', methods=['GET'])
def get_templates():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    tmpl=db.execute('SELECT * FROM contract_templates WHERE org_id=?',(user['org_id'],)).fetchall()
    db.close(); return jsonify([dict(t) for t in tmpl])

@app.route('/api/templates', methods=['POST'])
def upload_template():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    if 'file' not in request.files: return jsonify({'error':'No file'}),400
    f=request.files['file']
    if not f or not ('.' in f.filename and f.filename.rsplit('.',1)[1].lower() in ALLOWED_EXT): return jsonify({'error':'Invalid file type'}),400
    db=get_db(); user=get_user(uid,db); fn=secure_filename(f.filename)
    fp=os.path.join(UPLOAD_DIR,f"{user['org_id']}_{int(time.time())}_{fn}"); f.save(fp)
    db.execute('INSERT INTO contract_templates (org_id,name,description,file_path,file_type,category) VALUES (?,?,?,?,?,?)',
        (user['org_id'],request.form.get('name',fn),request.form.get('description',''),fp,fn.rsplit('.',1)[1],request.form.get('category','general'))); db.commit()
    tmpl=db.execute('SELECT * FROM contract_templates WHERE org_id=? ORDER BY id DESC LIMIT 1',(user['org_id'],)).fetchone()
    db.close(); return jsonify(dict(tmpl)),201

@app.route('/api/templates/<int:tid>', methods=['DELETE'])
def delete_template(tid):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    tmpl=db.execute('SELECT * FROM contract_templates WHERE id=? AND org_id=?',(tid,user['org_id'])).fetchone()
    if not tmpl: db.close(); return jsonify({'error':'Not found'}),404
    try: os.remove(tmpl['file_path'])
    except: pass
    db.execute('DELETE FROM contract_templates WHERE id=?',(tid,)); db.commit(); db.close()
    return jsonify({'success':True})

@app.route('/api/documents', methods=['GET'])
def get_documents():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    docs=db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY created_at DESC',(user['org_id'],)).fetchall()
    db.close(); return jsonify([dict(d) for d in docs])

@app.route('/api/generate-contract', methods=['POST'])
def generate_contract():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}; db=get_db(); user=get_user(uid,db); data=d.get('data',{})
    prompt=f"Generate a professional contract:\nTitle: {d.get('title','Contract')}\nData: {json.dumps(data)}\nReturn complete contract text only."
    try: text=openai_call([{'role':'user','content':prompt}],max_tokens=2000)
    except Exception as e: db.close(); return jsonify({'error':str(e)}),500
    fp=os.path.join(DOCS_DIR,f'contract_{int(time.time())}.pdf')
    _text_to_pdf(text, fp)
    db.execute('INSERT INTO generated_documents (org_id,doc_type,title,data_json,file_path,status) VALUES (?,?,?,?,?,?)',
        (user['org_id'],'contract',d.get('title','Contract'),json.dumps(data),fp,'draft')); db.commit()
    doc=db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY id DESC LIMIT 1',(user['org_id'],)).fetchone()
    db.close(); return jsonify({'success':True,'doc_id':doc['id'],'content':text}),201

@app.route('/api/generate-invoice', methods=['POST'])
def generate_invoice():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}; db=get_db(); user=get_user(uid,db); data=d.get('data',{})
    amount=float(data.get('amount',0)); tax=float(data.get('tax_rate',0)); total=amount*(1+tax/100)
    inv_num=data.get('invoice_num',secrets.token_hex(4).upper())
    date_str=datetime.datetime.now().strftime('%B %d, %Y')
    fp=os.path.join(DOCS_DIR,f'invoice_{int(time.time())}.pdf')
    _invoice_to_pdf(fp,inv_num,date_str,data.get('due_date',''),user['name'] or user['email'],
                    data.get('client_name',''),data.get('client_email',''),data.get('description',''),
                    amount,tax,total,data.get('terms','Net 30'))
    db.execute('INSERT INTO generated_documents (org_id,doc_type,title,data_json,file_path,status) VALUES (?,?,?,?,?,?)',
        (user['org_id'],'invoice',f'Invoice #{inv_num}',json.dumps(data),fp,'draft')); db.commit()
    doc=db.execute('SELECT * FROM generated_documents WHERE org_id=? ORDER BY id DESC LIMIT 1',(user['org_id'],)).fetchone()
    db.close(); return jsonify({'success':True,'doc_id':doc['id'],'total':total}),201

@app.route('/api/documents/<int:doc_id>/download', methods=['GET'])
def download_document(doc_id):
    uid=verify_token(request)
    if not uid:
        tok=request.args.get('token','')
        try: uid=jwt.decode(tok,SECRET,algorithms=['HS256'])['user_id']
        except: pass
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    doc=db.execute('SELECT * FROM generated_documents WHERE id=? AND org_id=?',(doc_id,user['org_id'])).fetchone()
    db.close()
    if not doc: return jsonify({'error':'Not found'}),404
    fname=os.path.basename(doc['file_path'])
    return send_from_directory(os.path.dirname(doc['file_path']),fname,as_attachment=True,download_name=fname)

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    doc=db.execute('SELECT * FROM generated_documents WHERE id=? AND org_id=?',(doc_id,user['org_id'])).fetchone()
    if not doc: db.close(); return jsonify({'error':'Not found'}),404
    try: os.remove(doc['file_path'])
    except: pass
    db.execute('DELETE FROM generated_documents WHERE id=?',(doc_id,)); db.commit(); db.close()
    return jsonify({'success':True})

@app.route('/api/upgrade', methods=['POST'])
def upgrade():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db); db.close()
    d=request.json or {}; plan=d.get('plan','pro'); price_id=STRIPE_PRO if plan=='pro' else STRIPE_SUPER
    if STRIPE_SECRET and price_id:
        try:
            sess=stripe_post('checkout/sessions',{'payment_method_types[]':'card','line_items[0][price]':price_id,'line_items[0][quantity]':'1','mode':'subscription','customer_email':user['email'],'metadata[user_id]':str(uid),'metadata[plan]':plan,'success_url':f'{BASE_URL}/dashboard?upgraded=1','cancel_url':f'{BASE_URL}/dashboard?upgrade_cancelled=1'})
            return jsonify({'url':sess['url']})
        except Exception as e: print(f'[stripe] {e}')
    send_email(ADMIN_EMAIL,f'Upgrade: {plan}',f'<p>{user["email"]} wants {plan}</p>')
    return jsonify({'message':"Upgrade request sent. We'll be in touch within 24h."})

@app.route('/api/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload=request.get_data(); sig=request.headers.get('Stripe-Signature','')
    if STRIPE_WEBHOOK and not verify_stripe_sig(payload,sig): return jsonify({'error':'Invalid signature'}),400
    try:
        event=json.loads(payload)
        if event['type']=='checkout.session.completed':
            sess=event['data']['object']; uid=int(sess.get('metadata',{}).get('user_id',0))
            plan=sess.get('metadata',{}).get('plan','pro'); sub_id=sess.get('subscription','')
            if uid:
                db=get_db(); db.execute('UPDATE users SET plan=?,stripe_sub_id=? WHERE id=?',(plan,sub_id,uid)); db.commit(); db.close()
        elif event['type']=='customer.subscription.deleted':
            sub_id=event['data']['object']['id']
            db=get_db(); db.execute("UPDATE users SET plan='free',stripe_sub_id=NULL WHERE stripe_sub_id=?",(sub_id,)); db.commit(); db.close()
    except Exception as e: print(f'[webhook] {e}')
    return jsonify({'received':True})

@app.route('/api/setup-chat', methods=['POST'])
def setup_chat():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}; messages=d.get('messages',[])
    system="""You are Peekbot Setup. Collect 3 things one at a time: 1) Business name 2) What they do (1-2 sentences) 3) Tone (Professional/Friendly/Expert/Casual).
After confirming all 3, output ONLY this JSON on the last line:
{"done":true,"name":"<name>","purpose":"<purpose>","tone":"<professional|friendly|expert|casual>"}"""
    try:
        reply=openai_call([{'role':'system','content':system}]+messages,max_tokens=250)
        config=None; m=re.search(r'\{[^{}]*"done"\s*:\s*true[^{}]*\}',reply)
        if m:
            try: config=json.loads(m.group()); reply=reply[:m.start()].strip()
            except: pass
        return jsonify({'reply':reply,'config':config})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/feature-request', methods=['POST'])
def feature_request():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    d=request.json or {}; db=get_db(); user=get_user(uid,db); db.close()
    send_email(ADMIN_EMAIL,f'Feature Request from {user["email"]}',f'<pre>{json.dumps(d,indent=2)}</pre>')
    return jsonify({'success':True})

@app.route('/api/chat/<bot_token>', methods=['POST'])
def chat(bot_token):
    if not rate_ok(bot_token,limit=100): return jsonify({'error':'Rate limit exceeded.'}),429
    db=get_db(); bot=db.execute('SELECT * FROM bots WHERE token=?',(bot_token,)).fetchone()
    if not bot: db.close(); return jsonify({'error':'Bot not found'}),404
    org=db.execute('SELECT * FROM organizations WHERE id=?',(bot['org_id'],)).fetchone()
    owner=db.execute('SELECT * FROM users WHERE id=?',(org['owner_id'],)).fetchone()
    if owner and owner['plan']=='free' and monthly_msg_count(bot['id'],db)>=FREE_MSG_LIMIT:
        db.close(); return jsonify({'reply':"I've reached my message limit. Please contact the site owner to upgrade."})
    d=request.json or {}; messages=d.get('messages',[]); session_id=d.get('session_id') or secrets.token_hex(8)
    if messages:
        last=messages[-1]
        db.execute('INSERT INTO conversations (bot_id,session_id,role,message) VALUES (?,?,?,?)',(bot['id'],session_id,last['role'],last['content'][:2000])); db.commit()
    knowledge=db.execute('SELECT content FROM knowledge_base WHERE org_id=? ORDER BY id DESC LIMIT 20',(bot['org_id'],)).fetchall()
    kb_text='\n\n'.join(k['content'] for k in knowledge)
    system=bot['system_prompt'] or 'You are a helpful assistant.'
    if kb_text: system+=f'\n\n--- Knowledge Base ---\n{kb_text}\n--- End Knowledge ---'
    system+="""

--- Deal Capture Instructions ---
When a visitor expresses clear interest in purchasing or acquiring a specific listing/service/product:
1. Collect their name and email naturally in conversation.
2. Ask for key details (what they want, budget, timeline).
3. Once you have name + email + item of interest, output this EXACTLY on its own line then continue:
   DEAL_READY:{"buyer_name":"...","buyer_email":"...","deal_name":"...","property_address":"...","notes":"..."}
Tell them a team member will follow up shortly.
--- End Deal Capture ---"""
    try: reply=openai_call([{'role':'system','content':system}]+messages)
    except Exception as e: db.close(); return jsonify({'error':str(e)}),500
    db.execute('INSERT INTO conversations (bot_id,session_id,role,message) VALUES (?,?,?,?)',(bot['id'],session_id,'assistant',reply)); db.commit(); db.close()
    deal_link=None; m=re.search(r'DEAL_READY:(\{[^\n]+\})',reply)
    if m:
        try:
            deal_data=json.loads(m.group(1)); deal_data['session_id']=session_id; deal_data['messages']=messages
            def _bg():
                try:
                    req=urllib.request.Request(f'http://localhost:3005/api/deals/from-chat/{bot_token}',data=json.dumps(deal_data).encode(),headers={'Content-Type':'application/json'},method='POST')
                    with urllib.request.urlopen(req,timeout=10) as r: res=json.loads(r.read()); print(f'[deal] id={res.get("deal_id")}')
                except Exception as e: print(f'[deal] bg: {e}')
            threading.Thread(target=_bg,daemon=True).start()
            deal_link=f'{BASE_URL}/dashboard?deal=pending'
            reply=re.sub(r'\nDEAL_READY:\{[^\n]+\}','',reply).strip()
        except Exception as e: print(f'[deal-parse] {e}')
    return jsonify({'reply':reply,'session_id':session_id,'deal_link':deal_link})

@app.route('/api/lead/<bot_token>', methods=['POST'])
def capture_lead(bot_token):
    db=get_db(); bot=db.execute('SELECT * FROM bots WHERE token=?',(bot_token,)).fetchone()
    if not bot: db.close(); return jsonify({'error':'Bot not found'}),404
    d=request.json or {}
    db.execute('INSERT INTO leads (bot_id,name,email,phone,notes,status) VALUES (?,?,?,?,?,?)',(bot['id'],d.get('name'),d.get('email'),d.get('phone'),d.get('notes'),'new')); db.commit()
    org=db.execute('SELECT * FROM organizations WHERE id=?',(bot['org_id'],)).fetchone()
    owner=db.execute('SELECT * FROM users WHERE id=?',(org['owner_id'],)).fetchone()
    if owner:
        send_email(owner['email'],f'New lead from {bot["name"]}',
            f'<h2>New Lead!</h2><p><b>Name:</b> {d.get("name","N/A")}</p><p><b>Email:</b> {d.get("email","N/A")}</p><p><a href="{BASE_URL}/dashboard">View →</a></p>')
    db.close(); return jsonify({'success':True})

@app.route('/api/config/<bot_token>', methods=['GET'])
def get_config(bot_token):
    db=get_db(); bot=db.execute('SELECT id,name,greeting,color,lead_capture FROM bots WHERE token=?',(bot_token,)).fetchone()
    db.close()
    if not bot: return jsonify({'error':'Not found'}),404
    return jsonify(dict(bot))

@app.route('/embed.js')
def embed_script():
    script=r"""(function(){
'use strict';
var t=document.currentScript&&document.currentScript.getAttribute('data-token');
if(!t)return;
var base='https://peekbot.cana.chat',cfg=null,hist=[],sid='pb_'+Math.random().toString(36).substr(2,9);
var pos=document.currentScript.getAttribute('data-position')||'right';
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
fetch(base+'/api/config/'+t).then(function(r){return r.json();}).then(function(c){cfg=c;inject();}).catch(function(){});
function inject(){
  var host=document.createElement('div');host.id='peekbot-widget';
  host.style.cssText='position:fixed;bottom:1.5rem;z-index:2147483647;'+(pos==='left'?'left:1.5rem':'right:1.5rem');
  document.body.appendChild(host);var shadow=host.attachShadow({mode:'closed'});
  var style=document.createElement('style');
  style.textContent=[
    ':host{all:initial;font-family:system-ui,-apple-system,sans-serif;font-size:14px;}',
    '#pb-btn{width:52px;height:52px;border-radius:50%;background:'+cfg.color+';border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(0,0,0,.25);color:white;font-size:1.4rem;transition:transform .2s;}',
    '#pb-btn:hover{transform:scale(1.08);}',
    '#pb-panel{position:absolute;bottom:4rem;'+(pos==='left'?'left:0':'right:0')+';width:340px;background:#fff;border-radius:16px;display:none;flex-direction:column;overflow:hidden;border:1px solid rgba(0,0,0,.1);max-height:520px;box-shadow:0 8px 40px rgba(0,0,0,.18);}',
    '#pb-panel.open{display:flex;}',
    '#pb-head{background:'+cfg.color+';padding:.85rem 1rem;display:flex;align-items:center;gap:.6rem;color:#fff;}',
    '#pb-head-name{font-weight:600;font-size:.9rem;flex:1;}',
    '#pb-close{background:none;border:none;color:rgba(255,255,255,.8);cursor:pointer;font-size:1.1rem;padding:0;}',
    '#pb-msgs{flex:1;overflow-y:auto;padding:.85rem;display:flex;flex-direction:column;gap:.6rem;background:#f7f7f8;}',
    '.pb-msg{display:flex;gap:.4rem;max-width:100%;}',
    '.pb-msg.u{justify-content:flex-end;}',
    '.pb-bubble{max-width:82%;padding:.55rem .8rem;border-radius:14px;font-size:.8rem;line-height:1.5;word-break:break-word;}',
    '.pb-msg.b .pb-bubble{background:#fff;color:#111;border:1px solid #e5e5e5;}',
    '.pb-msg.u .pb-bubble{background:'+cfg.color+';color:#fff;}',
    '.pb-deal-card{background:#f0fdf4;border:1.5px solid #22c55e;border-radius:12px;padding:.85rem 1rem;margin:.25rem 0;}',
    '.pb-deal-title{font-weight:700;color:#15803d;font-size:.82rem;margin-bottom:.25rem;}',
    '.pb-deal-sub{font-size:.75rem;color:#166534;margin-bottom:.5rem;}',
    '.pb-deal-link{display:inline-block;background:#16a34a;color:white;padding:.4rem 1rem;border-radius:8px;text-decoration:none;font-size:.75rem;font-weight:600;}',
    '.pb-deal-link:hover{background:#15803d;}',
    '#pb-form{background:#fff;padding:.6rem .75rem;border-top:1px solid #f0f0f0;display:flex;gap:.4rem;}',
    '#pb-input{flex:1;border:1px solid #e5e5e5;border-radius:20px;padding:.4rem .85rem;font-size:.8rem;outline:none;}',
    '#pb-input:focus{border-color:'+cfg.color+';}',
    '#pb-send{width:32px;height:32px;border-radius:50%;background:'+cfg.color+';border:none;cursor:pointer;color:#fff;font-size:1rem;display:flex;align-items:center;justify-content:center;flex-shrink:0;}',
    '.pb-typing{display:flex;gap:4px;align-items:center;padding:.4rem;}',
    '.pb-dot{width:6px;height:6px;border-radius:50%;background:#999;animation:pb-bounce .8s infinite;}',
    '.pb-dot:nth-child(2){animation-delay:.15s}.pb-dot:nth-child(3){animation-delay:.3s}',
    '@keyframes pb-bounce{0%,80%,100%{transform:translateY(0)}40%{transform:translateY(-6px)}}',
  ].join('');
  shadow.appendChild(style);
  var panel=document.createElement('div');panel.id='pb-panel';
  panel.innerHTML='<div id="pb-head"><div style="width:28px;height:28px;border-radius:50%;background:rgba(255,255,255,.25);display:flex;align-items:center;justify-content:center;font-size:.9rem;">'+esc(cfg.name[0])+'</div>'+
    '<div id="pb-head-name">'+esc(cfg.name)+'</div><button id="pb-close">✕</button></div>'+
    '<div id="pb-msgs" role="log" aria-live="polite"></div>'+
    '<div id="pb-form"><input id="pb-input" type="text" placeholder="Type a message..."/><button id="pb-send">➤</button></div>';
  var btn=document.createElement('button');btn.id='pb-btn';btn.innerHTML='💬';
  shadow.appendChild(panel);shadow.appendChild(btn);
  var msgs=shadow.getElementById('pb-msgs'),inp=shadow.getElementById('pb-input'),open=false;
  btn.addEventListener('click',function(){open=!open;panel.classList.toggle('open',open);btn.innerHTML=open?'✕':'💬';if(open)inp.focus();});
  shadow.getElementById('pb-close').addEventListener('click',function(){open=false;panel.classList.remove('open');btn.innerHTML='💬';});
  shadow.getElementById('pb-send').addEventListener('click',function(){send(inp.value);});
  inp.addEventListener('keypress',function(e){if(e.key==='Enter')send(inp.value);});
  var leadStep=0,leadData={},LEAD_TRIGGER=3;
  function add(text,role){
    var d=document.createElement('div');d.className='pb-msg '+(role==='u'?'u':'b');
    var bub=document.createElement('div');bub.className='pb-bubble';bub.textContent=text;
    d.appendChild(bub);msgs.appendChild(d);msgs.scrollTop=msgs.scrollHeight;return d;
  }
  function addDealCard(name,link){
    var d=document.createElement('div');d.className='pb-msg b';
    var card=document.createElement('div');card.className='pb-deal-card';
    card.innerHTML='<div class="pb-deal-title">🔑 Deal Created!</div><div class="pb-deal-sub">'+esc(name)+'</div><a class="pb-deal-link" href="'+esc(link)+'" target="_blank">View in Dashboard →</a>';
    d.appendChild(card);msgs.appendChild(d);msgs.scrollTop=msgs.scrollHeight;
  }
  function addTyping(){
    var d=document.createElement('div');d.className='pb-msg b';d.id='pb-typing';
    d.innerHTML='<div class="pb-bubble pb-typing"><div class="pb-dot"></div><div class="pb-dot"></div><div class="pb-dot"></div></div>';
    msgs.appendChild(d);msgs.scrollTop=msgs.scrollHeight;return d;
  }
  var botCount=0;
  function handleReply(text,dealLink){
    botCount++;add(text,'b');
    if(dealLink&&dealLink.indexOf('deal=pending')===-1)setTimeout(function(){addDealCard('Your inquiry has been logged',dealLink);},800);
    if(cfg.lead_capture&&botCount===LEAD_TRIGGER&&leadStep===0)setTimeout(promptLead,800);
  }
  function promptLead(){leadStep=1;add("Want someone to follow up with you? I can take your name and email.",'b');}
  async function send(text){
    text=text.trim();if(!text)return;inp.value='';
    if(leadStep===1){var low=text.toLowerCase();
      if(low.match(/yes|sure|ok|yeah|please/)){leadStep=2;add(text,'u');add("Great! What's your name?",'b');return;}
      else if(low.match(/no|nope|skip/)){leadStep=-1;add(text,'u');add("No problem! What else can I help with?",'b');return;}}
    if(leadStep===2){leadData.name=text;leadStep=3;add(text,'u');add("Thanks "+esc(text)+"! And your email?",'b');return;}
    if(leadStep===3){leadData.email=text;leadStep=4;add(text,'u');
      fetch(base+'/api/lead/'+t,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(leadData)});
      add("Got it! Someone will be in touch. What else can I help with?",'b');return;}
    add(text,'u');hist.push({role:'user',content:text});
    var typing=addTyping();inp.disabled=true;
    try{
      var res=await fetch(base+'/api/chat/'+t,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages:hist,session_id:sid})});
      var data=await res.json();typing.remove();inp.disabled=false;inp.focus();
      var reply=data.reply||data.error||'Something went wrong.';
      hist.push({role:'assistant',content:reply});handleReply(reply,data.deal_link);
      if(data.session_id)sid=data.session_id;
    }catch(e){typing.remove();inp.disabled=false;add('Connection error. Please try again.','b');}
  }
  add(cfg.greeting||'Hi! How can I help?','b');
}
})();"""
    resp=Response(script,mimetype='application/javascript'); resp.headers['Cache-Control']='public, max-age=300'; return resp

def qb_get_token(org,db):
    ea=org['qb_token_expires_at']
    if ea:
        try:
            exp=datetime.datetime.fromisoformat(ea)
            if datetime.datetime.utcnow()<exp-datetime.timedelta(minutes=5): return org['qb_access_token']
        except: pass
    creds=base64.b64encode(f'{QB_CLIENT_ID}:{QB_CLIENT_SECRET}'.encode()).decode()
    data=urllib.parse.urlencode({'grant_type':'refresh_token','refresh_token':org['qb_refresh_token']}).encode()
    req=urllib.request.Request('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',data=data,
        headers={'Authorization':f'Basic {creds}','Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'})
    with urllib.request.urlopen(req) as r: tokens=json.loads(r.read())
    new_exp=(datetime.datetime.utcnow()+datetime.timedelta(seconds=tokens.get('expires_in',3600))).isoformat()
    db.execute('UPDATE organizations SET qb_access_token=?,qb_refresh_token=?,qb_token_expires_at=? WHERE id=?',
        (tokens['access_token'],tokens.get('refresh_token',org['qb_refresh_token']),new_exp,org['id'])); db.commit()
    return tokens['access_token']

@app.route('/api/quickbooks/connect')
def qb_connect():
    token=request.args.get('token','')
    try: jwt.decode(token,SECRET,algorithms=['HS256'])
    except: return jsonify({'error':'Unauthorized'}),401
    state=base64.urlsafe_b64encode(json.dumps({'token':token}).encode()).decode()
    params=urllib.parse.urlencode({'client_id':QB_CLIENT_ID,'scope':'com.intuit.quickbooks.accounting','redirect_uri':QB_REDIRECT_URI,'response_type':'code','access_type':'offline','state':state})
    return redirect(f'https://appcenter.intuit.com/connect/oauth2?{params}')

@app.route('/api/quickbooks/callback')
def qb_callback():
    if request.args.get('error'): return redirect('/?qb_error=1')
    code=request.args.get('code',''); state=request.args.get('state',''); realm_id=request.args.get('realmId','')
    try:
        sd=json.loads(base64.urlsafe_b64decode(state+'==')); payload=jwt.decode(sd['token'],SECRET,algorithms=['HS256']); user_id=payload['user_id']
    except: return redirect('/?qb_error=1')
    creds=base64.b64encode(f'{QB_CLIENT_ID}:{QB_CLIENT_SECRET}'.encode()).decode()
    data=urllib.parse.urlencode({'grant_type':'authorization_code','code':code,'redirect_uri':QB_REDIRECT_URI}).encode()
    try:
        req=urllib.request.Request('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',data=data,
            headers={'Authorization':f'Basic {creds}','Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'})
        with urllib.request.urlopen(req) as r: tokens=json.loads(r.read())
    except: return redirect('/?qb_error=1')
    exp=(datetime.datetime.utcnow()+datetime.timedelta(seconds=tokens.get('expires_in',3600))).isoformat()
    db=get_db(); user=get_user(user_id,db)
    db.execute('UPDATE organizations SET qb_realm_id=?,qb_access_token=?,qb_refresh_token=?,qb_token_expires_at=? WHERE id=?',
        (realm_id,tokens['access_token'],tokens['refresh_token'],exp,user['org_id'])); db.commit(); db.close()
    return redirect('/?qb_connected=1')

@app.route('/api/quickbooks/status')
def qb_status():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    org=db.execute('SELECT qb_realm_id,qb_access_token FROM organizations WHERE id=?',(user['org_id'],)).fetchone()
    db.close(); return jsonify({'connected':bool(org and org['qb_access_token'] and org['qb_realm_id']),'realm_id':org['qb_realm_id'] if org else None})

@app.route('/api/quickbooks/sync', methods=['POST'])
def qb_sync():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    org=db.execute('SELECT * FROM organizations WHERE id=?',(user['org_id'],)).fetchone()
    if not org or not org['qb_access_token']: db.close(); return jsonify({'error':'QuickBooks not connected'}),400
    bot=get_org_bot(user['org_id'],db)
    if not bot: db.close(); return jsonify({'error':'No bot found for this organization'}),400
    try: access_token=qb_get_token(org,db)
    except Exception as e: db.close(); return jsonify({'error':f'Token refresh failed: {e}'}),502
    query=urllib.parse.quote("SELECT * FROM Customer MAXRESULTS 100")
    req=urllib.request.Request(f'https://quickbooks.api.intuit.com/v3/company/{org["qb_realm_id"]}/query?query={query}&minorversion=65',headers={'Authorization':f'Bearer {access_token}','Accept':'application/json'})
    try:
        with urllib.request.urlopen(req) as r: qb_data=json.loads(r.read())
    except Exception as e: db.close(); return jsonify({'error':f'QB API error: {e}'}),502
    customers=qb_data.get('QueryResponse',{}).get('Customer',[])
    synced=0
    for cust in customers:
        email=(cust.get('PrimaryEmailAddr') or {}).get('Address','').strip(); name=cust.get('DisplayName','').strip()
        if not email: continue
        if not db.execute('SELECT id FROM leads WHERE email=? AND bot_id=?',(email,bot['id'])).fetchone():
            db.execute('INSERT INTO leads (bot_id,name,email,notes,status,created_at) VALUES (?,?,?,?,?,?)',
                (bot['id'],name,email,'Synced from QuickBooks','new',datetime.datetime.now(datetime.timezone.utc).isoformat())); synced+=1
    db.commit(); db.close(); return jsonify({'synced':synced,'total':len(customers)})

@app.route('/api/quickbooks/disconnect', methods=['POST'])
def qb_disconnect():
    uid=verify_token(request)
    if not uid: return jsonify({'error':'Unauthorized'}),401
    db=get_db(); user=get_user(uid,db)
    db.execute('UPDATE organizations SET qb_realm_id=NULL,qb_access_token=NULL,qb_refresh_token=NULL,qb_token_expires_at=NULL WHERE id=?',(user['org_id'],))
    db.commit(); db.close(); return jsonify({'ok':True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3005, debug=False)
