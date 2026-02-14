import ssl
import sqlite3
import os
import math
import re
import threading
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g, abort, jsonify
)
from werkzeug.serving import make_server
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup
import markdown
import bleach
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

def _load_or_create_secret_key():
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()
    key = os.urandom(32)
    with open(key_path, 'wb') as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    return key

app.secret_key = _load_or_create_secret_key()
app.config['DATABASE'] = os.environ.get('DB_PATH', os.path.join(app.root_path, 'blog.db'))
app.config['POSTS_PER_PAGE'] = 4
app.config['CANONICAL_HOST'] = os.environ.get('CANONICAL_HOST', '').strip()
trusted_hosts = [h.strip().lower() for h in os.environ.get('TRUSTED_HOSTS', '').split(',') if h.strip()]
if not trusted_hosts:
    trusted_hosts = ['localhost', '127.0.0.1', '::1']
app.config['TRUSTED_HOSTS_SET'] = set(trusted_hosts)

# --- Security: CSRF Protection ---
csrf = CSRFProtect(app)

# --- Security: Rate Limiting ---
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# --- Security: Cookie Flags ---
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- Security: Response Headers ---

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' https: data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none';"
    )
    return response

# --- Database ---

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            content TEXT NOT NULL,
            excerpt TEXT,
            cover_image TEXT,
            author_id INTEGER NOT NULL,
            published INTEGER DEFAULT 0,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            slug TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS post_tags (
            post_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            PRIMARY KEY (post_id, tag_id),
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    # Create default user if no users exist
    existing = db.execute('SELECT id FROM users LIMIT 1').fetchone()
    if not existing:
        admin_user = os.environ.get('BLOG_ADMIN_USER', 'admin')
        admin_pass = os.environ.get('BLOG_ADMIN_PASS', 'changeme')
        db.execute(
            'INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)',
            (admin_user, generate_password_hash(admin_pass), admin_user)
        )
    # Create about page if not exists
    existing_page = db.execute('SELECT id FROM pages WHERE slug = ?', ('about',)).fetchone()
    if not existing_page:
        db.execute(
            'INSERT INTO pages (title, slug, content) VALUES (?, ?, ?)',
            ('About', 'about', '# About\n\nWelcome to my blog.')
        )
    db.commit()

# --- Helpers ---

def slugify(text):
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')

def reading_time(content):
    word_count = len(content.split())
    minutes = max(1, round(word_count / 200))
    return f"{minutes} min read"

BLEACH_ALLOWED_TAGS = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'p', 'br', 'hr', 'strong', 'em', 'b', 'i', 'u', 's', 'del',
    'a', 'img',
    'ul', 'ol', 'li',
    'blockquote', 'pre', 'code', 'span', 'div',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'dl', 'dt', 'dd', 'abbr', 'sup', 'sub',
]
BLEACH_ALLOWED_ATTRS = {
    'a': ['href', 'title', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'code': ['class'],
    'span': ['class'],
    'div': ['class'],
    'td': ['align'],
    'th': ['align'],
    'abbr': ['title'],
}
BLEACH_ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

def render_markdown(text):
    raw_html = markdown.markdown(
        text,
        extensions=['fenced_code', 'codehilite', 'tables', 'toc', 'nl2br'],
        extension_configs={
            'codehilite': {'css_class': 'highlight', 'linenums': False}
        }
    )
    clean_html = bleach.clean(
        raw_html,
        tags=BLEACH_ALLOWED_TAGS,
        attributes=BLEACH_ALLOWED_ATTRS,
        protocols=BLEACH_ALLOWED_PROTOCOLS,
        strip=True
    )
    return Markup(clean_html)

app.jinja_env.filters['markdown'] = render_markdown
app.jinja_env.filters['reading_time'] = reading_time

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def is_trusted_redirect_host(host_header):
    host = host_header.split(':', 1)[0].strip().strip('[]').lower()
    return host in app.config['TRUSTED_HOSTS_SET']

def get_all_tags():
    db = get_db()
    return db.execute('''
        SELECT t.*, COUNT(pt.post_id) as post_count
        FROM tags t
        JOIN post_tags pt ON t.id = pt.tag_id
        JOIN posts p ON pt.post_id = p.id AND p.published = 1
        GROUP BY t.id
        ORDER BY post_count DESC
    ''').fetchall()

# --- Context Processor ---

@app.context_processor
def inject_globals():
    return {
        'all_tags': get_all_tags,
        'now': datetime.now()
    }

# --- Public Routes ---

@app.route('/')
def index():
    return post_list(1)

@app.route('/page/<int:page>/')
def post_list(page=1):
    db = get_db()
    per_page = app.config['POSTS_PER_PAGE']
    offset = (page - 1) * per_page

    total = db.execute('SELECT COUNT(*) FROM posts WHERE published = 1').fetchone()[0]
    total_pages = max(1, math.ceil(total / per_page))

    if page < 1 or page > total_pages:
        abort(404)

    posts = db.execute('''
        SELECT p.*, u.display_name as author_name
        FROM posts p
        JOIN users u ON p.author_id = u.id
        WHERE p.published = 1
        ORDER BY p.sort_order ASC, p.created_at DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()

    # Get tags for each post
    posts_with_tags = []
    for post in posts:
        tags = db.execute('''
            SELECT t.* FROM tags t
            JOIN post_tags pt ON t.id = pt.tag_id
            WHERE pt.post_id = ?
        ''', (post['id'],)).fetchall()
        posts_with_tags.append({'post': post, 'tags': tags})

    return render_template('index.html',
        posts=posts_with_tags,
        page=page,
        total_pages=total_pages,
        active_tag=None
    )

@app.route('/post/<slug>/')
def post_detail(slug):
    db = get_db()
    post = db.execute('''
        SELECT p.*, u.display_name as author_name
        FROM posts p
        JOIN users u ON p.author_id = u.id
        WHERE p.slug = ? AND p.published = 1
    ''', (slug,)).fetchone()

    if not post:
        abort(404)

    tags = db.execute('''
        SELECT t.* FROM tags t
        JOIN post_tags pt ON t.id = pt.tag_id
        WHERE pt.post_id = ?
    ''', (post['id'],)).fetchall()

    return render_template('post.html', post=post, tags=tags)

@app.route('/tag/<slug>/')
def tag_posts(slug):
    return tag_posts_page(slug, 1)

@app.route('/tag/<slug>/page/<int:page>/')
def tag_posts_page(slug, page=1):
    db = get_db()
    tag = db.execute('SELECT * FROM tags WHERE slug = ?', (slug,)).fetchone()
    if not tag:
        abort(404)

    per_page = app.config['POSTS_PER_PAGE']
    offset = (page - 1) * per_page

    total = db.execute('''
        SELECT COUNT(*) FROM posts p
        JOIN post_tags pt ON p.id = pt.post_id
        WHERE pt.tag_id = ? AND p.published = 1
    ''', (tag['id'],)).fetchone()[0]
    total_pages = max(1, math.ceil(total / per_page))

    posts = db.execute('''
        SELECT p.*, u.display_name as author_name
        FROM posts p
        JOIN users u ON p.author_id = u.id
        JOIN post_tags pt ON p.id = pt.post_id
        WHERE pt.tag_id = ? AND p.published = 1
        ORDER BY p.sort_order ASC, p.created_at DESC
        LIMIT ? OFFSET ?
    ''', (tag['id'], per_page, offset)).fetchall()

    posts_with_tags = []
    for post in posts:
        ptags = db.execute('''
            SELECT t.* FROM tags t
            JOIN post_tags pt ON t.id = pt.tag_id
            WHERE pt.post_id = ?
        ''', (post['id'],)).fetchall()
        posts_with_tags.append({'post': post, 'tags': ptags})

    return render_template('tag.html',
        tag=tag,
        posts=posts_with_tags,
        page=page,
        total_pages=total_pages,
        active_tag=tag
    )

@app.route('/about/')
def about():
    db = get_db()
    page = db.execute('SELECT * FROM pages WHERE slug = ?', ('about',)).fetchone()
    return render_template('about.html', page=page)

@app.route('/search/')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return render_template('search.html', posts=[], query='')

    db = get_db()
    escaped_query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    posts = db.execute('''
        SELECT p.*, u.display_name as author_name
        FROM posts p
        JOIN users u ON p.author_id = u.id
        WHERE p.published = 1 AND (p.title LIKE ? ESCAPE '\\' OR p.content LIKE ? ESCAPE '\\')
        ORDER BY p.sort_order ASC, p.created_at DESC
    ''', (f'%{escaped_query}%', f'%{escaped_query}%')).fetchall()

    posts_with_tags = []
    for post in posts:
        tags = db.execute('''
            SELECT t.* FROM tags t
            JOIN post_tags pt ON t.id = pt.tag_id
            WHERE pt.post_id = ?
        ''', (post['id'],)).fetchall()
        posts_with_tags.append({'post': post, 'tags': tags})

    return render_template('search.html', posts=posts_with_tags, query=query)

# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['display_name'] = user['display_name']
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin/login.html')

@app.route('/admin/logout', methods=['POST'])
@login_required
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/')
@login_required
def admin_dashboard():
    db = get_db()
    posts = db.execute('''
        SELECT p.*, u.display_name as author_name
        FROM posts p
        JOIN users u ON p.author_id = u.id
        ORDER BY p.sort_order ASC, p.created_at DESC
    ''').fetchall()
    return render_template('admin/dashboard.html', posts=posts)

@app.route('/admin/post/new', methods=['GET', 'POST'])
@login_required
def admin_new_post():
    if request.method == 'POST':
        return save_post(None)
    return render_template('admin/edit_post.html', post=None, post_tags=[])

@app.route('/admin/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_post(post_id):
    db = get_db()
    if request.method == 'POST':
        return save_post(post_id)
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        abort(404)
    tags = db.execute('''
        SELECT t.name FROM tags t
        JOIN post_tags pt ON t.id = pt.tag_id
        WHERE pt.post_id = ?
    ''', (post_id,)).fetchall()
    tag_names = ', '.join([t['name'] for t in tags])
    return render_template('admin/edit_post.html', post=post, post_tags=tag_names)

def save_post(post_id):
    db = get_db()
    title = request.form['title'].strip()
    slug = request.form.get('slug', '').strip() or slugify(title)
    content = request.form['content']
    excerpt = request.form.get('excerpt', '').strip()
    cover_image = request.form.get('cover_image', '').strip()
    published = 1 if 'published' in request.form else 0
    tag_string = request.form.get('tags', '').strip()

    if not excerpt:
        plain = re.sub(r'[#*`\[\]()]', '', content)
        excerpt = plain[:200] + '...' if len(plain) > 200 else plain

    if post_id:
        db.execute('''
            UPDATE posts SET title=?, slug=?, content=?, excerpt=?, cover_image=?,
            published=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
        ''', (title, slug, content, excerpt, cover_image, published, post_id))
    else:
        cursor = db.execute('''
            INSERT INTO posts (title, slug, content, excerpt, cover_image, author_id, published)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (title, slug, content, excerpt, cover_image, session['user_id'], published))
        post_id = cursor.lastrowid

    # Handle tags
    db.execute('DELETE FROM post_tags WHERE post_id = ?', (post_id,))
    if tag_string:
        for tag_name in [t.strip() for t in tag_string.split(',') if t.strip()]:
            tag_slug = slugify(tag_name)
            existing = db.execute('SELECT id FROM tags WHERE slug = ?', (tag_slug,)).fetchone()
            if existing:
                tag_id = existing['id']
            else:
                cursor = db.execute('INSERT INTO tags (name, slug) VALUES (?, ?)', (tag_name, tag_slug))
                tag_id = cursor.lastrowid
            db.execute('INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?, ?)', (post_id, tag_id))

    db.commit()
    flash('Post saved successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required
def admin_delete_post(post_id):
    db = get_db()
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash('Post deleted', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reorder', methods=['POST'])
@login_required
def admin_reorder():
    data = request.get_json()
    if not data or 'order' not in data:
        return jsonify({'error': 'invalid'}), 400
    db = get_db()
    for i, post_id in enumerate(data['order']):
        db.execute('UPDATE posts SET sort_order = ? WHERE id = ?', (i, int(post_id)))
    db.commit()
    return jsonify({'ok': True})

@app.route('/admin/about', methods=['GET', 'POST'])
@login_required
def admin_about():
    db = get_db()
    if request.method == 'POST':
        content = request.form['content']
        db.execute('UPDATE pages SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?',
                   (content, 'about'))
        db.commit()
        flash('About page updated', 'success')
        return redirect(url_for('admin_about'))
    page = db.execute('SELECT * FROM pages WHERE slug = ?', ('about',)).fetchone()
    return render_template('admin/edit_about.html', page=page)

# --- Error Handlers ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# --- Init ---

with app.app_context():
    init_db()

if __name__ == '__main__':
    CERT_PATH = os.environ.get('SSL_CERT_PATH', 'ssl/fullchain.pem')
    KEY_PATH = os.environ.get('SSL_KEY_PATH', 'ssl/privkey.pem')
    BIND_HOST = os.environ.get('BIND_HOST', '0.0.0.0')
    HTTP_PORT = int(os.environ.get('HTTP_PORT', '80'))
    HTTPS_PORT = int(os.environ.get('HTTPS_PORT', '443'))

    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        # HTTPS on 443 + HTTP redirect on 80
        from flask import Flask as _F
        redirect_app = _F(__name__)

        @redirect_app.before_request
        def https_redirect():
            if not request.is_secure:
                host_header = request.host
                if not is_trusted_redirect_host(host_header):
                    abort(400)
                target_host = app.config['CANONICAL_HOST'] or host_header
                query = f"?{request.query_string.decode('utf-8')}" if request.query_string else ''
                url = f"https://{target_host}{request.path}{query}"
                return redirect(url, code=301)

        # HTTP redirect server (port 80)
        def run_http_redirect():
            http_server = make_server(BIND_HOST, HTTP_PORT, redirect_app)
            print(f' * HTTP redirect server on port {HTTP_PORT}')
            http_server.serve_forever()

        t = threading.Thread(target=run_http_redirect, daemon=True)
        t.start()

        # HTTPS server (port 443)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_PATH, KEY_PATH)
        print(f' * HTTPS server on port {HTTPS_PORT}')
        app.run(host=BIND_HOST, port=HTTPS_PORT, ssl_context=ctx)
    else:
        # Fallback: HTTP only
        print(f' * SSL certs not found, running HTTP on port {HTTP_PORT}')
        app.run(host=BIND_HOST, port=HTTP_PORT)
