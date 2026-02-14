"""Migrate articles from MongoDB BSON backup to SQLite blog."""
import bson
import sqlite3
import os
import re
import base64
import hashlib
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

BSON_PATH = os.environ.get('BSON_PATH', 'articles.bson')
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'blog.db'))
UPLOAD_DIR = os.environ.get('UPLOAD_DIR', os.path.join(os.path.dirname(__file__), 'static/uploads'))

os.makedirs(UPLOAD_DIR, exist_ok=True)

def slugify(text):
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')

def save_base64_image(b64_string, prefix):
    """Save a base64 data URI to a file, return the relative URL path."""
    match = re.match(r'data:image/(\w+);base64,(.*)', b64_string, re.DOTALL)
    if not match:
        return None
    ext = match.group(1)
    if ext == 'jpeg':
        ext = 'jpg'
    raw = match.group(2)
    try:
        img_data = base64.b64decode(raw)
    except Exception:
        return None
    # Use hash for unique filename
    h = hashlib.md5(img_data).hexdigest()[:12]
    filename = f"{prefix}_{h}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        with open(filepath, 'wb') as f:
            f.write(img_data)
    return f"/static/uploads/{filename}"

def extract_inline_images(content, slug):
    """Replace all inline base64 images in content with file references."""
    counter = [0]
    def replacer(match):
        full_match = match.group(0)
        # Extract the base64 data URI
        data_uri_match = re.search(r'data:image/\w+;base64,[A-Za-z0-9+/=\s]+', full_match)
        if not data_uri_match:
            return full_match
        data_uri = data_uri_match.group(0).replace('\n', '').replace('\r', '').replace(' ', '')
        counter[0] += 1
        url = save_base64_image(data_uri, f"{slug}_img{counter[0]}")
        if url:
            return f"![]({url})"
        return full_match

    # Match markdown images with base64 data
    result = re.sub(r'!\[([^\]]*)\]\(data:image/[^\)]+\)', replacer, content)
    return result

def migrate():
    # Read BSON
    with open(BSON_PATH, 'rb') as f:
        articles = bson.decode_all(f.read())

    print(f"Found {len(articles)} articles in BSON backup")

    # Connect to SQLite
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    c = conn.cursor()

    # Get or create admin user
    admin_user = os.environ.get('BLOG_ADMIN_USER', 'admin')
    admin_pass = os.environ.get('BLOG_ADMIN_PASS', 'changeme')
    c.execute("SELECT id FROM users WHERE username = ?", (admin_user,))
    user = c.fetchone()
    if not user:
        c.execute(
            "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
            (admin_user, generate_password_hash(admin_pass), admin_user)
        )
        conn.commit()
        c.execute("SELECT id FROM users WHERE username = ?", (admin_user,))
        user = c.fetchone()
    author_id = user[0]

    migrated = 0
    skipped = 0

    for article in articles:
        title = article.get('title', 'Untitled')
        slug = slugify(title)
        tags = article.get('tags', [])
        content = article.get('content', '')
        cover_b64 = article.get('coverImage', '')
        is_private = article.get('isPrivate', False)
        created_at = article.get('createdAt', None)

        # Check if already migrated
        c.execute("SELECT id FROM posts WHERE slug = ?", (slug,))
        if c.fetchone():
            print(f"  SKIP (exists): {title}")
            skipped += 1
            continue

        print(f"  Migrating: {title}")
        print(f"    Tags: {tags}")
        print(f"    Content: {len(content)} chars")

        # Save cover image
        cover_url = ''
        if cover_b64:
            cover_url = save_base64_image(cover_b64, f"cover_{slug}")
            if cover_url:
                print(f"    Cover image saved: {cover_url}")

        # Extract inline base64 images from content
        content = extract_inline_images(content, slug)

        # Generate excerpt
        plain = re.sub(r'[#*`\[\]()!]', '', content)
        plain = re.sub(r'data:image/[^\s]+', '', plain)  # remove any remaining data URIs
        plain = plain.strip()
        excerpt = plain[:200] + '...' if len(plain) > 200 else plain

        # Set published based on isPrivate
        published = 0 if is_private else 1

        # Insert post
        c.execute('''
            INSERT INTO posts (title, slug, content, excerpt, cover_image, author_id, published, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, slug, content, excerpt, cover_url, author_id, published, created_at))
        post_id = c.lastrowid

        # Insert tags
        for tag_name in tags:
            tag_slug = slugify(tag_name)
            c.execute("SELECT id FROM tags WHERE slug = ?", (tag_slug,))
            existing = c.fetchone()
            if existing:
                tag_id = existing[0]
            else:
                c.execute("INSERT INTO tags (name, slug) VALUES (?, ?)", (tag_name, tag_slug))
                tag_id = c.lastrowid
            c.execute("INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?, ?)", (post_id, tag_id))

        migrated += 1

    conn.commit()
    conn.close()
    print(f"\nDone! Migrated: {migrated}, Skipped: {skipped}")

if __name__ == '__main__':
    migrate()
