"""Seed the database with sample posts."""
import sqlite3
import os
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'blog.db'))

def seed():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Ensure admin exists
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

    # Sample tags
    tags = ['Python', 'Security', 'Web Development', 'Linux', 'Tutorial', 'DevOps']
    tag_ids = {}
    for tag_name in tags:
        slug = tag_name.lower().replace(' ', '-')
        c.execute("INSERT OR IGNORE INTO tags (name, slug) VALUES (?, ?)", (tag_name, slug))
        c.execute("SELECT id FROM tags WHERE slug = ?", (slug,))
        tag_ids[tag_name] = c.fetchone()[0]

    # Sample posts
    posts = [
        {
            'title': 'Getting Started with Flask and SQLite',
            'slug': 'getting-started-flask-sqlite',
            'content': """# Getting Started with Flask and SQLite

Flask is a lightweight WSGI web application framework in Python. Combined with SQLite, it provides a powerful yet simple stack for building web applications.

## Why Flask + SQLite?

- **Lightweight**: No external database server needed
- **Simple**: Easy to set up and deploy
- **Portable**: The entire database is a single file

## Setting Up

```python
from flask import Flask
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn
```

## Creating Tables

```sql
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

This combination is perfect for personal blogs, small projects, and prototypes.
""",
            'excerpt': 'Learn how to build a web application using Flask and SQLite - a lightweight yet powerful combination for personal projects.',
            'tags': ['Python', 'Web Development', 'Tutorial']
        },
        {
            'title': 'Linux Security Hardening Basics',
            'slug': 'linux-security-hardening-basics',
            'content': """# Linux Security Hardening Basics

Security hardening is the process of reducing a system's attack surface. Here are fundamental steps for securing a Linux server.

## 1. Keep System Updated

```bash
sudo apt update && sudo apt upgrade -y
```

## 2. Configure Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
```

## 3. SSH Hardening

Edit `/etc/ssh/sshd_config`:

```
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
```

## 4. Fail2ban

```bash
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

## 5. File Permissions

Always follow the principle of least privilege. Review file permissions regularly:

```bash
find / -perm -4000 -type f 2>/dev/null
```

These are just the basics. A comprehensive security strategy involves many more layers.
""",
            'excerpt': 'Fundamental steps for securing a Linux server - from firewall configuration to SSH hardening and beyond.',
            'tags': ['Security', 'Linux', 'Tutorial']
        },
        {
            'title': 'Python Virtual Environments Explained',
            'slug': 'python-virtual-environments-explained',
            'content': """# Python Virtual Environments Explained

Virtual environments are isolated Python environments that allow you to manage dependencies per-project.

## Creating a Virtual Environment

```bash
python3 -m venv myenv
source myenv/bin/activate
```

## Why Use Virtual Environments?

1. **Dependency Isolation**: Each project has its own dependencies
2. **Version Control**: Different projects can use different package versions
3. **Clean Development**: System Python stays unmodified

## Managing Dependencies

```bash
pip install flask
pip freeze > requirements.txt
pip install -r requirements.txt
```

## Best Practices

- Always use a virtual environment for Python projects
- Include `requirements.txt` in your repository
- Add `venv/` to `.gitignore`
- Consider using `pipenv` or `poetry` for more advanced dependency management

Virtual environments are a fundamental tool in any Python developer's workflow.
""",
            'excerpt': 'Understanding Python virtual environments - why they matter and how to use them effectively in your projects.',
            'tags': ['Python', 'Tutorial']
        },
        {
            'title': 'Docker Basics for Developers',
            'slug': 'docker-basics-developers',
            'content': """# Docker Basics for Developers

Docker containers package applications with their dependencies, ensuring consistent environments across development and production.

## Key Concepts

- **Image**: A read-only template for creating containers
- **Container**: A running instance of an image
- **Dockerfile**: Instructions for building an image
- **Volume**: Persistent data storage

## Simple Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
```

## Essential Commands

```bash
# Build an image
docker build -t myapp .

# Run a container
docker run -p 5000:5000 myapp

# List running containers
docker ps

# Stop a container
docker stop <container_id>
```

## Docker Compose

For multi-container applications:

```yaml
version: '3'
services:
  web:
    build: .
    ports:
      - "5000:5000"
  db:
    image: postgres
    environment:
      POSTGRES_PASSWORD: secret
```

Docker simplifies deployment and makes your development environment reproducible.
""",
            'excerpt': 'A practical introduction to Docker for developers - from Dockerfiles to Docker Compose for multi-container applications.',
            'tags': ['DevOps', 'Tutorial']
        },
        {
            'title': 'Web Application Security Checklist',
            'slug': 'web-application-security-checklist',
            'content': """# Web Application Security Checklist

A practical checklist for securing your web applications against common vulnerabilities.

## Input Validation

- Validate all user input on the server side
- Use parameterized queries to prevent SQL injection
- Sanitize HTML output to prevent XSS

```python
# Bad - SQL Injection vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Good - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

## Authentication

- Use bcrypt or argon2 for password hashing
- Implement rate limiting on login endpoints
- Use HTTPS everywhere
- Implement proper session management

## Headers

```python
# Security headers
response.headers['X-Content-Type-Options'] = 'nosniff'
response.headers['X-Frame-Options'] = 'DENY'
response.headers['Content-Security-Policy'] = "default-src 'self'"
```

## CSRF Protection

Always include CSRF tokens in forms that modify data.

## Regular Updates

Keep all dependencies updated. Use tools like `safety` or `pip-audit` to check for known vulnerabilities.

Stay vigilant and keep learning about emerging threats.
""",
            'excerpt': 'A practical security checklist for web applications covering input validation, authentication, security headers, and more.',
            'tags': ['Security', 'Web Development']
        },
    ]

    for post_data in posts:
        c.execute("SELECT id FROM posts WHERE slug = ?", (post_data['slug'],))
        if c.fetchone():
            continue
        c.execute(
            """INSERT INTO posts (title, slug, content, excerpt, author_id, published)
               VALUES (?, ?, ?, ?, ?, 1)""",
            (post_data['title'], post_data['slug'], post_data['content'],
             post_data['excerpt'], author_id)
        )
        post_id = c.lastrowid
        for tag_name in post_data['tags']:
            c.execute(
                "INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?, ?)",
                (post_id, tag_ids[tag_name])
            )

    # Update about page
    c.execute("""
        UPDATE pages SET content = ? WHERE slug = 'about'
    """, ("""# About This Blog

Welcome to my blog! This is a place where I share my thoughts, tutorials, and experiences in software development, security, and technology.

## Topics

- **Web Development**: Flask, Python, JavaScript
- **Security**: Linux hardening, web security, best practices
- **DevOps**: Docker, deployment, automation

## Contact

Feel free to reach out via email or social media.
""",))

    conn.commit()
    conn.close()
    print("Database seeded successfully!")

if __name__ == '__main__':
    seed()
