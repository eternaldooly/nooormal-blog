# nooormal-blog

A minimal personal blog built with Flask + SQLite | [Demo](https://dooly.life/)

⚡ Lightweight | 🎨 Minimal | ✍️ Markdown | 🔒 Secure

<img width="1129" height="788" alt="image" src="https://github.com/user-attachments/assets/e89125f2-b526-4fe7-aef7-2884973e4bc1" />

---

## Features 💥

- **Markdown-based Writing** — Write and publish posts in Markdown.
- **Tags & Search** — Categorize with tags and find posts instantly.
- **Admin Dashboard** — Create, edit, delete posts with drag-and-drop reordering.
- **About Page Editor** — Edit your About page directly from the dashboard.
- **HTTPS Support** — Automatically switches to HTTPS when SSL certificates are configured.

## Tech Stack 🛠️

| Category | Technology |
|---|---|
| **Backend** | Python, Flask, Werkzeug |
| **Database** | SQLite (migrated from MongoDB) |
| **Templating** | Jinja2 |
| **Frontend** | Vanilla CSS, Vanilla JS |
| **Markdown** | markdown, MarkupSafe |
| **Infra** | SSL/HTTPS, `.env` config |

> No frontend frameworks. No bundlers. Just pure Flask + SQLite + Jinja2.

## Setup 📥

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration ⚙️

Create a `.env` file based on `.env.example` or set environment variables:

```
BLOG_ADMIN_USER=admin
BLOG_ADMIN_PASS=your_password
SSL_CERT_PATH=ssl/fullchain.pem
SSL_KEY_PATH=ssl/privkey.pem
CANONICAL_HOST=
TRUSTED_HOSTS=localhost,127.0.0.1,::1
BIND_HOST=0.0.0.0
HTTP_PORT=80
HTTPS_PORT=443
```

## Run 🚀

```bash
python app.py
```

Runs on HTTP by default. If SSL certificates are present, it switches to HTTPS.
Ports are controlled by `HTTP_PORT` and `HTTPS_PORT` (defaults: 80/443).
For production domains, set `CANONICAL_HOST` and include your domain in `TRUSTED_HOSTS`.

## Project Structure 📂

```
app.py            # Main application
seed.py           # Sample data generator
migrate.py        # MongoDB BSON → SQLite migration
update_posts.py   # Batch update tags/titles
static/           # CSS, JS
templates/        # Jinja2 templates
```

## Support 🫶

- ⭐ Star this repository.
- 🐛 Found a bug or have a suggestion? Open an [Issue](https://github.com/eternaldooly/nooormal-blog/issues).
