"""Update tags to English and add [KOR]/[ENG] prefix to post titles."""
import sqlite3
import os
import re
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'blog.db'))

# Tag translation map (Korean -> English)
TAG_MAP = {
    '회고록': 'Retrospective',
    '강의자료': 'Lecture',
    '2024': '2024',
    'Hack the box': 'Hack The Box',
    'algorithm': 'Algorithm',
    'study': 'Study',
    'OS': 'OS',
}

def has_korean(text):
    return bool(re.search('[가-힣]', text))

def update():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # 1. Update tag names to English
    tags = c.execute('SELECT id, name, slug FROM tags').fetchall()
    for tag in tags:
        new_name = TAG_MAP.get(tag['name'], tag['name'])
        if new_name != tag['name']:
            # Check if target tag already exists
            existing = c.execute('SELECT id FROM tags WHERE name = ? AND id != ?', (new_name, tag['id'])).fetchone()
            if existing:
                # Merge: update post_tags to point to existing tag, delete duplicate
                c.execute('UPDATE OR IGNORE post_tags SET tag_id = ? WHERE tag_id = ?', (existing['id'], tag['id']))
                c.execute('DELETE FROM post_tags WHERE tag_id = ?', (tag['id'],))
                c.execute('DELETE FROM tags WHERE id = ?', (tag['id'],))
                print(f"  Merged tag '{tag['name']}' -> '{new_name}' (existing)")
            else:
                new_slug = new_name.lower().replace(' ', '-')
                c.execute('UPDATE tags SET name = ?, slug = ? WHERE id = ?', (new_name, new_slug, tag['id']))
                print(f"  Renamed tag '{tag['name']}' -> '{new_name}'")

    # 2. Add [KOR]/[ENG] prefix to post titles
    posts = c.execute('SELECT id, title, content FROM posts').fetchall()
    for post in posts:
        title = post['title']
        # Skip if already has prefix
        if title.startswith('[KOR]') or title.startswith('[ENG]'):
            continue
        # Check content language
        content_sample = post['content'][:500]
        if has_korean(title) or has_korean(content_sample):
            new_title = f"[KOR] {title}"
        else:
            new_title = f"[ENG] {title}"
        c.execute('UPDATE posts SET title = ? WHERE id = ?', (new_title, post['id']))
        print(f"  {title} -> {new_title}")

    conn.commit()
    conn.close()
    print("\nDone!")

if __name__ == '__main__':
    update()
