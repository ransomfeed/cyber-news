import opml
import feedparser
import sys
import os
import mysql.connector
from datetime import datetime
from dateutil import parser as date_parser
from hashlib import md5
from email.utils import parsedate_to_datetime

# === Uso: python importer.py [tipo] [opml_path] ===
if len(sys.argv) != 3:
    print("❌ Uso corretto: python importer.py [tipo] [opml_path]")
    sys.exit(1)

FEED_TYPE = sys.argv[1]  # es: article, podcast, video, ecc.
OPML_PATH = sys.argv[2]
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# === Connessione a MySQL ===
db = mysql.connector.connect(
    host="xxxxxxxxxxxxxxxx",     # 🔁 change with your MySQL host
    user="xxxxxxxxxxxxxxxxx",    # 🔁 change with your MySQL user
    password="xxxxx",            # 🔁 change with your MySQL password
    database="xxxxx"             # 🔁 change with your MySQL DB name
)
cursor = db.cursor()

# === Crea tabelle se non esistono ===
cursor.execute('''
CREATE TABLE IF NOT EXISTS feeds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title TEXT,
    xmlUrl TEXT UNIQUE,
    type TEXT,
    last_updated DATETIME
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    feed_id INT,
    title TEXT,
    link TEXT,
    published DATETIME,
    summary TEXT,
    content TEXT,
    guid TEXT UNIQUE,
    FOREIGN KEY(feed_id) REFERENCES feeds(id)
)
''')

# === Importa OPML e cicla i feed ===
outline = opml.parse(OPML_PATH)

for feed in outline:
    if hasattr(feed, 'xmlUrl'):
        print(f"📡 Importing: {feed.text}")
        xmlUrl = feed.xmlUrl
        title = feed.text

        # Inserisce feed se non esiste
        cursor.execute("""
            INSERT IGNORE INTO feeds (title, xmlUrl, type)
            VALUES (%s, %s, %s)
        """, (title, xmlUrl, FEED_TYPE))
        db.commit()

        # Ottieni ID del feed
        cursor.execute("SELECT id FROM feeds WHERE xmlUrl = %s", (xmlUrl,))
        result = cursor.fetchone()
        if not result:
            print(f"❌ Errore nel recupero ID feed: {xmlUrl}")
            continue
        feed_id = result[0]

        # Parse RSS
        d = feedparser.parse(xmlUrl)
        for entry in d.entries:
            guid = entry.get('id') or entry.get('guid') or md5(entry.link.encode()).hexdigest()

            # Normalizza la data di pubblicazione
            published_raw = entry.get('published', '')
            try:
                dt = date_parser.parse(published_raw)
                published_dt = dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                published_dt = None

            content = entry.get('content', [{}])[0].get('value', '') if entry.get('content') else ''
            summary = entry.get('summary', '')

            # Inserisce solo se nuovo
            try:
                cursor.execute('''
                    INSERT INTO entries (feed_id, title, link, published, summary, content, guid)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (
                    feed_id,
                    entry.title,
                    entry.link,
                    published_dt,
                    summary,
                    content,
                    guid
                ))
                print(f"✅ Inserita: {entry.title}")
            except mysql.connector.errors.IntegrityError:
                print(f"⏭️ Già presente: {entry.title}")
                continue

        # Aggiorna ultima scansione
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE feeds SET last_updated = %s WHERE id = %s", (now, feed_id))
        db.commit()

db.close()
