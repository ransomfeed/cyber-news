# Cyber-News RSS Feeds

**Cyber-News** is a curated, open-source collection of RSS feeds focused on cybersecurity news, breaches, threat intelligence, and infosec research. The project also includes a Python script (`importer.py`) to fetch and normalize RSS entries into a local database.

**Live interaction**: [Cyber-news.it](https://cyber-news.it)

**Latest OPML version** (type=article): [feeds.opml](https://github.com/ransomfeed/cyber-news/raw/refs/heads/main/feeds.opml)

## ✨ Features

* ✅ Open-source OPML file with categorized cybersecurity news sources ([view sources here](https://github.com/ransomfeed/cyber-news/blob/main/feed_list.md))
* 🐍 Python `importer.py` script to parse feeds and store them into a database
* 📅 Dates are automatically normalized to ISO 8601 format (UTC)
* 🔁 Deduplication and GUID-based handling of entries
* 💡 Designed to be lightweight and easily extendable
* ✅ The database is created directly by the importer.py on first run

## 📁 Files in this repository

* `feeds.opml` — the main OPML file listing cybersecurity RSS sources
* `importer.py` — script to parse RSS entries from the OPML file, and store in MySQL database
* `README.md` — this file

## 🛠 Usage

### 1. Clone this repository

```bash
git clone https://github.com/ransomfeed/cyber-news.git
cd cyber-news
```

### 2. Install Python dependencies

```bash
pip install feedparser opml python-dateutil
```

### 3. Run the importer

```bash
python importer.py article feeds.opml
```

> The first argument (`article`) is the content type (e.g., article, podcast, video) and is stored alongside each feed.

### 4. Output

The importer will:

* Parse all feeds in the OPML
* Store them in a local SQLite or MySQL database (depending on configuration)
* Normalize publication dates to a consistent ISO 8601 format (e.g., `2025-08-07T12:30:00Z`)

## 🌐 Contributing

Want to contribute a new source? Just open a pull request with your addition to the `feeds.opml` file.
Please make sure it’s a reliable, high-quality feed related to cybersecurity.

## 🧭 Roadmap

* [ ] Add OPML categories (article, video, podcasts - for now in OPML file there are only "article" type of sources: is possibile to create a OPML file for every type of sources)
* [ ] Provide Docker container for full backend
* [ ] Frontend viewer for entries

## 🙏 Credits

This project is heavily inspired by [all InfoSec News - Sources](https://github.com/foorilla/allinfosecnews_sources) by Foorilla, with added parsing logic and normalization features for use in more advanced workflows.
