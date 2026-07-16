# Vulnerabilities Updater

A defensive vulnerability intelligence tool that crawls CVE news advisories, summarizes them with Google Gemini, and exposes the results through a FastAPI dashboard and API.

## What it does

- Crawls the CVE Details news sitemap for new vulnerability reports.
- Fetches and cleans advisory page content using `requests` and `BeautifulSoup`.
- Summarizes content into structured defensive intelligence using Google Gemini.
- Stores intelligence in a local SQLite database and saves JSON outputs to `vulnerabilities/`.
- Provides a simple UI at `/` and API endpoints for triggering crawls and fetching vulnerabilities.

## Key features

- Defensive-only vulnerability intelligence generation
- CVE validation and safe data capture
- Retry-safe HTTP crawling with backoff
- Persistent storage in `vuln_intel.db`
- Browser dashboard in `static/index.html`

## Project structure

- `main.py` - FastAPI application and API routes
- `scraper.py` - sitemap crawler, page fetcher, and storage logic
- `summarizer.py` - Gemini prompt generation and intelligence schema handling
- `database.py` - SQLite persistence for visited URLs and vulnerability records
- `models.py` - Pydantic models defining the intelligence schema
- `static/index.html` - frontend dashboard UI
- `vulnerabilities/` - JSON output storage for processed vulnerabilities
- `requirements.txt` - Python dependencies

## Requirements

- Python 3.11+ recommended
- Google Gemini API key for `gemini-2.5-flash`

## Installation

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Create a `.env` file in the project root and add your Gemini API key:

```env
GEMINI_API_KEY=your_gemini_api_key_here
DOWNLOAD_DIR=vulnerabilities
```

4. Ensure the `vulnerabilities/` directory exists (the scraper also creates it automatically).

## Running the app

Start the FastAPI server:

```powershell
python main.py
```

Open the dashboard in your browser:

- `http://127.0.0.1:8000/`

## API endpoints

- `POST /api/crawl` - Trigger the background crawler to fetch new advisories.
- `GET /api/vulnerabilities` - Retrieve all stored vulnerability intelligence records.

## Notes

- The summarizer is intentionally defensive: it avoids exploit code, attack instructions, and offensive content.
- Intelligence content is generated in French per the prompt configuration.
- The database schema stores visited URLs and de-duplicated vulnerability records keyed by `cve_id`.

## Troubleshooting

- If the dashboard does not load, verify that `static/index.html` exists.
- If the crawler cannot run, ensure `GEMINI_API_KEY` is set and valid.
- Check logs for crawl failures and HTTP retry activity.

## License

This project is provided as-is for defensive cybersecurity research and secure vulnerability awareness.
