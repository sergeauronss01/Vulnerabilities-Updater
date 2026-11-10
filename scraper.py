import requests
from bs4 import BeautifulSoup
import time
import os
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from database import is_visited, mark_visited, save_vulnerability
from summarizer import summarize_vulnerability

logging.basicConfig(level=logging.INFO)

IS_VERCEL = bool(os.environ.get("VERCEL"))
# Only /tmp is writable on Vercel; locally the folder lives inside the project
DOWNLOAD_DIR = os.environ.get("DOWNLOAD_DIR", "/tmp/vulnerabilities" if IS_VERCEL else "vulnerabilities")

def get_resilient_session():
    session = requests.Session()
    retries = Retry(
        total=5, 
        backoff_factor=3, 
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0"
    })
    return session

def clean_html_content(soup: BeautifulSoup) -> str:
    for tag in soup(["script", "style", "nav", "footer", "iframe", "header", "aside"]):
        tag.decompose()
    return soup.get_text(separator=' ', strip=True)

def run_crawler():
    sitemap_url = "https://www.cvedetails.com/sitemap/news-sitemap.xml"
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    session = get_resilient_session()
    
    try:
        logging.info("Fetching sitemap...")
        resp = session.get(sitemap_url, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        logging.error(f"Failed to fetch sitemap: {e}")
        return

    soup = BeautifulSoup(resp.content, "xml")
    # [::-1] safely reverses the list without returning None
    urls = soup.find_all("url")[::-1] 
    
    processed_count = 0
    max_process_per_run = 10 
    
    for url_tag in urls:
        if processed_count >= max_process_per_run:
            logging.info("Reached maximum process limit for this run.")
            break

        loc_tag = url_tag.find("loc")
        date_tag = url_tag.find("news:publication_date")
        
        if not loc_tag:
            continue
            
        url = loc_tag.text
        pub_date = date_tag.text if date_tag else "Unknown"

        if is_visited(url):
            continue

        logging.info(f"Crawling new entry: {url}")
        try:
            page_resp = session.get(url, timeout=15)
            page_resp.raise_for_status()
            
            page_soup = BeautifulSoup(page_resp.content, "html.parser")
            main_content = page_soup.find("main")
            target_soup = main_content if main_content else page_soup.body
            
            if target_soup:
                clean_text = clean_html_content(target_soup)
                
                if clean_text:
                    intelligence = summarize_vulnerability(clean_text, url, pub_date)
                    
                    if intelligence:
                        # 1. Save to Database
                        save_vulnerability(intelligence)
                        
                        # 2. Save as JSON File in the vulnerabilities directory
                        cve_id = intelligence.vulnerability_summary.cve_id
                        # Sanitize filename in case CVE_ID is empty or malformed
                        safe_filename = f"{cve_id}.json" if cve_id else f"UNKNOWN_{int(time.time())}.json"
                        file_path = os.path.join(DOWNLOAD_DIR, safe_filename)
                        
                        # Write the Pydantic model to a formatted JSON file
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(intelligence.model_dump_json(indent=4))
                            
                        logging.info(f"Successfully processed, stored, and downloaded intel for {url} as {safe_filename}")
                
            mark_visited(url, pub_date)
            processed_count += 1
            
            time.sleep(3) 

        except Exception as e:
            logging.error(f"Failed to process page {url}: {e}")
            mark_visited(url, pub_date)