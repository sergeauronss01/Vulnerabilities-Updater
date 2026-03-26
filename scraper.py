import requests
from bs4 import BeautifulSoup
import time
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from database import is_visited, mark_visited, save_vulnerability
from summarizer import summarize_vulnerability

logging.basicConfig(level=logging.INFO)

def get_resilient_session():
    session = requests.Session()
    # Implement retry logic for transient network failures and rate limits
    retries = Retry(
        total=4, 
        backoff_factor=2, 
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    # Mask default python requests user-agent to avoid immediate blocking from WAFs
    session.headers.update({"User-Agent": "Defensive-Vuln-Intel-Crawler/1.0"})
    return session

def clean_html_content(soup: BeautifulSoup) -> str:
    # Remove noisy tags
    for tag in soup(["script", "style", "nav", "footer", "iframe", "header", "aside"]):
        tag.decompose()
    return soup.get_text(separator=' ', strip=True)

def run_crawler():
    sitemap_url = "https://www.cvedetails.com/sitemap/news-sitemap.xml"
    session = get_resilient_session()
    
    try:
        logging.info("Fetching sitemap...")
        resp = session.get(sitemap_url, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        logging.error(f"Failed to fetch sitemap: {e}")
        return

    soup = BeautifulSoup(resp.content, "xml")
    urls = soup.find_all("url")
    
    processed_count = 0
    max_process_per_run = 10 # Prevent massive LLM API billing during initial historical sync
    
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
            
            # Fallback if no <main> tag exists
            target_soup = main_content if main_content else page_soup.body
            
            if target_soup:
                clean_text = clean_html_content(target_soup)
                
                if clean_text:
                    intelligence = summarize_vulnerability(clean_text, url, pub_date)
                    if intelligence:
                        save_vulnerability(intelligence)
                        logging.info(f"Successfully processed and stored intel for {url}")
                
            mark_visited(url, pub_date)
            processed_count += 1
            
            # Strict Rate Limiting (Polite Crawling)
            time.sleep(3) 

        except Exception as e:
            logging.error(f"Failed to process page {url}: {e}")
            mark_visited(url, pub_date) # Mark visited even on fail to prevent permanent loop block