import os
import logging
from google import genai
from google.genai import types
from models import VulnerabilityIntelligence
from pydantic import ValidationError

def summarize_vulnerability(content: str, url: str, pub_date: str) -> VulnerabilityIntelligence | None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logging.error("GEMINI_API_KEY not found in environment variables.")
        return None

    client = genai.Client(api_key=api_key)
    
    prompt = f"""
    You are a Senior Defensive Cybersecurity Analyst. 
    Analyze the following extracted content from a vulnerability report.
    
    YOUR DIRECTIVES:
    1. Extract the facts to build a strictly DEFENSIVE vulnerability intelligence report.
    2. NEVER include exploit code, payloads, or attack instructions.
    3. NEVER explain how to weaponize or trigger the vulnerability.
    4. Strip any offensive or dangerous content. Focus entirely on risk awareness, impact analysis, and remediation.
    5. If no valid vulnerability information exists, output a safe, generalized response marking it as an informational update.
    6. All information gotten should be translated in french.
    
    CONTEXT:
    Reference URL: {url}
    Publication Date: {pub_date}
    
    RAW CONTENT:
    {content[:15000]}  # Truncated to prevent context window overload while preserving core data
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=VulnerabilityIntelligence,
                temperature=0.1 # Low temperature to prevent hallucinations
            ),
        )
        
        # Pydantic validates schema completeness, CVE format, and type safety
        intel = VulnerabilityIntelligence.model_validate_json(response.text)
        return intel

    except ValidationError as ve:
        logging.error(f"Validation Error matching JSON Schema for {url}: {ve}")
        return None
    except Exception as e:
        logging.error(f"LLM Summarization Error for {url}: {e}")
        return None