from pydantic import BaseModel, Field, field_validator
from typing import List
import re

class Metadata(BaseModel):
    reference: str = Field(description="The source URL of the vulnerability data")
    date: str = Field(description="Publication date from the sitemap")
    origin: str = Field(description="The source platform, e.g., cvedetails.com")
    destinataries: str = Field(description="Target audience for the intelligence, e.g., SecOps, IT Admins")

class VulnerabilitySummary(BaseModel):
    title: str = Field(description="A concise, defensive title of the vulnerability")
    cve_id: str = Field(description="The CVE identifier")
    cvss_score: str = Field(description="The CVSS score if available, otherwise 'Unknown'")
    overview: str = Field(description="High-level summary of the vulnerability without exploit specifics")
    description: str = Field(description="Detailed technical description focusing on impact, not exploitation methods")

    @field_validator('cve_id')
    @classmethod
    def validate_cve(cls, v: str) -> str:
        if v and v.upper() != "UNKNOWN":
            if not re.match(r'^CVE-\d{4}-\d{4,}$', v, re.IGNORECASE):
                raise ValueError(f"Invalid CVE format detected: {v}")
        return v.upper()

class InventoryPatching(BaseModel):
    product: str = Field(description="The affected product or software")
    affected_versions: str = Field(description="Specific versions vulnerable")
    fix_version: str = Field(description="The patched or safe version")

class VulnerabilityIntelligence(BaseModel):
    metadata: Metadata
    vulnerability_summary: VulnerabilitySummary
    impacts: List[str] = Field(description="List of potential business and technical impacts")
    inventory_and_patching: List[InventoryPatching]
    remediation_steps: List[str] = Field(description="Step-by-step defensive remediation actions")
    references: List[str] = Field(description="List of safe reference URLs for further reading")