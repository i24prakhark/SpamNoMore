"""
FastAPI application for SpamNoMore - Email Deliverability Checker
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
import re
import dns.exception

from app.modules import DNSChecker, TrustScorer, ActionGenerator
from app.config import settings

app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION
)

# Add CORS middleware with configurable origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanDomainRequest(BaseModel):
    """Request model for domain scanning."""
    domain: str = Field(..., description="Domain name to scan (e.g., example.com)")
    email_headers: Optional[str] = Field(None, description="Optional email headers for analysis")
    email_body: Optional[str] = Field(None, description="Optional email body content for analysis")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        if not v:
            raise ValueError("Domain cannot be empty")
        
        # Remove protocol if present
        v = re.sub(r'^https?://', '', v)
        # Remove path if present
        v = v.split('/')[0]
        # Remove www. prefix
        v = re.sub(r'^www\.', '', v)
        
        # Basic domain validation
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError(f"Invalid domain format: {v}")
        
        return v.lower()


class DNSResultsResponse(BaseModel):
    """DNS check results."""
    spf: Dict[str, Any]
    dmarc: Dict[str, Any]
    dkim: Dict[str, Any]
    mx: Dict[str, Any]


class ScoreResponse(BaseModel):
    """Individual score component."""
    score: int
    max_score: int
    percentage: float
    details: List[str]
    risk_factors: Optional[List[str]] = None


class SuggestionResponse(BaseModel):
    """Fix suggestion."""
    priority: str
    category: str
    issue: str
    action: str
    details: str
    impact: str


class ScanDomainResponse(BaseModel):
    """Response model for domain scan."""
    domain: str
    trust_score: int = Field(..., description="Overall trust score (0-100)")
    trust_percentage: float
    scores: Dict[str, ScoreResponse] = Field(..., description="Detailed scores breakdown")
    dns_results: DNSResultsResponse = Field(..., description="DNS lookup results")
    top_suggestions: List[SuggestionResponse] = Field(..., description="Top fix suggestions")
    summary: str


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "description": settings.API_DESCRIPTION,
        "endpoints": {
            "scan": "/api/scan-domain (POST)"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/api/scan-domain", response_model=ScanDomainResponse)
async def scan_domain(request: ScanDomainRequest):
    """
    Scan a domain for email deliverability.
    
    Performs DNS lookups for SPF, DKIM, DMARC, and MX records.
    Analyzes email headers and body if provided.
    Calculates trust score and provides fix suggestions.
    """
    try:
        # Perform DNS checks
        dns_checker = DNSChecker(request.domain)
        dns_results = dns_checker.check_all()
        
        # Calculate scores
        scorer = TrustScorer(
            dns_results=dns_results,
            headers=request.email_headers,
            body=request.email_body
        )
        overall_scores = scorer.calculate_overall_score()
        
        # Generate action suggestions
        action_gen = ActionGenerator(dns_results=dns_results, scores=overall_scores)
        all_suggestions = action_gen.generate_suggestions()
        top_suggestions = action_gen.get_top_suggestions(limit=5)
        
        # Create summary
        trust_percentage = overall_scores['trust_percentage']
        if trust_percentage >= 90:
            summary = f"Enterprise-grade configuration detected. Deliverability posture is well above industry baseline. Trust score: {trust_percentage}%."
        elif trust_percentage >= 75:
            summary = f"Strong configuration with minor gaps. Most providers will trust this domain. Trust score: {trust_percentage}%."
        elif trust_percentage >= 55:
            summary = f"Partial authentication coverage detected. Some providers may not fully trust this domain. Trust score: {trust_percentage}%. Review suggestions to improve."
        elif trust_percentage >= 35:
            summary = f"Weak authentication posture detected. This domain is at risk of filtering. Trust score: {trust_percentage}%. Action is recommended to enhance deliverability."
        else:
            summary = f"PCritical misconfiguration detected. High risk of spam filtering or rejection. Trust score: {trust_percentage}%. Immediate action required to fix issues."
        
        # Format response
        return ScanDomainResponse(
            domain=request.domain,
            trust_score=int(overall_scores['total_score']),
            trust_percentage=overall_scores['trust_percentage'],
            scores={
                'authentication': ScoreResponse(**overall_scores['authentication']),
                'domain_health': ScoreResponse(**overall_scores['domain_health']),
                'sending_setup': ScoreResponse(**overall_scores['sending_setup']),
                'content_risk': ScoreResponse(**overall_scores['content_risk'])
            },
            dns_results=DNSResultsResponse(**dns_results),
            top_suggestions=[SuggestionResponse(**s) for s in top_suggestions],
            summary=summary
        )
    
    except dns.exception.DNSException as e:
        # DNS-specific errors
        raise HTTPException(
            status_code=400,
            detail=f"DNS lookup failed for domain '{request.domain}'. Please verify the domain is valid and has DNS records configured."
        )
    except Exception as e:
        # Log the full error internally (in production, use proper logging)
        # For now, we'll just keep it simple
        raise HTTPException(
            status_code=500,
            detail="An error occurred while scanning the domain. Please try again later."
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
