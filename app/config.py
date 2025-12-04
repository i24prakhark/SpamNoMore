"""
Configuration settings for SpamNoMore API
"""
import os
from typing import List


class Settings:
    """Application settings."""
    
    # API Configuration
    API_TITLE: str = "SpamNoMore API"
    API_VERSION: str = "1.0.0"
    API_DESCRIPTION: str = "Email deliverability checker that analyzes domains and provides actionable insights"
    
    # CORS Configuration
    CORS_ORIGINS_ENV: str = os.getenv("CORS_ORIGINS", "*")
    CORS_ORIGINS: List[str] = CORS_ORIGINS_ENV.split(",") if CORS_ORIGINS_ENV != "*" else ["*"]
    
    # DNS Configuration
    DNS_TIMEOUT: int = int(os.getenv("DNS_TIMEOUT", "5"))
    DNS_LIFETIME: int = int(os.getenv("DNS_LIFETIME", "5"))
    
    # Scoring Configuration
    SPAM_KEYWORDS: List[str] = [
        'click here', 'act now', 'limited time', 'free money', 
        'nigerian prince', 'winner', 'congratulations', 'urgent',
        'cash bonus', 'risk-free', 'satisfaction guaranteed'
    ]
    
    # Common DKIM selectors to check
    COMMON_DKIM_SELECTORS: List[str] = [
        'default', 'google', 'k1', 'selector1', 'selector2'
    ]


settings = Settings()
