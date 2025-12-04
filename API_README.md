# SpamNoMore API

An open-source email deliverability checker that analyzes domains and provides actionable insights to improve email deliverability.

## Features

- **DNS Checks**: Comprehensive DNS lookups for SPF, DKIM, DMARC, and MX records
- **Trust Scoring**: Calculate overall trust score (0-100) based on authentication, domain health, sending setup, and content analysis
- **Actionable Insights**: Prioritized fix suggestions to improve email deliverability
- **Email Analysis**: Optional analysis of email headers and body content

## Installation

1. Clone the repository:
```bash
git clone https://github.com/i24prakhark/SpamNoMore.git
cd SpamNoMore
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your desired configuration
```

## Configuration

The API can be configured using environment variables. See `.env.example` for available options:

- `CORS_ORIGINS`: Comma-separated list of allowed origins (default: `*` for all)
  - Example: `CORS_ORIGINS=https://example.com,https://app.example.com`
- `DNS_TIMEOUT`: Timeout for DNS queries in seconds (default: `5`)
- `DNS_LIFETIME`: DNS lifetime for queries in seconds (default: `5`)

For production deployments, it's recommended to:
1. Set `CORS_ORIGINS` to specific domains instead of using wildcard
2. Adjust DNS timeout values based on your network conditions

## Running the API

Start the FastAPI server:

```bash
./run.sh
```

Or manually:

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

You can also customize the host and port:

```bash
HOST=127.0.0.1 PORT=5000 ./run.sh
```

## API Documentation

Once the server is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### POST /api/scan-domain

Scan a domain for email deliverability issues.

**Request Body:**
```json
{
  "domain": "example.com",
  "email_headers": "optional email headers",
  "email_body": "optional email body content"
}
```

**Response:**
```json
{
  "domain": "example.com",
  "trust_score": 75,
  "trust_percentage": 75.0,
  "scores": {
    "authentication": {
      "score": 30,
      "max_score": 40,
      "percentage": 75.0,
      "details": ["SPF record exists and is properly configured", "..."]
    },
    "domain_health": {
      "score": 15,
      "max_score": 20,
      "percentage": 75.0,
      "details": ["All authentication methods configured"]
    },
    "sending_setup": {
      "score": 20,
      "max_score": 20,
      "percentage": 100.0,
      "details": ["Multiple MX records configured (2 servers)", "..."]
    },
    "content_risk": {
      "score": 20,
      "max_score": 20,
      "percentage": 100.0,
      "details": ["No content risk factors detected"],
      "risk_factors": []
    }
  },
  "dns_results": {
    "spf": {
      "exists": true,
      "record": "v=spf1 include:_spf.google.com ~all",
      "valid": true
    },
    "dmarc": {
      "exists": true,
      "record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
      "policy": "quarantine",
      "valid": true
    },
    "dkim": {
      "exists": true,
      "records": [{"selector": "default", "record": "v=DKIM1; k=rsa; p=..."}],
      "valid": true
    },
    "mx": {
      "exists": true,
      "records": [
        {"priority": 1, "server": "mx1.example.com"},
        {"priority": 5, "server": "mx2.example.com"}
      ],
      "count": 2,
      "valid": true
    }
  },
  "top_suggestions": [
    {
      "priority": "high",
      "category": "DMARC",
      "issue": "DMARC policy set to 'quarantine'",
      "action": "Strengthen DMARC policy to 'reject'",
      "details": "Change p=quarantine to p=reject for better protection.",
      "impact": "Medium - Stronger policy provides better protection"
    }
  ],
  "summary": "Good setup with room for improvement. Trust score: 75.0%. Address the suggestions below to improve deliverability."
}
```

## Score Components

### Authentication Score (40 points max)
- **SPF**: 15 points for valid SPF record
- **DKIM**: 10 points for DKIM records
- **DMARC**: 15 points for DMARC with strong policy

### Domain Health Score (20 points max)
- Evaluates overall authentication configuration completeness
- Bonus points for strong DMARC policies

### Sending Setup Score (20 points max)
- **MX Records**: Points based on MX record configuration
- Multiple MX records score higher (redundancy)

### Content Risk Score (20 points max)
- Analyzes email headers for authentication results
- Checks body content for spam indicators
- Deducts points for risk factors

## Example Usage

### Using cURL:
```bash
curl -X POST "http://localhost:8000/api/scan-domain" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

### Using Python:
```python
import requests

response = requests.post(
    "http://localhost:8000/api/scan-domain",
    json={
        "domain": "example.com",
        "email_headers": "Authentication-Results: spf=pass dkim=pass dmarc=pass",
        "email_body": "Your email content here"
    }
)

result = response.json()
print(f"Trust Score: {result['trust_percentage']}%")
print(f"Summary: {result['summary']}")
```

### Using the example script:
```bash
python example_usage.py google.com

# With custom API URL
python example_usage.py example.com https://api.spamnomore.com
```

## Project Structure

```
SpamNoMore/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   └── modules/
│       ├── __init__.py
│       ├── dns.py           # DNS lookup module
│       ├── scoring.py       # Trust scoring module
│       └── actions.py       # Fix suggestions module
├── requirements.txt
├── .env.example             # Example environment configuration
├── API_README.md
└── README.md
```

## Dependencies

- **FastAPI**: Modern web framework for building APIs
- **Uvicorn**: ASGI server for running FastAPI
- **dnspython**: DNS toolkit for Python
- **Pydantic**: Data validation using Python type annotations
- **email-validator**: Email address validation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
