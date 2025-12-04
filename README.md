# SpamNoMore
An open-source email deliverability checker that tells you whether you'll land in inbox or spam, and what to fix next.

## Features

- **Comprehensive DNS Analysis**: Check SPF, DKIM, DMARC, and MX records
- **Trust Scoring**: Get a 0-100 trust score for your domain's email deliverability
- **Actionable Insights**: Receive prioritized recommendations to fix issues
- **Email Content Analysis**: Optional analysis of email headers and body content
- **REST API**: Easy-to-use FastAPI backend with comprehensive documentation

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the API server:**
   ```bash
   ./run.sh
   # Or manually:
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

3. **Test the API:**
   ```bash
   python example_usage.py google.com
   ```

4. **Access the interactive API docs:**
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

## API Documentation

For detailed API documentation, see [API_README.md](API_README.md)

## Example Response

```json
{
  "domain": "google.com",
  "trust_score": 80,
  "trust_percentage": 80.0,
  "scores": {
    "authentication": {"score": 30, "max_score": 40, "percentage": 75.0},
    "domain_health": {"score": 15, "max_score": 20, "percentage": 75.0},
    "sending_setup": {"score": 15, "max_score": 20, "percentage": 75.0},
    "content_risk": {"score": 20, "max_score": 20, "percentage": 100.0}
  },
  "top_suggestions": [
    {
      "priority": "high",
      "category": "DKIM",
      "issue": "No DKIM records found",
      "action": "Set up DKIM signing for your domain"
    }
  ]
}
```

## Project Structure

```
SpamNoMore/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   └── modules/
│       ├── dns.py           # DNS lookup module
│       ├── scoring.py       # Trust scoring module
│       └── actions.py       # Fix suggestions module
├── example_usage.py         # Example Python client
├── run.sh                   # Server startup script
├── requirements.txt         # Python dependencies
└── API_README.md           # Detailed API documentation
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
