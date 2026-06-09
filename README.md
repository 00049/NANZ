# ShieldCheck (NAANZ)

ShieldCheck is a comprehensive, AI-driven cybersecurity scanning and threat intelligence platform. It performs deep analysis of web applications, cloud infrastructure, and APIs to identify vulnerabilities and provide actionable remediation guidance.

## Prerequisites

- Node.js 18+
- Python 3.11+
- PostgreSQL
- Redis

## Running Locally

### Backend

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```

### Celery Worker (Background Scanner)

To process background scans, start the Celery worker from the backend directory:
```bash
cd backend
celery -A app.core.celery_app worker --loglevel=info
```

### Frontend

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Next.js development server:
   ```bash
   npm run dev
   ```

## Environment Variables

See the `.env.example` files in the respective directories for configuration details:
- [Backend `.env.example`](backend/.env.example)
- [Frontend `.env.example`](frontend/.env.example)