# ShieldCheck (by NAANZ) 🛡️

[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-00a393.svg)](https://fastapi.tiangolo.com/)
[![Celery](https://img.shields.io/badge/Celery-Distributed_Task_Queue-37814A.svg)](https://docs.celeryq.dev/en/stable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ShieldCheck is an Enterprise Application Security Posture Management (ASPM) platform designed to provide deep, actionable security intelligence. Built to handle complex scanning workloads, it orchestrates multiple security tools and threat intelligence feeds to deliver comprehensive vulnerability assessments, AI-driven remediation guidance, and compliance reports.

## 🚀 Key Features

*   **Deep Reconnaissance & Scanning**: Automated orchestration of tools like `Nuclei`, `Nmap`, `WPScan`, and `Subfinder` for exhaustive asset discovery and vulnerability detection.
*   **AI-Powered Remediation (FixPanel)**: Context-aware security guidance leveraging OpenAI to map findings against specific regulatory controls and provide actionable, step-by-step remediation plans.
*   **Threat Intelligence Integration**: Real-time correlation with Shodan, VirusTotal, urlscan.io, Google Safe Browsing, and HaveIBeenPwned.
*   **Enterprise Compliance Reporting**: Generates DPDP, GDPR, and SOC 2 aligned security reports with risk-scoring models and penalty exposure analysis.
*   **Asynchronous Architecture**: Built on Celery and Redis to handle long-running, CPU-intensive security scans without blocking the main API.

## 🏗 Architecture & Tech Stack

ShieldCheck uses a modern, decoupled architecture:

*   **Frontend**: Next.js 14 (App Router), React 18, TailwindCSS, Zustand (State Management), Radix UI.
*   **Backend API**: FastAPI (Python 3.11), SQLAlchemy (AsyncPG).
*   **Task Queue**: Celery with Redis broker for distributed scan execution.
*   **Database**: PostgreSQL for persistent storage of scan histories, domain data, and user workspaces.

## 🛠 Getting Started

### Prerequisites
*   Docker and Docker Compose
*   Node.js 20+
*   Python 3.11+
*   Redis & PostgreSQL (if running locally without Docker)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/naanz.git
   cd naanz
   ```

2. **Start Infrastructure (Postgres & Redis)**
   ```bash
   cd backend
   docker-compose up -d
   ```

3. **Configure Environment Variables**
   *   Copy `backend/.env.example` to `backend/.env` and fill in the required API keys.
   *   Copy `frontend/.env.example` to `frontend/.env.local` (or create it with `NEXT_PUBLIC_API_URL=http://localhost:8000`).

4. **Run the Backend & Celery Worker**
   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   
   # Run migrations
   alembic upgrade head
   
   # You can use the unified start script (which runs migrations, celery, and uvicorn)
   ./start.sh
   ```

5. **Run the Frontend**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

6. Open [http://localhost:3000](http://localhost:3000) to view the application.

## 🤝 Contributing

We welcome contributions to ShieldCheck! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, or request features.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.