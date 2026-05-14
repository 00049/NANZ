# Architecture Overview

ShieldCheck (NAANZ) is built using a decoupled, service-oriented architecture designed for scalability, particularly for long-running security scans.

## System Components

### 1. Frontend (Next.js)
*   **Framework**: Next.js 14 using the App Router.
*   **Styling**: TailwindCSS with Radix UI primitives for accessible, customizable components.
*   **State Management**: Zustand for global state, React Query for server state and caching.
*   **Routing**: Client-side routing with Next.js router. Server-side rendering is used for SEO-critical pages (like public reports).

### 2. Backend API (FastAPI)
*   **Framework**: FastAPI for high-performance, async API endpoints.
*   **Database ORM**: SQLAlchemy with AsyncPG for asynchronous PostgreSQL access.
*   **Authentication**: JWT-based stateless authentication.
*   **Rate Limiting**: `slowapi` to prevent abuse.

### 3. Task Queue & Workers (Celery)
*   **Broker**: Redis.
*   **Worker**: Celery workers execute the actual security scans asynchronously.
*   **Tools Orchestrated**:
    *   `Nuclei`: Template-based vulnerability scanner.
    *   `WPScan`: WordPress vulnerability scanner.
    *   `Subfinder`: Subdomain discovery.
    *   `Nmap`: Network mapper.
*   **External Integrations**: OpenAI (for AI remediation generation), Shodan, HaveIBeenPwned, VirusTotal, etc.

## Data Flow for a Security Scan

1.  **Initiation**: User requests a scan via the frontend.
2.  **API Handling**: FastAPI receives the request, validates the domain, and creates a `ScanHistory` record in PostgreSQL with a status of `PENDING`.
3.  **Task Enqueue**: FastAPI pushes a `run_full_scan` task to the Celery/Redis queue.
4.  **Execution**: A Celery worker picks up the task, updates the status to `SCANNING`, and sequentially runs the security tools (Nmap, Subfinder, Nuclei, WPScan, external APIs).
5.  **Completion**: The worker aggregates the findings, saves them to the database, updates the status to `COMPLETED`, and caches the result.
6.  **Polling**: The frontend polls the FastAPI `/api/scans/{scan_id}` endpoint to get real-time updates and finally renders the complete report.

## Security & Compliance
*   All sensitive data (API keys, JWT secrets) is managed via environment variables.
*   The system incorporates an AI-driven "FixPanel" to map discovered vulnerabilities directly to DPDP, GDPR, and SOC 2 compliance controls.
