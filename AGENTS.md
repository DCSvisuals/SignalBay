# AGENTS.md: Signalbay — macOS Web-SIEM & Cyber News Aggregator

## Project Overview
Build a self-contained, privacy-focused web application engineered exclusively for macOS (optimized for Apple Silicon). The system is built using a decoupled React front-end and a Node.js backend running over a local SQLite engine:
1. **Node.js Backend Core**: Written in TypeScript/JavaScript, managing live network socket collection, scheduling CISA feed scraping, writing data to SQLite, and handling embedded Apple Silicon inference via GGUF files.
2. **React Front-End Interface**: Built with `.tsx` / `.jsx` modules, providing a modern browser cockpit that maps live streaming logs via WebSockets and shows AI summaries.

---

## 1. Node.js Backend Server Architecture (`server/`)

### A. Ingestion & Database Logic (`server/src/`)
- **Network Listener (`collector.ts`)**: Open an asynchronous UDP network socket handler natively inside Node.js (`dgram` module). Attempt port `514`, falling back gracefully to port `1514` if root access is denied. Parse raw event data to clean JSON arrays.
- **Threat Aggregator (`aggregator.ts`)**: Regularly query CISA's XML feed (`/cybersecurity-advisories/all.xml`) and JSON feed (`/known_exploited_vulnerabilities.json`). Generate SHA-256 hashes of articles to prevent duplicate processing loops.
- **Database Engine (`database.ts`)**: Initialize an optimized local SQLite instance at `~/Library/Application Support/LocalSIEM/siem_enterprise.db`. Maintain indices for high-velocity event writing and correlation queries.

### B. Embedded Apple Silicon AI Engine (`server/src/llm.ts`)
- **Engine Bindings**: Use **`node-llama-cpp`** to run inference natively inside the Node process wrapper. Do not call cloud endpoints or depend on outside binaries.
- **Hardware Optimization**: Compile using Apple Metal parameters. Enforce full GPU offloading to leverage your Mac's Unified Memory for rapid summarization and triage pipelines.
- **Model**: Automate caching and downloading of `Qwen/Qwen2.5-3B-Instruct-GGUF` (`qwen2.5-3b-instruct-q4_k_m.gguf`).

### C. Real-Time Communication (`server/src/index.ts`)
- Expose local REST endpoints for historical search and manually syncing data feeds.
- Instatiate a **WebSocket Server (`ws`)** to push live incoming log rows and newly generated AI incident reports directly to the React front-end without page refreshes.

---

## 2. React Web Front-End Client (`client/`)

Build a highly responsive, modern component tree layout utilizing `.tsx` / `.jsx` structures:

### Main Layout Panes
- **Tab A: "SIEM Live Dashboard"**
  - **Live Log Stream Panel**: A virtualization grid streaming syslog activity directly from the WebSocket connection.
  - **Active Anomaly Explorer**: A side selector tracking active incidents flagged by database correlation rules.
  - **AI Triage Viewport**: Renders the local GGUF model's rich Markdown summary breakdown, risk severity gauges, and copyable macOS containment commands.
- **Tab B: "Cyber News Threat Intel Hub"**
  - **Headline Selector Grid**: Interactive components displaying recent vulnerability items, CVE links, and targets.
  - **AI Summary Card**: Clean Markdown text display providing the local model's 3-bullet technical summaries (Asset Impacted, Attack Vector, Remediation).

---

## Direct Tasks for Grok Build

### Step 1: Environment Provisioning & Workspace Partitioning
1. Scaffold a monorepo workspace containing two main sub-directories: `/server` and `/client`.
2. Generate `server/package.json` locking packages for `node-llama-cpp`, `sqlite3`, `ws`, `express`, `dotenv`, and `typescript`.
3. Generate `client/package.json` deploying a standard React build engine featuring `lucide-react` for graphics and styling utilities.
4. **CRITICAL**: During the installation phase, ensure `node-llama-cpp` builds against the system's architecture flags to enable Apple Metal hardware GPU compilation natively on this Mac.

### Step 2: Implement Code Modules
1. Build the Node.js backend files (`database.ts`, `collector.ts`, `aggregator.ts`, `llm.ts`, `index.ts`).
2. Construct the React dashboard UI components utilizing `.tsx` or `.jsx` and link the local browser state to the server's WebSocket pipe.

### Step 3: Deployment Verification
1. Create a root-level startup script `start_platform.sh` that fires up the Node.js server, kicks off the React compilation server, and triggers your browser to open up `http://localhost:5173`.
2. Confirm the pipeline works: the UI renders smoothly in the browser, CISA news is summarized offline via Metal, and synthetic log packets push onto the screen instantly.
