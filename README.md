# Signalbay

Local macOS SIEM. A React dashboard and a Node server on localhost collect syslog and host logs, correlate incidents, and can summarize them with a local GGUF or MLX model.

## Run

```bash
./start_platform.sh
```

Dashboard: http://127.0.0.1:5173
API: http://127.0.0.1:3001

Events, models, and settings stay in `~/Library/Application Support/LocalSIEM`. The packet-filter anchor name is `localsiem`.
