# Troubleshooting

- If the API is not responding, check the `HONEYTRACE_ADDR` environment variable and whether the process is still listening on port 8080.
- If the dashboard build fails later, install the Node dependencies in `dashboard/` before running the Vite scripts.
- If ingest is being used as a long-running process, make sure it is supervised by a service manager before treating the scaffold as operational.
