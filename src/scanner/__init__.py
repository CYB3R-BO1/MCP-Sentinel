"""Static taint-analysis security scanner for MCP servers: source (tool
argument) -> propagation -> sink (shell/SQL/filesystem/HTTP), plus
structural checks (permission scope, rate limiting/auth, tool description
injection vectors). See scanner.scan.run_scan for the entrypoint."""
