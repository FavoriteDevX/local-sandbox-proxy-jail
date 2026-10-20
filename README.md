# Local Sandbox Proxy Jail 🧪🔒

An advanced, zero-dependency local network reverse proxy and sandbox boundary environment designed for software engineers testing third-party scripts, unstable APIs, or network scraping components.

This utility spins up a defensive local web micro-gateway that forces running scripts into a virtualized network **Jail**, handles automatic **Outbound Proxy rotation**, and enforces strict domain host white-listing policies to prevent data leakage and tracking flags.

---

## 💡 Architectural Overview

When executing untrusted dependencies, legacy web scraping scripts, or background webhooks locally, development environments are highly vulnerable to tracking blocks, security flaws, and unmonitored connections.

This repository mitigates development risks by establishing a modular local interceptor layer:
1. **The Sandbox Jail Boundary:** Outbound traffic from your development application is captured locally. If a script attempts to dial out to an unapproved server host destination, the transaction is dropped instantly.
2. **Dynamic Proxy Masking:** Transparently wraps clean requests and tunnels them through an array of configurable outbound round-robin proxies.
3. **Fault Simulation:** Permits developers to intentionally simulate network failures, throttling lag, and bad status codes inside their local code pipeline securely.

---

## 🚀 Deployment & Operational Guide

Initialize the secure proxy isolation matrix boundary layer using your native system terminal shell interface console:

```powershell
# Boot up the isolation environment gating allowed endpoints and injecting routing proxies
.\SandboxJail.ps1 -ListenPort 9090 -AllowedHosts @("github.com", "npmjs.org") -OutboundProxies @("http://51.75.14.22:3128")
```

### Directing Application Scripts Into the Boundary

Instead of triggering native outbound API connections over clear external configurations, route transactions into your local runtime prison container gateway. 

Add the `X-Sandbox-Target-Redirect` descriptor controller key string mapping into your local application engine headers:

- **Target Destination:** `https://github.com`
- **Sandboxed Route Mapping Interface:**
  ```http
  GET http://localhost:9090/users/octocat
  X-Sandbox-Target-Redirect: https://github.com
  ```

Your local application code now interacts flawlessly with the sandbox client engine loop, protecting system integrity and enforcing deep debugging capabilities.
