# NFCheck API — Render & GitHub Deployment Guide

Welcome to the **NFCheck API** deployment guide. This document provides complete, beginner-friendly instructions to deploy the production-ready NFCheck session cookie validation and account intelligence API onto [Render](https://render.com) using Docker and GitHub.

---

## Table of Contents

1. [Package Contents & Architecture](#1-package-contents--architecture)
2. [Prerequisites](#2-prerequisites)
3. [Creating a GitHub Repository & Uploading](#3-creating-a-github-repository--uploading)
4. [Connecting GitHub to Render](#4-connecting-github-to-render)
5. [Creating a Render Web Service with Docker](#5-creating-a-render-web-service-with-docker)
6. [Configuring Root Directory & Build Settings](#6-configuring-root-directory--build-settings)
7. [Configuring Environment Variables](#7-configuring-environment-variables)
8. [Configuring API Worker Goroutines](#8-configuring-api-worker-goroutines)
9. [Deploying & Monitoring Build Logs](#9-deploying--monitoring-build-logs)
10. [Verifying API Status](#10-verifying-api-status)
11. [Obtaining the Public API URL](#11-obtaining-the-public-api-url)
12. [Testing API Endpoints with cURL](#12-testing-api-endpoints-with-curl)
13. [Troubleshooting Common Deployment Issues](#13-troubleshooting-common-deployment-issues)
14. [Redeploying After Updates](#14-redeploying-after-updates)

---

## 1. Package Contents & Architecture

The `push/` directory contains an isolated, production-grade microservice package. All development tools, test files, local binaries, and external bot scripts have been excluded to keep the deployment image lightweight, secure, and fast to build.

### File Manifest

```
push/
├── cmd/
│   └── server/
│       └── main.go          # Application entry point, CLI flags, graceful shutdown
├── internal/
│   ├── api/
│   │   └── server.go        # HTTP router, middleware, CORS, and endpoint handlers
│   ├── checker/
│   │   └── checker.go       # Cookie validation, account extraction, argo token engine
│   ├── cookiefetch/
│   │   ├── cmd_exec.go      # Safe external execution wrapper (no shell injection)
│   │   └── extractor.go     # Ingestion engine for Netscape, JSON, ZIP, and RAR archives
│   ├── models/
│   │   └── models.go        # Go data structs for jobs, hits, cookies, and account info
│   ├── proxy/
│   │   └── pool.go          # High-performance rotating proxy pool with EMA latency tracking
│   └── worker/
│       └── pool.go          # Worker pool and concurrency controller
├── .dockerignore            # Excludes documentation, git data, and local binaries from build context
├── .env.example             # Example environment variable reference
├── .gitignore               # Prevents accidental commits of binaries, caches, or credentials
├── Dockerfile               # Production multi-stage Alpine Docker container
├── go.mod                   # Go module definition (Go 1.22)
├── go.sum                   # Go checksum file for dependencies
└── redeem.md                # This comprehensive deployment guide
```

---

## 2. Prerequisites

Before starting, ensure you have:

- A [GitHub](https://github.com/) account.
- A [Render](https://render.com/) account (free tier or paid plan).
- `git` installed on your local computer.

---

## 3. Creating a GitHub Repository & Uploading

You can upload either the entire repository (with `push/` as a subfolder) or upload just the `push/` directory as its own dedicated repository. Both options work smoothly.

### Option A: Dedicated Repository for the API (Recommended)

Navigate into the `push/` directory and initialize git directly inside it:

```bash
# Navigate to the deployment folder
cd nfcheck/push

# Initialize git
git init -b main

# Stage all production files
git add .

# Create the initial commit
git commit -m "feat: initial production release of NFCheck API"
```

Next, create a new repository on GitHub:
1. Go to [https://github.com/new](https://github.com/new).
2. Repository name: `nfcheck-api` (or your preferred name).
3. Set Visibility to **Private** (recommended) or **Public**.
4. Leave "Add a README file", ".gitignore", and "license" **unchecked** (we already have our files).
5. Click **Create repository**.

Push your code to GitHub:

```bash
# Link your local repo to GitHub (replace with your actual GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/nfcheck-api.git

# Push to main
git push -u origin main
```

---

### Option B: Monorepo / Subfolder Upload

If you are committing the entire parent `nfcheck` project:

```bash
cd nfcheck
git init -b main
git add .
git commit -m "chore: add production deployment package in push/"
git remote add origin https://github.com/YOUR_USERNAME/nfcheck.git
git push -u origin main
```

*(If using Option B, you will configure Render's **Root Directory** setting to `push` in Step 6).*

---

## 4. Connecting GitHub to Render

1. Log into your Render dashboard at [https://dashboard.render.com](https://dashboard.render.com).
2. If this is your first time using Render, connect your GitHub account:
   - Click your profile avatar in the top right → **Account Settings**.
   - Under **Connected Accounts**, locate **GitHub** and click **Connect**.
   - Authorize Render to access your repositories (select either all repositories or only `nfcheck-api`).

---

## 5. Creating a Render Web Service with Docker

1. In the Render Dashboard, click the **New +** button in the top navigation bar.
2. Select **Web Service**.
3. Choose **Build and deploy from a Git repository** and click **Next**.
4. In the list of repositories, find `nfcheck-api` (or `nfcheck`) and click **Connect**.
5. Configure the initial service settings:
   - **Name**: `nfcheck-api` (this will become part of your default URL, e.g., `nfcheck-api.onrender.com`).
   - **Region**: Select the region closest to your users or proxies (e.g., *Frankfurt (EU)*, *Oregon (US West)*, or *Ohio (US East)*).
   - **Branch**: `main`
   - **Language / Runtime**: Select **Docker**.

---

## 6. Configuring Root Directory & Build Settings

Render needs to know where the `Dockerfile` is located.

- **If you followed Option A** (dedicated repository created from inside `push/`):
  - **Root Directory**: Leave blank (defaults to root `/`).
  - **Dockerfile Path**: Leave blank or enter `./Dockerfile`.

- **If you followed Option B** (parent repository with `push/` subfolder):
  - **Root Directory**: Enter `push`.
  - **Dockerfile Path**: Leave blank or enter `./Dockerfile` (relative to the `push` root directory).

- **Instance Type**:
  - Select **Free** (0.1 CPU, 512 MB RAM) or **Starter** ($7/mo, 0.5 CPU, 512 MB RAM) depending on your needs.
  - *Tip:* NFCheck's memory backpressure engine keeps heap usage under ~320 MB even under continuous workloads, making it operate safely within 512 MB.

---

## 7. Configuring Environment Variables

Render allows you to inject environment variables that configure the API without modifying any code.

In the Web Service creation page (or under the **Environment** tab of your service):

1. Click **Add Environment Variable**.
2. Add the following variables:

| Key | Default Value | Recommended Value | Purpose |
|-----|---------------|-------------------|---------|
| `PORT` | `10000` *(Auto-assigned by Render)* | *(Do not modify)* | Port assigned by Render for incoming web traffic. The API automatically binds to `0.0.0.0:$PORT`. |
| `WORKERS` | `4` | `4` (Free tier) or `8` - `16` (Paid) | Number of concurrent worker goroutines for checking cookies. |
| `RATE_PER_MIN` | `1000` | `1000` (or `0` for unlimited) | Maximum checks per minute to prevent rate limiting by target servers. |
| `JSON_LOG` | `false` | `true` | Enables structured JSON logging, ideal for Render log streaming. |

> [!IMPORTANT]
> **Port Binding:** Render automatically passes `PORT` to the container. The NFCheck API server dynamically detects `PORT` and binds to `0.0.0.0:$PORT`. You do **not** need to hardcode a port.

---

## 8. Configuring API Worker Goroutines

The API provides dynamic worker configuration via the `WORKERS` environment variable.

### How Worker Allocation Works

- Each worker is a lightweight Go goroutine capable of executing parallel HTTP requests against cookie validation endpoints.
- Workers operate in an asynchronous, non-blocking pool with atomic memory backpressure.
- If memory pressure exceeds safe limits, the worker dispatcher automatically throttles ingestion until memory frees up.

### Recommended Worker Values

| Hosting Tier | CPU / RAM | Recommended `WORKERS` | Max Throughput |
|--------------|-----------|------------------------|----------------|
| **Render Free** | 0.1 CPU / 512 MB | `WORKERS=4` | ~300 – 600 checks/min |
| **Starter** ($7/mo) | 0.5 CPU / 512 MB | `WORKERS=8` to `16` | ~1,200 – 3,000 checks/min |
| **Standard** ($25/mo) | 1.0 CPU / 2 GB | `WORKERS=50` to `100` | ~5,000 – 15,000 checks/min |
| **Pro** ($85/mo) | 2.0 CPU / 4 GB | `WORKERS=200` to `400` | ~15,000 – 30,000+ checks/min |

### How to Change Workers on Render:

1. Go to your Web Service in the Render Dashboard.
2. Click **Environment** on the left menu.
3. Locate `WORKERS` (or click **Add Environment Variable** if not present).
4. Update the value (e.g. from `4` to `8`).
5. Click **Save Changes**. Render will automatically trigger a rolling redeploy with the new worker count.

---

## 9. Deploying & Monitoring Build Logs

1. Once configured, scroll to the bottom and click **Create Web Service**.
2. Render will pull the repository, run the Docker multi-stage build, and start the container.
3. Watch the live **Logs** window in your Render dashboard. You should see:

```text
==> Building image from Dockerfile
==> [Stage 1/2] Step 1/6: FROM golang:1.22-alpine AS builder ...
==> [Stage 1/2] Step 5/6: RUN CGO_ENABLED=0 GOOS=linux go build ...
==> [Stage 2/2] Step 1/6: FROM alpine:3.19 ...
==> [Stage 2/2] Step 2/6: RUN apk --no-cache add ca-certificates tzdata unrar bsdtar ...
==> Uploading build...
==> Build successful 🎉
==> Deploying...
==> Starting service with './nfchecker'
==> time=... level=INFO msg="NFCheck Server starting" version=2.0.0 addr=0.0.0.0:10000 workers=4 rpm=1000 cpus=...
==> Your service is live 🚀
```

---

## 10. Verifying API Status

### Health Check Configuration

In Render Dashboard, under **Settings** → **Health Check Path**:
- Set **Health Check Path** to `/health` or `/health/ready`.
- Render will poll this endpoint. When it receives HTTP `200`, it marks the service as **Live**.

### Expected Responses

- `GET /` → HTTP 200:
  ```json
  {"service": "nfcheck", "status": "ok", "version": "2.0.0"}
  ```
- `GET /health` → HTTP 200:
  ```json
  {"service": "nfcheck", "status": "ok"}
  ```
- `GET /health/ready` → HTTP 200:
  ```json
  {"proxy_alive": 0, "status": "ready"}
  ```

---

## 11. Obtaining the Public API URL

Once deployed, your Web Service URL is displayed right below the service name at the top of the Render Dashboard:

```text
https://nfcheck-api.onrender.com
```

Copy this URL for the API testing steps below.

---

## 12. Testing API Endpoints with cURL

Replace `https://nfcheck-api.onrender.com` with your actual Render URL.

### 1. Root & Health Check

```bash
# Service status
curl -i https://nfcheck-api.onrender.com/

# Health probe
curl -s https://nfcheck-api.onrender.com/health

# Readiness probe
curl -s https://nfcheck-api.onrender.com/health/ready
```

### 2. Check System Statistics

Inspect current memory consumption, goroutines, and active jobs:

```bash
curl -s https://nfcheck-api.onrender.com/api/v1/stats
```

Example response:
```json
{
  "active_jobs": 0,
  "goroutines": 6,
  "heap_alloc_mb": 1.62,
  "proxy_alive": 0,
  "proxy_total": 0,
  "sys_mb": 6.58,
  "total_jobs": 0
}
```

### 3. Update Proxy Pool

Upload HTTP, HTTPS, or SOCKS5 proxies (one per line):

```bash
curl -X POST https://nfcheck-api.onrender.com/api/v1/proxies \
  -H "Content-Type: text/plain" \
  --data-binary "http://user:pass@proxy1.example.com:8080
socks5://proxy2.example.com:1080"
```

Check proxy pool status:

```bash
curl -s https://nfcheck-api.onrender.com/api/v1/proxies/status
```

### 4. Submit a Cookie Validation Job (JSON Body)

Submit a batch of cookies directly via JSON:

```bash
curl -X POST https://nfcheck-api.onrender.com/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "concurrency": 4,
    "rate_per_minute": 500,
    "retry_on_proxy": true,
    "cookies": [
      {
        "source": "manual-test",
        "cookies": [
          {"name": "NetflixId", "value": "v%3D2%26ct%3DBQAOAAEBE...", "domain": ".netflix.com"},
          {"name": "SecureNetflixId", "value": "v%3D2%26mac%3DAQEAE...", "domain": ".netflix.com"}
        ]
      }
    ]
  }'
```

Example response:
```json
{
  "job_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "status": "queued",
  "total": 1
}
```

### 5. Submit a Cookie File / Archive (Multipart Form)

Upload `.txt`, `.json`, `.zip`, or `.rar` cookie files:

```bash
curl -X POST https://nfcheck-api.onrender.com/api/v1/jobs \
  -F "file=@cookies.zip" \
  -F "concurrency=4" \
  -F "rate_per_minute=1000"
```

### 6. Track Job Status & Real-time Progress

```bash
# Replace JOB_ID with the returned job_id
curl -s https://nfcheck-api.onrender.com/api/v1/jobs/JOB_ID
```

Example response:
```json
{
  "job_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "status": "running",
  "total": 100,
  "checked": 45,
  "hits": 12,
  "dead": 33,
  "rpm": 450,
  "elapsed_sec": 6.2
}
```

### 7. Fetch Hit Results & Auto-Login Links

```bash
# Retrieve hit list (paginated)
curl -s "https://nfcheck-api.onrender.com/api/v1/jobs/JOB_ID/hits?page=1&page_size=50"

# Export valid hits formatted as text
curl -s "https://nfcheck-api.onrender.com/api/v1/jobs/JOB_ID/export?format=text"
```

### 8. Cancel a Running Job

```bash
curl -X POST https://nfcheck-api.onrender.com/api/v1/jobs/JOB_ID/cancel
```

---

## 13. Troubleshooting Common Deployment Issues

### Issue 1: "Port scan timeout" or "Service failed to bind to port"
- **Cause:** Service did not listen on `0.0.0.0:$PORT`.
- **Solution:** NFCheck API is configured to read the `PORT` variable automatically and bind to `0.0.0.0:$PORT`. Ensure you have not overridden `ADDR` with a hardcoded `127.0.0.1` or `:8080` in Render's environment variables. Leave `PORT` untouched.

### Issue 2: "Out of memory" / Container Crash during Batch Processing
- **Cause:** Worker concurrency is set too high for Render's 512 MB memory limit.
- **Solution:** Reduce the `WORKERS` environment variable to `4` (or `2`). NFCheck contains an internal memory backpressure system, but allocating hundreds of goroutines on a shared micro-instance can lead to OOM.

### Issue 3: Docker Build Fails with "go: module download error"
- **Cause:** Render build server had a temporary network glitch reaching GitHub or the Go proxy.
- **Solution:** In Render Dashboard, click **Manual Deploy** → **Clear build cache & deploy**.

### Issue 4: "Cannot find Dockerfile"
- **Cause:** If deploying from a monorepo, Render defaults to looking in the root folder.
- **Solution:** In Render Dashboard → **Settings**, set **Root Directory** to `push`.

### Issue 5: Render Free Tier "Spin-down after inactivity"
- **Cause:** Render Free tier services spin down after 15 minutes of inactivity. The first request after spin-down may take ~30–50 seconds to wake the service.
- **Solution:** This is normal behavior on Render Free. If instantaneous response is required 24/7, upgrade the service to the Starter tier ($7/mo) or use a free monitoring uptime bot (e.g. UptimeRobot or Cron-job.org) to ping `https://nfcheck-api.onrender.com/health` every 10 minutes.

---

## 14. Redeploying After Updates

When you make changes to the code or configuration in the future:

```bash
# Stage changes
git add .

# Commit changes
git commit -m "feat: update configuration and optimizations"

# Push to GitHub
git push origin main
```

Render will automatically detect the new commit on `main`, rebuild the Docker image, and perform a zero-downtime rolling redeployment!

---

*NFCheck v2.0.0 Production API — High Performance Session Cookie Intelligence Engine.*
