# SentryScan ⭐⭐⭐⭐⭐ – Premium GitHub Secret & API Key Scanner

SentryScan is a premium, client-side secret scanner web application that identifies leaked API keys, tokens, databases, credentials, and passwords. It features a professional light theme, fluid animations, and real-time scanning analytics.

---

## 🔒 100% Client-Side & Secure

SentryScan is designed with a **privacy-first architecture**. 
- **Zero Server Uploads**: Your source code files are parsed entirely inside your browser. No contents or scanned text are ever sent to an external server.
- **Local Secret Storage**: Optional GitHub Personal Access Tokens are stored locally in the browser's `localStorage` and used directly in HTTP headers to communicate with the official GitHub REST API.

---

## 🚀 Key Features

- **GitHub Repository Scanning**: Paste any public or private GitHub repository URL. The scanner recursively fetches file structures and evaluates code contents.
- **Local File & Directory Scanning**: Drag & drop folders or select files. Leverages high-performance browser FileReader APIs to scan directories in milliseconds.
- **Comprehensive Detection Coverage**:
  - **High Severity**: AWS Access/Secret Keys, GitHub PATs (Classic & Fine-grained) and OAuth tokens, Stripe Secret Keys, Database connection URLs (PostgreSQL, MongoDB, Redis, MySQL), SSH Private Keys, Slack bot/user tokens, Slack Incoming Webhooks, Heroku API Keys.
  - **Medium Severity**: Google Cloud & Firebase API keys, Stripe Publishable Keys.
  - **Low Severity**: JSON Web Tokens (JWT), generic hardcoded passwords and variable assignments.
- **Rich Interactive UX**:
  - Concentric radar progress animations during active scans.
  - Interactive SVG doughnut chart representing threat breakdown.
  - Expandable file cards containing code previews with highlighted threat contexts.
  - Remediations Panel: Dynamic slide-out sidebar drawer with step-by-step resolution guides and command-line scripts to clean repository histories.
  - Export capabilities: Download scanning reports in formatted JSON or print/save as PDF.

---

## 🛠️ How to Run Locally

Since this is a client-side single-page app (SPA) with zero external compilation dependencies:
1. Open the folder `C:\Users\asus\.gemini\antigravity-ide\scratch\github-secret-scanner`.
2. Double-click the `index.html` file to launch it in any modern web browser.

---

## ☁️ Deploying to Vercel

SentryScan is configured and ready for immediate deployment on Vercel:
1. Go to the [Vercel Dashboard](https://vercel.com/dashboard).
2. Click **Add New** > **Project**.
3. Import the repository created on GitHub.
4. Vercel will automatically detect the static project structure (the included `vercel.json` ensures clean URLs).
5. Click **Deploy**. Your app will be live on a secure HTTPS domain!
