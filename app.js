// SentryScan Application Logic

// --- Secret Detection Database (Regex Patterns & Remediation Guides) ---
const SECRET_REGISTRY = [
  {
    id: "aws-key-id",
    name: "AWS Access Key ID",
    severity: "high",
    regex: /\b(AKIA|ASCA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    explanation: "AWS Access Key ID found. An attacker can use this to identify your AWS account and attempt access with a corresponding Secret Key.",
    remediation: {
      steps: [
        "Deactivate and delete the compromised Access Key in the AWS IAM Console.",
        "Generate a new Access Key Pair and configure it securely using environment variables or AWS Secrets Manager.",
        "Check CloudTrail logs for unauthorized API activities executed with the compromised key."
      ],
      commands: [
        "aws iam update-access-key --access-key-id [KEY_ID] --status Inactive",
        "aws iam delete-access-key --access-key-id [KEY_ID]"
      ]
    }
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    severity: "high",
    regex: /(?:aws_secret|aws_secret_access_key|secret_key)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]/gi,
    explanation: "AWS Secret Access Key detected. Combined with an Access Key ID, this gives full programmatic command-line control of your AWS resources.",
    remediation: {
      steps: [
        "Immediately delete the access key associated with this secret from the AWS IAM Console.",
        "Rotate the credentials and verify that the security policies limit permissions to the absolute minimum necessary (Principle of Least Privilege).",
        "Never commit AWS secrets directly. Use IAM Instance Profiles, AWS ECS Task Roles, or environment variables instead."
      ],
      commands: [
        "git filter-repo --invert-paths --path [COMPROMISED_FILE]",
        "# Rotate key instantly via AWS IAM console"
      ]
    }
  },
  {
    id: "github-pat-classic",
    name: "GitHub Personal Access Token (Classic)",
    severity: "high",
    regex: /\bghp_[a-zA-Z0-9]{36}\b/g,
    explanation: "GitHub Classic PAT leaked. This allows full access to repositories, orgs, and user accounts depending on the token's defined scopes.",
    remediation: {
      steps: [
        "Go to GitHub > Settings > Developer Settings > Personal Access Tokens.",
        "Revoke the compromised token immediately.",
        "Create a new token, preferably a Fine-Grained token with minimal repository permissions and a short expiry period."
      ],
      commands: [
        "curl -L -X DELETE -H \"Authorization: Bearer [TOKEN]\" https://api.github.com/applications/grants"
      ]
    }
  },
  {
    id: "github-pat-fine",
    name: "GitHub Personal Access Token (Fine-grained)",
    severity: "high",
    regex: /\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b/g,
    explanation: "GitHub Fine-Grained PAT leaked. This token grants granular read/write access to your designated GitHub repositories.",
    remediation: {
      steps: [
        "Instantly log into GitHub, navigate to developer settings, and revoke the compromised token.",
        "Audit the audit log of your repository and organization to check if any unauthorized commits or settings changes occurred."
      ],
      commands: [
        "# Revoke online via GitHub settings dashboard"
      ]
    }
  },
  {
    id: "github-oauth",
    name: "GitHub OAuth Access Token",
    severity: "high",
    regex: /\bgho_[a-zA-Z0-9]{36}\b/g,
    explanation: "GitHub OAuth Access Token leaked. Grants third-party applications access to your GitHub data.",
    remediation: {
      steps: [
        "Revoke the OAuth access token using the GitHub API or within the authorized OAuth Apps settings page.",
        "Notify any affected users if this token belonged to an integration."
      ],
      commands: [
        "# Revoke using application endpoints or developer portal"
      ]
    }
  },
  {
    id: "google-api-key",
    name: "Google / Firebase API Key",
    severity: "medium",
    regex: /\bAIza[0-9A-Za-z-_]{35}\b/g,
    explanation: "Google Cloud or Firebase API Key detected. Allows access to Google Cloud APIs, Firebase Firestore, Maps, and other services.",
    remediation: {
      steps: [
        "Go to the Google Cloud Console > APIs & Services > Credentials.",
        "Do not delete if active, but click 'Edit API Key' and add HTTP referrer restrictions or IP restrictions.",
        "Limit the API access scopes so the key can only call the specific APIs required."
      ],
      commands: [
        "# Add application restrictions in Google Cloud Console"
      ]
    }
  },
  {
    id: "stripe-secret-key",
    name: "Stripe Secret API Key",
    severity: "high",
    regex: /\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b/g,
    explanation: "Stripe Secret Key leaked. This allows full access to your Stripe account, transactions, customers, and payments.",
    remediation: {
      steps: [
        "Log into Stripe Dashboard > Developers > API Keys.",
        "Click 'Roll key' next to the compromised secret key to revoke it and generate a new one.",
        "Update your server-side environment configurations immediately to avoid processing disruptions."
      ],
      commands: [
        "# Rotate instantly inside Stripe Dashboard"
      ]
    }
  },
  {
    id: "stripe-publishable-key",
    name: "Stripe Publishable API Key",
    severity: "medium",
    regex: /\bpk_(?:live|test)_[0-9a-zA-Z]{24}\b/g,
    explanation: "Stripe Publishable Key found in server file or configuration. While publishable keys are safe for frontends, storing them in backends or configuration files is bad practice.",
    remediation: {
      steps: [
        "Confirm that this publishable key is only used in clients (frontends).",
        "If leaked in an open public repository, rotate the key in the Stripe Dashboard to prevent unauthorized usage counters."
      ],
      commands: []
    }
  },
  {
    id: "database-url-pg",
    name: "PostgreSQL Connection String",
    severity: "high",
    regex: /\bpostgres(?:ql)?:\/\/[^:]+:[^@]+@[^/:]+:[0-9]+\/?[a-zA-Z0-9_-]*\b/g,
    explanation: "PostgreSQL Database URL detected. Contains cleartext username, password, host, and database name, allowing complete data exposure.",
    remediation: {
      steps: [
        "Immediately change the password of the database user specified in the connection string.",
        "Restrict database connection endpoints in your firewall to trusted server IPs only.",
        "Use environment variables (`DATABASE_URL`) on your hosting platform instead of hardcoding."
      ],
      commands: [
        "ALTER USER [username] WITH PASSWORD '[new_password]';"
      ]
    }
  },
  {
    id: "database-url-mongo",
    name: "MongoDB Connection String",
    severity: "high",
    regex: /\bmongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/:]+:[0-9]+\/?[a-zA-Z0-9_-]*\b/g,
    explanation: "MongoDB connection URI found. Grants direct database cluster access, threatening database wiping or unauthorized reads.",
    remediation: {
      steps: [
        "Go to MongoDB Atlas or your database server settings.",
        "Rotate the user credentials instantly.",
        "Enable Network Access limitations (whitelist only your server's static IP)."
      ],
      commands: [
        "# Change DB User credentials in Atlas UI or shell"
      ]
    }
  },
  {
    id: "database-url-generic",
    name: "Database Connection String (MySQL/Redis)",
    severity: "high",
    regex: /\b(?:mysql|redis):\/\/[^:]*:[^@]+@[^/:]+:[0-9]+\/?[a-zA-Z0-9_-]*\b/g,
    explanation: "Database Connection URL found for MySQL or Redis. Exposes administrative passwords and endpoints.",
    remediation: {
      steps: [
        "Rotate the passwords for the MySQL user or Redis AUTH client.",
        "Ensure database ports (3306, 6379) are closed to the public web."
      ],
      commands: [
        "redis-cli -a [OLD_PASSWORD] config set requirepass [NEW_PASSWORD]"
      ]
    }
  },
  {
    id: "slack-webhook",
    name: "Slack Incoming Webhook URL",
    severity: "high",
    regex: /\bhttps:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}\b/g,
    explanation: "Slack incoming webhook URL leaked. Attackers can spam messages, send phishing links, or spoof announcements directly to your Slack channels.",
    remediation: {
      steps: [
        "Revoke the webhook inside Slack Workspace > Apps > Incoming Webhooks.",
        "Generate a new webhook URL and store it safely in server-side environment variables."
      ],
      commands: [
        "curl -X POST -H 'Content-type: application/json' --data '{\"text\":\"Revoke Test\"}' [WEBHOOK_URL]"
      ]
    }
  },
  {
    id: "slack-token",
    name: "Slack API Bot / User Token",
    severity: "high",
    regex: /\bxox[baprs]-[a-zA-Z0-9-]{10,60}\b/g,
    explanation: "Slack Bot/User API Token found. Allows attackers to read logs, fetch workspace channels, post messages, or manipulate workspace applications.",
    remediation: {
      steps: [
        "Revoke the bot/user token inside the Slack App configuration page.",
        "Reinstall the Slack app to generate new tokens."
      ],
      commands: []
    }
  },
  {
    id: "ssh-private-key",
    name: "SSH Private Key",
    severity: "high",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    explanation: "SSH Private Key detected. Allows administrative access to cloud instances, servers, or repositories configured with the corresponding public key.",
    remediation: {
      steps: [
        "Delete the associated public key from all servers (`authorized_keys`), GitHub accounts, and deployment environments.",
        "Generate a new keypair using secure protocols.",
        "Add a passphrase to the new private key for an extra layer of protection."
      ],
      commands: [
        "ssh-keygen -t ed25519 -C \"new_secure_key\"",
        "rm -f [OLD_PRIVATE_KEY_PATH]"
      ]
    }
  },
  {
    id: "jwt-token",
    name: "JSON Web Token (JWT)",
    severity: "low",
    regex: /\beyJhbGciOi[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]*\b/g,
    explanation: "JSON Web Token (JWT) detected. May contain user payloads, session data, or authorization claims. While often temporary, hardcoding active tokens is a leak risk.",
    remediation: {
      steps: [
        "Determine if this is a live, production user token or a mock token used in tests.",
        "If live, invalidate the session by rotating the JWT signature secret key on the authorization server."
      ],
      commands: []
    }
  },
  {
    id: "heroku-api",
    name: "Heroku API Key",
    severity: "high",
    regex: /(?:heroku_api_key|heroku_key)\s*[:=]\s*['"]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]/gi,
    explanation: "Heroku API Key detected. Allows absolute control over your Heroku apps, billing, databases, and deployments.",
    remediation: {
      steps: [
        "Revoke the API token in the Heroku Account Dashboard > API Keys.",
        "Generate a new key or use CLI auth."
      ],
      commands: [
        "heroku authorizations:revoke [KEY_OR_TOKEN_ID]"
      ]
    }
  },
  {
    id: "generic-secret",
    name: "Hardcoded Credential / Secret Pattern",
    severity: "low",
    regex: /(?:password|passwd|pass|client_secret|api_key|apikey|private_key|auth_token)\s*[:=]\s*['"]([^'"]{8,50})['"]/gi,
    explanation: "A configuration variable assignment containing keywords like 'password' or 'api_key' was found. This indicates hardcoded credentials.",
    remediation: {
      steps: [
        "Move the hardcoded credential to an external `.env` file or local configuration file.",
        "Ensure the configuration file is included in your `.gitignore`.",
        "Rotate the compromised credential if it has been exposed in public history."
      ],
      commands: [
        "echo \"API_KEY=your_key_here\" >> .env"
      ]
    }
  }
];

// --- Application State Variable Definitions ---
let activeTab = "github";
let isScanning = false;
let shouldCancel = false;
let scanStartTime = null;
let timerInterval = null;

// Scanner Statistics Tracker
let filesScannedCount = 0;
let secretsFoundCount = 0;
let currentFileList = [];
let allSecretsFound = []; // Stores objects: { file, line, col, value, rule, context: [] }

// --- DOM Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide Icons
  lucide.createIcons();
  
  // Set up drag and drop listeners
  setupDragAndDrop();

  // Load saved GitHub PAT from localStorage
  const savedToken = localStorage.getItem("sentryscan_gh_token");
  if (savedToken) {
    document.getElementById("githubToken").value = savedToken;
  }
});

// --- Tab Switching Navigation ---
function switchTab(mode) {
  if (isScanning) {
    showToast("Please cancel or wait for the current scan to finish.", "error");
    return;
  }
  
  activeTab = mode;
  
  const tabGithubBtn = document.getElementById("tabGithubBtn");
  const tabLocalBtn = document.getElementById("tabLocalBtn");
  const githubTabContent = document.getElementById("githubTabContent");
  const localTabContent = document.getElementById("localTabContent");
  
  if (mode === "github") {
    tabGithubBtn.classList.add("active");
    tabLocalBtn.classList.remove("active");
    githubTabContent.classList.add("active");
    localTabContent.classList.remove("active");
  } else {
    tabGithubBtn.classList.remove("active");
    tabLocalBtn.classList.add("active");
    githubTabContent.classList.remove("active");
    localTabContent.classList.add("active");
  }
}

// --- Toggle Advanced settings ---
function toggleAdvancedSettings() {
  const content = document.getElementById("advancedSettingsContent");
  const chevron = document.getElementById("advancedChevron");
  
  content.classList.toggle("active");
  chevron.classList.toggle("rotated");
}

// --- Drag & Drop Setup ---
function setupDragAndDrop() {
  const dropZone = document.getElementById("dropZone");

  ["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add("dragover");
    }, false);
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove("dragover");
    }, false);
  });

  dropZone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
      processLocalFiles(files);
    }
  });
}

// --- Scan Controls & Progress Engine ---
function initScanState() {
  isScanning = true;
  shouldCancel = false;
  filesScannedCount = 0;
  secretsFoundCount = 0;
  allSecretsFound = [];
  
  // Save token if input exists
  const tokenVal = document.getElementById("githubToken").value.trim();
  if (tokenVal) {
    localStorage.setItem("sentryscan_gh_token", tokenVal);
  } else {
    localStorage.removeItem("sentryscan_gh_token");
  }
  
  // Show Scanning panel, hide input and results
  document.getElementById("inputSection").classList.add("hidden");
  document.getElementById("resultsSection").classList.add("hidden");
  document.getElementById("scanningSection").classList.remove("hidden");
  
  // Reset counters
  document.getElementById("countFilesScanned").innerText = "0";
  document.getElementById("countSecretsFound").innerText = "0";
  document.getElementById("countTimeElapsed").innerText = "0.0s";
  document.getElementById("countScanSpeed").innerText = "0 f/s";
  
  // Clean logs console
  const consoleBody = document.getElementById("consoleBody");
  consoleBody.innerHTML = '<div class="log-line system-log">SentryScan engine initialized.</div>';
  
  scanStartTime = performance.now();
  timerInterval = setInterval(() => {
    const elapsed = ((performance.now() - scanStartTime) / 1000).toFixed(1);
    document.getElementById("countTimeElapsed").innerText = `${elapsed}s`;
    
    if (filesScannedCount > 0) {
      const speed = (filesScannedCount / (parseFloat(elapsed) || 0.1)).toFixed(0);
      document.getElementById("countScanSpeed").innerText = `${speed} f/s`;
    }
  }, 100);
}

function cancelScan() {
  shouldCancel = true;
  logConsole("Cancellation requested. Stopping worker...", "error-log");
}

function finishScan(success = true) {
  isScanning = false;
  clearInterval(timerInterval);
  
  const elapsed = ((performance.now() - scanStartTime) / 1000).toFixed(1);
  document.getElementById("countTimeElapsed").innerText = `${elapsed}s`;
  
  document.getElementById("scanningSection").classList.add("hidden");
  
  if (success) {
    renderResults();
    document.getElementById("resultsSection").classList.remove("hidden");
  } else {
    resetToScanner();
  }
}

function resetToScanner() {
  isScanning = false;
  clearInterval(timerInterval);
  document.getElementById("scanningSection").classList.add("hidden");
  document.getElementById("resultsSection").classList.add("hidden");
  document.getElementById("inputSection").classList.remove("hidden");
}

// --- Console Log Output ---
function logConsole(message, type = "") {
  const consoleBody = document.getElementById("consoleBody");
  const line = document.createElement("div");
  line.className = `log-line ${type}`;
  line.innerText = message;
  consoleBody.appendChild(line);
  consoleBody.scrollTop = consoleBody.scrollHeight;
}

// --- Toast Notification ---
function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = "toast-msg";
  
  const icon = document.createElement("i");
  if (type === "success") {
    icon.setAttribute("data-lucide", "check-circle-2");
    icon.className = "toast-icon";
  } else {
    icon.setAttribute("data-lucide", "alert-circle");
    icon.className = "toast-icon error";
  }
  
  const text = document.createElement("span");
  text.innerText = message;
  
  toast.appendChild(icon);
  toast.appendChild(text);
  document.body.appendChild(toast);
  
  lucide.createIcons({attrs: {"data-lucide": true}});
  
  setTimeout(() => toast.classList.add("show"), 50);
  
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// --- File Extension Filters ---
const IGNORED_EXTENSIONS = [
  // Images
  "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "tiff", "bmp",
  // Fonts
  "woff", "woff2", "ttf", "eot", "otf",
  // Archives
  "zip", "tar", "gz", "rar", "7z", "bz2", "xz",
  // Documents
  "pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp",
  // Audio/Video
  "mp3", "mp4", "wav", "avi", "mov", "flv", "mkv", "webm",
  // Executables/Binaries
  "exe", "dll", "so", "dylib", "bin", "class", "db", "sqlite"
];

function isBinaryOrIgnored(fileName) {
  const ext = fileName.split(".").pop().toLowerCase();
  return IGNORED_EXTENSIONS.includes(ext) || fileName.includes("/.git/");
}

// --- Secret Scanning Engine (CORE REGEX PARSER) ---
function scanFileContent(filePath, content) {
  const lines = content.split(/\r?\n/);
  const fileSecrets = [];
  
  lines.forEach((line, index) => {
    const lineNum = index + 1;
    
    SECRET_REGISTRY.forEach(rule => {
      // Reset lastIndex for safety
      rule.regex.lastIndex = 0;
      let match;
      
      while ((match = rule.regex.exec(line)) !== null) {
        // match[0] is the entire string matched.
        // For some rules we capture a sub-group (e.g. AWS Secret / Generic config secret)
        // If a subgroup is matched, use it; otherwise use the whole match.
        const matchedVal = match[1] || match[0];
        
        // Prevent matching duplicates on the same line
        if (fileSecrets.some(s => s.line === lineNum && s.value === matchedVal && s.rule.id === rule.id)) {
          continue;
        }

        // Get surrounding lines context (2 lines before, 2 lines after)
        const contextLines = [];
        const start = Math.max(0, index - 2);
        const end = Math.min(lines.length - 1, index + 2);
        
        for (let i = start; i <= end; i++) {
          contextLines.push({
            lineNum: i + 1,
            text: lines[i],
            isMatch: i === index
          });
        }
        
        // Generate a masked value
        let maskedVal = "";
        if (matchedVal.length <= 8) {
          maskedVal = "*".repeat(matchedVal.length);
        } else {
          maskedVal = matchedVal.substring(0, 4) + "*".repeat(matchedVal.length - 8) + matchedVal.substring(matchedVal.length - 4);
        }
        
        fileSecrets.push({
          file: filePath,
          line: lineNum,
          value: matchedVal,
          masked: maskedVal,
          rule: rule,
          context: contextLines
        });
      }
    });
  });
  
  return fileSecrets;
}

// --- LOCAL SCAN HANDLING ---
function handleFileSelection(event) {
  const files = event.target.files;
  if (files.length > 0) processLocalFiles(files);
}

function handleFolderSelection(event) {
  const files = event.target.files;
  if (files.length > 0) processLocalFiles(files);
}

async function processLocalFiles(files) {
  initScanState();
  document.getElementById("scanTitle").innerText = "Analyzing Local Files...";
  document.getElementById("scanStatusText").innerText = "Indexing files...";
  
  const filesToScan = [];
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    // webkitRelativePath gives the relative path in folders, name gives standard file name
    const path = file.webkitRelativePath || file.name;
    if (!isBinaryOrIgnored(path)) {
      filesToScan.push(file);
    }
  }
  
  if (filesToScan.length === 0) {
    logConsole("No text-based code files found to scan.", "error-log");
    finishScan(false);
    showToast("No compatible files found to scan.", "error");
    return;
  }
  
  logConsole(`Indexed ${filesToScan.length} text files. Starting scan...`);
  
  const totalFiles = filesToScan.length;
  
  for (let i = 0; i < totalFiles; i++) {
    if (shouldCancel) {
      logConsole("Scan cancelled by user.", "error-log");
      finishScan(false);
      return;
    }
    
    const file = filesToScan[i];
    const path = file.webkitRelativePath || file.name;
    
    document.getElementById("scanStatusText").innerText = `Scanning: ${path}`;
    const pct = Math.round(((i + 1) / totalFiles) * 100);
    document.getElementById("progressBarFill").style.width = `${pct}%`;
    
    try {
      const content = await readFileAsText(file);
      const results = scanFileContent(path, content);
      
      filesScannedCount++;
      document.getElementById("countFilesScanned").innerText = filesScannedCount;
      
      if (results.length > 0) {
        secretsFoundCount += results.length;
        document.getElementById("countSecretsFound").innerText = secretsFoundCount;
        allSecretsFound.push(...results);
        logConsole(`Found ${results.length} secrets in: ${path}`, "error-log");
      }
    } catch (err) {
      logConsole(`Failed to read file ${path}: ${err.message}`, "error-log");
    }
    
    // Give browser thread a breath to paint UI
    if (i % 15 === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
  
  logConsole(`Local scan complete. Scanned ${filesScannedCount} files. Found ${secretsFoundCount} secrets.`, "success-log");
  finishScan(true);
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

// --- GITHUB REPOSITORY SCAN HANDLING ---
async function startGithubScan() {
  const repoUrlInput = document.getElementById("repoUrl").value.trim();
  if (!repoUrlInput) {
    showToast("Please enter a valid GitHub repository URL", "error");
    return;
  }
  
  // Extract owner, repo, and branch from URL
  // Matches: https://github.com/owner/repo or https://github.com/owner/repo/tree/branch
  const githubPattern = /github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_\.-]+)(?:\/tree\/([a-zA-Z0-9_\.\/-]+))?/;
  const match = repoUrlInput.match(githubPattern);
  
  if (!match) {
    showToast("Invalid GitHub URL. Must be in the format github.com/owner/repo", "error");
    return;
  }
  
  const owner = match[1];
  const repo = match[2].replace(/\.git$/, ""); // remove trailing .git if present
  let branch = match[3] || "";
  
  initScanState();
  document.getElementById("scanTitle").innerText = `Scanning: ${owner}/${repo}`;
  document.getElementById("scanStatusText").innerText = "Connecting to GitHub API...";
  
  // Token authentication
  const tokenInput = document.getElementById("githubToken").value.trim();
  const headers = {
    "Accept": "application/vnd.github.v3+json"
  };
  if (tokenInput) {
    headers["Authorization"] = `token ${tokenInput}`;
  }
  
  try {
    // 1. Fetch Repository default branch if not specified
    if (!branch) {
      logConsole(`Fetching repository metadata for ${owner}/${repo}...`);
      const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
      
      if (!repoRes.ok) {
        if (repoRes.status === 401) throw new Error("Unauthorized GitHub Token. Please check credentials.");
        if (repoRes.status === 403) throw new Error("API Limit exceeded or private repo. Provide a GitHub PAT under Advanced Settings.");
        if (repoRes.status === 404) throw new Error("Repository not found. Double-check the URL and permissions.");
        throw new Error(`GitHub API error (Code: ${repoRes.status})`);
      }
      
      const repoData = await repoRes.json();
      branch = repoData.default_branch;
      logConsole(`Default branch detected: ${branch}`);
    }
    
    // 2. Fetch Git Tree recursively
    logConsole(`Fetching directory structure recursively for branch "${branch}"...`);
    const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, { headers });
    
    if (!treeRes.ok) {
      if (treeRes.status === 409) {
        throw new Error("Repository is empty. Cannot scan.");
      }
      throw new Error(`Failed to retrieve branch directory tree (Code: ${treeRes.status})`);
    }
    
    const treeData = await treeRes.json();
    const allFiles = treeData.tree.filter(node => node.type === "blob" && !isBinaryOrIgnored(node.path));
    
    if (allFiles.length === 0) {
      logConsole("No text-based code files found in this repository.", "error-log");
      finishScan(true);
      return;
    }
    
    logConsole(`Discovered ${allFiles.length} files. Starting parallel content downloads...`);
    
    const totalFiles = allFiles.length;
    
    // Concurrency pool size (5 files at a time)
    const CONCURRENCY_LIMIT = 5;
    let index = 0;
    
    async function scanWorker() {
      while (index < totalFiles && !shouldCancel) {
        const fileNode = allFiles[index++];
        const currentIdx = index; // capture for progress calculation
        const filePath = fileNode.path;
        
        // Update status UI
        document.getElementById("scanStatusText").innerText = `Downloading & Scanning: ${filePath}`;
        const pct = Math.round((currentIdx / totalFiles) * 100);
        document.getElementById("progressBarFill").style.width = `${pct}%`;
        
        try {
          // Fetch raw contents using the file's Git Blob URL (returns base64 payload)
          const blobRes = await fetch(fileNode.url, { headers });
          if (!blobRes.ok) {
            logConsole(`Failed to download blob: ${filePath}`, "error-log");
            continue;
          }
          const blobData = await blobRes.json();
          // Decode Base64 safely handling UTF-8 characters
          const utf8decoder = new TextDecoder("utf-8");
          const binaryString = atob(blobData.content.replace(/\s/g, ''));
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }
          const content = utf8decoder.decode(bytes);
          
          const results = scanFileContent(filePath, content);
          
          filesScannedCount++;
          document.getElementById("countFilesScanned").innerText = filesScannedCount;
          
          if (results.length > 0) {
            secretsFoundCount += results.length;
            document.getElementById("countSecretsFound").innerText = secretsFoundCount;
            allSecretsFound.push(...results);
            logConsole(`Found ${results.length} secrets in: ${filePath}`, "error-log");
          }
          
        } catch (err) {
          logConsole(`Failed scanning ${filePath}: ${err.message}`, "error-log");
        }
      }
    }
    
    // Initialize worker pool
    const workers = [];
    for (let i = 0; i < Math.min(CONCURRENCY_LIMIT, totalFiles); i++) {
      workers.push(scanWorker());
    }
    
    await Promise.all(workers);
    
    if (shouldCancel) {
      logConsole("Scan cancelled by user.", "error-log");
      finishScan(false);
      return;
    }
    
    logConsole(`GitHub scan complete. Scanned ${filesScannedCount} files. Found ${secretsFoundCount} secrets.`, "success-log");
    finishScan(true);
    
  } catch (err) {
    logConsole(`Scan Failed: ${err.message}`, "error-log");
    finishScan(false);
    showToast(err.message, "error");
  }
}

// --- RESULTS RENDERING & CHARTING ---
function renderResults() {
  const container = document.getElementById("secretsListContainer");
  container.innerHTML = "";
  
  // Set total count
  document.getElementById("totalVulnerabilitiesCount").innerText = allSecretsFound.length;
  document.getElementById("chartTotalCount").textContent = allSecretsFound.length;
  
  // Clean severity stats
  let countHigh = 0;
  let countMedium = 0;
  let countLow = 0;
  
  allSecretsFound.forEach(sec => {
    if (sec.rule.severity === "high") countHigh++;
    else if (sec.rule.severity === "medium") countMedium++;
    else countLow++;
  });
  
  document.getElementById("countHighSeverity").innerText = countHigh;
  document.getElementById("countMediumSeverity").innerText = countMedium;
  document.getElementById("countLowSeverity").innerText = countLow;
  
  // Update progress bars
  const total = allSecretsFound.length || 1; // avoid divide by zero
  document.getElementById("fillHighSeverity").style.width = `${(countHigh / total) * 100}%`;
  document.getElementById("fillMediumSeverity").style.width = `${(countMedium / total) * 100}%`;
  document.getElementById("fillLowSeverity").style.width = `${(countLow / total) * 100}%`;
  
  // Update SVG Doughnut Chart segments
  updatePieChart(countHigh, countMedium, countLow);
  
  // Render banner details
  const iconBox = document.getElementById("bannerIconBox");
  const bannerTitle = document.getElementById("bannerTitle");
  const bannerSubtitle = document.getElementById("bannerSubtitle");
  const banner = document.getElementById("completionBanner");
  
  if (allSecretsFound.length > 0) {
    iconBox.className = "banner-icon-box compromised";
    iconBox.innerHTML = '<i data-lucide="shield-alert"></i>';
    bannerTitle.innerText = "Action Required: Credentials Found";
    bannerSubtitle.innerText = `SentryScan detected ${allSecretsFound.length} sensitive secrets leaked within the scanned source directories.`;
    banner.style.borderColor = "rgba(225, 29, 72, 0.2)";
    banner.style.background = "linear-gradient(to right, #ffffff, #fff1f2)";
    document.getElementById("resultsDashboardGrid").classList.remove("hidden");
  } else {
    iconBox.className = "banner-icon-box clean";
    iconBox.innerHTML = '<i data-lucide="shield-check"></i>';
    bannerTitle.innerText = "System Secure: No Secrets Found";
    bannerSubtitle.innerText = "Congratulations! No API keys, tokens, or plaintext credentials were found in the scanned resources.";
    banner.style.borderColor = "rgba(5, 150, 105, 0.2)";
    banner.style.background = "linear-gradient(to right, #ffffff, #f0fdf4)";
    document.getElementById("resultsDashboardGrid").classList.add("hidden");
  }
  
  // Group findings by file path
  const fileGroups = {};
  allSecretsFound.forEach(sec => {
    if (!fileGroups[sec.file]) fileGroups[sec.file] = [];
    fileGroups[sec.file].push(sec);
  });
  
  // Build and insert HTML
  Object.keys(fileGroups).forEach((filePath, index) => {
    const groupSecrets = fileGroups[filePath];
    
    const groupDiv = document.createElement("div");
    groupDiv.className = "file-secret-group";
    groupDiv.id = `file-group-${index}`;
    
    // Header
    const header = document.createElement("div");
    header.className = "file-group-header";
    header.onclick = () => groupDiv.classList.toggle("collapsed");
    
    const pathBox = document.createElement("div");
    pathBox.className = "file-path-box";
    pathBox.innerHTML = `<i data-lucide="file-text"></i> <span>${filePath}</span>`;
    
    const countBadge = document.createElement("span");
    countBadge.className = "file-badge-count";
    countBadge.innerText = `${groupSecrets.length} issue${groupSecrets.length > 1 ? "s" : ""}`;
    
    header.appendChild(pathBox);
    header.appendChild(countBadge);
    groupDiv.appendChild(header);
    
    // Body list of secrets
    const body = document.createElement("div");
    body.className = "file-group-body";
    
    groupSecrets.forEach((sec, secIdx) => {
      const item = document.createElement("div");
      item.className = "secret-item";
      item.dataset.severity = sec.rule.severity;
      
      const meta = document.createElement("div");
      meta.className = "secret-item-meta";
      
      const left = document.createElement("div");
      left.className = "meta-left";
      left.innerHTML = `
        <span class="severity-pill ${sec.rule.severity}">${sec.rule.severity}</span>
        <span class="secret-type-title">${sec.rule.name}</span>
      `;
      
      const right = document.createElement("div");
      right.className = "meta-right";
      right.innerHTML = `
        <span class="line-num-lbl">Line ${sec.line}</span>
        <button class="btn-remediate-trigger" onclick="openRemediationDrawer('${sec.rule.id}')">
          <i data-lucide="help-circle" style="width:12px;height:12px;"></i> How to Fix
        </button>
      `;
      
      meta.appendChild(left);
      meta.appendChild(right);
      item.appendChild(meta);
      
      // Value & Code Preview Block
      const details = document.createElement("div");
      details.className = "secret-details-box";
      
      const valRow = document.createElement("div");
      valRow.className = "value-display-row";
      
      const valContainer = document.createElement("div");
      valContainer.className = "raw-value-container masked";
      valContainer.id = `val-${index}-${secIdx}`;
      valContainer.innerText = sec.masked;
      
      const actions = document.createElement("div");
      actions.className = "actions-row";
      
      const btnToggle = document.createElement("button");
      btnToggle.className = "btn-icon-only";
      btnToggle.title = "Show/Hide Secret";
      btnToggle.innerHTML = '<i data-lucide="eye"></i>';
      btnToggle.onclick = () => toggleSecretMask(`val-${index}-${secIdx}`, btnToggle, sec.value, sec.masked);
      
      const btnCopy = document.createElement("button");
      btnCopy.className = "btn-icon-only";
      btnCopy.title = "Copy Value";
      btnCopy.innerHTML = '<i data-lucide="copy"></i>';
      btnCopy.onclick = () => copyTextToClipboard(sec.value);
      
      actions.appendChild(btnToggle);
      actions.appendChild(btnCopy);
      valRow.appendChild(valContainer);
      valRow.appendChild(actions);
      details.appendChild(valRow);
      
      // Code snippet view
      const snippet = document.createElement("div");
      snippet.className = "code-context-preview";
      
      const codeHeader = document.createElement("div");
      codeHeader.className = "code-header-bar";
      codeHeader.innerHTML = `<span>Source Context Preview</span> <span style="font-size:0.65rem;">Line ${sec.line}</span>`;
      snippet.appendChild(codeHeader);
      
      const codeLines = document.createElement("div");
      codeLines.className = "code-lines-wrapper";
      
      sec.context.forEach(ctxLine => {
        const line = document.createElement("div");
        line.className = `code-preview-line ${ctxLine.isMatch ? "flagged" : ""}`;
        line.innerHTML = `
          <span class="line-number">${ctxLine.lineNum}</span>
          <span class="line-content">${escapeHTML(ctxLine.text)}</span>
        `;
        codeLines.appendChild(line);
      });
      
      snippet.appendChild(codeLines);
      details.appendChild(snippet);
      item.appendChild(details);
      
      body.appendChild(item);
    });
    
    groupDiv.appendChild(body);
    container.appendChild(groupDiv);
  });
  
  lucide.createIcons();
}

// --- Circular Doughnut SVG Calculations ---
function updatePieChart(high, medium, low) {
  const total = high + medium + low || 1;
  const radius = 70;
  const circumference = 2 * Math.PI * radius; // 439.6
  
  const highPct = high / total;
  const medPct = medium / total;
  const lowPct = low / total;
  
  const highSegment = document.getElementById("chartHighSegment");
  const medSegment = document.getElementById("chartMediumSegment");
  const lowSegment = document.getElementById("chartLowSegment");
  
  if (high === 0 && medium === 0 && low === 0) {
    highSegment.style.strokeDashoffset = circumference;
    medSegment.style.strokeDashoffset = circumference;
    lowSegment.style.strokeDashoffset = circumference;
    return;
  }
  
  // Calculate stroke offsets
  const highOffset = circumference - (highPct * circumference);
  highSegment.style.strokeDashoffset = highOffset;
  
  const medOffset = circumference - (medPct * circumference);
  medSegment.style.strokeDashoffset = medOffset;
  medSegment.style.transform = `rotate(${highPct * 360}deg)`;
  medSegment.style.transformOrigin = "100px 100px";
  
  const lowOffset = circumference - (lowPct * circumference);
  lowSegment.style.strokeDashoffset = lowOffset;
  lowSegment.style.transform = `rotate(${(highPct + medPct) * 360}deg)`;
  lowSegment.style.transformOrigin = "100px 100px";
}

// --- Toggle Result List Visibility Filter ---
function filterResults() {
  const selected = document.getElementById("severityFilter").value;
  const items = document.querySelectorAll(".secret-item");
  const groups = document.querySelectorAll(".file-secret-group");
  
  items.forEach(item => {
    const sev = item.dataset.severity;
    if (selected === "all" || sev === selected) {
      item.style.display = "flex";
    } else {
      item.style.display = "none";
    }
  });
  
  // Hide parent folder groups if they contain zero visible items
  groups.forEach(group => {
    const groupItems = group.querySelectorAll(".secret-item");
    let visibleCount = 0;
    groupItems.forEach(item => {
      if (item.style.display !== "none") visibleCount++;
    });
    
    if (visibleCount === 0) {
      group.style.display = "none";
    } else {
      group.style.display = "block";
      const badge = group.querySelector(".file-badge-count");
      badge.innerText = `${visibleCount} match${visibleCount > 1 ? "es" : ""}`;
    }
  });
}

// --- Mask / Unmask Toggle ---
function toggleSecretMask(elementId, btnElement, rawValue, maskedValue) {
  const container = document.getElementById(elementId);
  const isMasked = container.classList.contains("masked");
  
  if (isMasked) {
    container.classList.remove("masked");
    container.innerText = rawValue;
    btnElement.innerHTML = '<i data-lucide="eye-off"></i>';
  } else {
    container.classList.add("masked");
    container.innerText = maskedValue;
    btnElement.innerHTML = '<i data-lucide="eye"></i>';
  }
  lucide.createIcons();
}

// --- Remediation slide-out sidebar logic ---
function openRemediationDrawer(secretId) {
  const rule = SECRET_REGISTRY.find(r => r.id === secretId);
  if (!rule) return;
  
  const body = document.getElementById("remediationDrawerBody");
  
  // Build remediation steps html
  let stepsHtml = "";
  rule.remediation.steps.forEach((step, idx) => {
    stepsHtml += `
      <div class="remediation-step">
        <span class="step-number">Step ${idx + 1}</span>
        <h4 class="step-title">${step}</h4>
      </div>
    `;
  });
  
  // Build CLI commands if they exist
  let commandsHtml = "";
  if (rule.remediation.commands && rule.remediation.commands.length > 0) {
    commandsHtml += `
      <div style="margin-top: 1.5rem;">
        <h4 class="field-label" style="margin-bottom: 0.5rem;"><i data-lucide="terminal"></i> Recommended Remediation Commands</h4>
    `;
    rule.remediation.commands.forEach(cmd => {
      commandsHtml += `
        <div class="command-box" style="margin-bottom: 0.75rem;">
          <span class="command-text">${escapeHTML(cmd)}</span>
          <button class="btn-copy-command" onclick="copyTextToClipboard('${cmd.replace(/'/g, "\\'")}')">
            <i data-lucide="copy"></i>
          </button>
        </div>
      `;
    });
    commandsHtml += `</div>`;
  }
  
  body.innerHTML = `
    <div>
      <span class="severity-pill ${rule.severity}" style="margin-bottom:0.5rem; display:inline-block;">${rule.severity} Priority</span>
      <h3 style="font-family:var(--font-heading); font-size:1.4rem; font-weight:700; margin-bottom:0.75rem;">${rule.name}</h3>
      <p style="font-size:0.9rem; color:var(--text-muted); line-height:1.6; margin-bottom:1.5rem;">
        ${rule.explanation}
      </p>
    </div>
    
    <div style="border-top:1px dashed var(--border-color); padding-top:1.5rem;">
      <h4 class="field-label" style="margin-bottom: 1rem;"><i data-lucide="activity"></i> Action Plan</h4>
      ${stepsHtml}
    </div>
    
    ${commandsHtml}
  `;
  
  document.getElementById("drawerOverlay").classList.remove("hidden");
  lucide.createIcons();
}

function closeRemediationDrawer() {
  document.getElementById("drawerOverlay").classList.add("hidden");
}

// --- Utilities ---
function copyTextToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast("Copied credential info to clipboard!");
  }).catch(err => {
    showToast("Failed to copy text", "error");
  });
}

function exportReportJSON() {
  const report = {
    scanner: "SentryScan v1.0.0",
    timestamp: new Date().toISOString(),
    summary: {
      total_secrets: allSecretsFound.length,
      high_severity: allSecretsFound.filter(s => s.rule.severity === "high").length,
      medium_severity: allSecretsFound.filter(s => s.rule.severity === "medium").length,
      low_severity: allSecretsFound.filter(s => s.rule.severity === "low").length
    },
    findings: allSecretsFound.map(s => ({
      file: s.file,
      line: s.line,
      type: s.rule.name,
      severity: s.rule.severity,
      explanation: s.rule.explanation,
      value_masked: s.masked
    }))
  };
  
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentryscan-report-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Report exported successfully!");
}

function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}
