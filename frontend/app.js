/**
 * ThreatChain — SOC Dashboard Application Logic
 * ================================================
 * Connects to MetaMask / local Hardhat node, interacts with the
 * ThreatRegistry smart contract for IoC submission, search, and live feed.
 */

// ─── Global State ────────────────────────────────────────────────────────────
let provider = null;
let signer = null;
let contract = null;
let deploymentConfig = null;
let currentAccount = null;
let isConnected = false;

// ─── Ethers.js CDN (v6) ─────────────────────────────────────────────────────
// We load ethers dynamically since this is a static HTML frontend
const ETHERS_CDN = "https://cdnjs.cloudflare.com/ajax/libs/ethers/6.13.4/ethers.umd.min.js";

// ─── Initialization ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
    // Load ethers.js
    await loadScript(ETHERS_CDN);

    // Load deployment config
    try {
        const resp = await fetch("deployment.json");
        deploymentConfig = await resp.json();
        console.log("📋 Deployment config loaded:", deploymentConfig.contractAddress);
    } catch (e) {
        console.warn("⚠️ No deployment.json found. Deploy the contract first.");
        showToast("Deploy the contract first (npx hardhat run scripts/deploy.js)", "warning");
    }

    // Setup drag-and-drop on upload zone
    setupDragAndDrop();

    // Auto-connect if MetaMask is available, otherwise try direct RPC
    if (window.ethereum) {
        console.log("🦊 MetaMask detected");
    } else {
        console.log("📡 No MetaMask — will connect directly to Hardhat RPC");
        if (deploymentConfig) {
            await connectDirectRPC();
        }
    }
});

// ─── Script Loader ───────────────────────────────────────────────────────────
function loadScript(src) {
    return new Promise((resolve, reject) => {
        if (document.querySelector(`script[src="${src}"]`)) {
            resolve();
            return;
        }
        const script = document.createElement("script");
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

// ─── Wallet Connection ───────────────────────────────────────────────────────
async function connectWallet() {
    if (!deploymentConfig) {
        showToast("Deploy the contract first!", "error");
        return;
    }

    try {
        if (window.ethereum) {
            // MetaMask connection
            provider = new ethers.BrowserProvider(window.ethereum);
            const accounts = await provider.send("eth_requestAccounts", []);
            signer = await provider.getSigner();
            currentAccount = accounts[0];

            contract = new ethers.Contract(
                deploymentConfig.contractAddress,
                deploymentConfig.abi,
                signer
            );

            showToast(`Connected: ${shortenAddress(currentAccount)}`, "success");
        } else {
            // Direct RPC (Hardhat node)
            await connectDirectRPC();
        }

        updateConnectionUI(true);
        await refreshStats();
        setupEventListener();

    } catch (err) {
        console.error("Connection error:", err);
        showToast("Connection failed: " + err.message, "error");
    }
}

async function connectDirectRPC() {
    try {
        provider = new ethers.JsonRpcProvider(deploymentConfig.rpcUrl);
        signer = await provider.getSigner(0);
        currentAccount = await signer.getAddress();

        contract = new ethers.Contract(
            deploymentConfig.contractAddress,
            deploymentConfig.abi,
            signer
        );

        updateConnectionUI(true);
        await refreshStats();
        setupEventListener();

        const btnConnect = document.getElementById("btn-connect");
        btnConnect.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="6" width="20" height="14" rx="2"/><path d="M2 10h20"/><circle cx="17" cy="16" r="1.5"/></svg>
            ${shortenAddress(currentAccount)}
        `;

        showToast("Connected to Hardhat node (direct RPC)", "success");
    } catch (err) {
        console.warn("Direct RPC connection failed:", err.message);
    }
}

function updateConnectionUI(connected) {
    isConnected = connected;
    const statusDot = document.querySelector("#connection-status .status-dot");
    const statusText = document.querySelector("#connection-status .status-text");

    if (connected) {
        statusDot.classList.add("connected");
        statusText.textContent = shortenAddress(currentAccount);

        const btnConnect = document.getElementById("btn-connect");
        btnConnect.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            Connected
        `;
        btnConnect.style.borderColor = "rgba(34, 197, 94, 0.4)";
        btnConnect.style.color = "#22c55e";
    } else {
        statusDot.classList.remove("connected");
        statusText.textContent = "Disconnected";
    }
}

// ─── Stats ───────────────────────────────────────────────────────────────────
async function refreshStats() {
    if (!contract) return;

    try {
        const threatCount = await contract.threatCount();
        document.getElementById("stat-total-threats").textContent = threatCount.toString();

        // Count critical/emergency threats
        const allHashes = await contract.getAllThreats();
        let criticalCount = 0;
        for (const hash of allHashes) {
            const details = await contract.getThreatDetails(hash);
            if (details.severity >= 4 && details.isActive) {
                criticalCount++;
            }
        }
        document.getElementById("stat-critical").textContent = criticalCount.toString();

        // Network info
        const network = await provider.getNetwork();
        const networkName = network.chainId === 31337n ? "Hardhat Local" : network.name;
        document.getElementById("stat-network").textContent = networkName;

        // Latest block
        const blockNumber = await provider.getBlockNumber();
        document.getElementById("stat-block").textContent = blockNumber.toLocaleString();

    } catch (err) {
        console.error("Stats refresh error:", err);
    }
}

// ─── File Upload & Hashing ───────────────────────────────────────────────────
function setupDragAndDrop() {
    const zone = document.getElementById("upload-zone");
    if (!zone) return;

    zone.addEventListener("dragover", (e) => {
        e.preventDefault();
        zone.classList.add("drag-over");
    });

    zone.addEventListener("dragleave", () => {
        zone.classList.remove("drag-over");
    });

    zone.addEventListener("drop", (e) => {
        e.preventDefault();
        zone.classList.remove("drag-over");
        if (e.dataTransfer.files.length > 0) {
            hashFile(e.dataTransfer.files[0]);
        }
    });
}

function handleFileUpload(event) {
    if (event.target.files.length > 0) {
        hashFile(event.target.files[0]);
    }
}

async function hashFile(file) {
    showToast(`Hashing: ${file.name}...`, "info");

    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

    // Display the hash
    document.getElementById("hash-display").style.display = "block";
    document.getElementById("computed-hash").textContent = hashHex;
    document.getElementById("hash-filename").textContent = `File: ${file.name} (${formatFileSize(file.size)})`;

    // Auto-fill the form
    document.getElementById("input-hash").value = hashHex;

    showToast("SHA-256 computed successfully", "success");
}

// ─── Register Threat ─────────────────────────────────────────────────────────
async function registerThreat(event) {
    event.preventDefault();

    if (!contract || !signer) {
        showToast("Connect your wallet first!", "error");
        return;
    }

    const hashHex = document.getElementById("input-hash").value.trim();
    const threatType = document.getElementById("input-threat-type").value;
    const severity = parseInt(document.getElementById("input-severity").value);
    const description = document.getElementById("input-description").value.trim();

    if (!hashHex || hashHex.length < 8) {
        showToast("Please enter a valid hash", "error");
        return;
    }

    // Convert hex string to bytes32
    const bytes32Hash = hexToBytes32(hashHex);

    const btn = document.getElementById("btn-register");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Submitting to Blockchain...';

    try {
        const tx = await contract.registerThreat(bytes32Hash, threatType, severity, description || "No description");
        showToast("Transaction submitted. Waiting for confirmation...", "info");

        await tx.wait();

        showToast(`✅ Threat registered on blockchain! TX: ${shortenAddress(tx.hash)}`, "success");

        // Reset form
        document.getElementById("register-form").reset();
        document.getElementById("hash-display").style.display = "none";
        document.getElementById("input-hash").value = "";

        // Refresh stats
        await refreshStats();

    } catch (err) {
        console.error("Registration error:", err);
        let errorMsg = err.message;
        if (err.message.includes("ThreatAlreadyExists")) {
            errorMsg = "This hash is already registered in the registry!";
        } else if (err.message.includes("InvalidSeverity")) {
            errorMsg = "Severity must be between 1 and 5.";
        }
        showToast("Registration failed: " + errorMsg, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Register Threat on Blockchain
        `;
    }
}

// ─── Search Threat ───────────────────────────────────────────────────────────
async function searchThreat() {
    if (!contract) {
        showToast("Connect to the blockchain first!", "error");
        return;
    }

    const hashHex = document.getElementById("search-hash").value.trim();
    if (!hashHex || hashHex.length < 8) {
        showToast("Enter a valid hash to search", "error");
        return;
    }

    const bytes32Hash = hexToBytes32(hashHex);
    const resultDiv = document.getElementById("search-result");

    try {
        const [exists, severity, threatType] = await contract.isThreat(bytes32Hash);

        if (exists) {
            const details = await contract.getThreatDetails(bytes32Hash);
            const timestamp = new Date(Number(details.timestamp) * 1000);

            resultDiv.innerHTML = `
                <div class="search-result-card threat-found">
                    <div class="result-header">
                        <div class="result-icon">🚨</div>
                        <div>
                            <h3>⚠️ THREAT DETECTED</h3>
                            <span class="severity-badge severity-${severity}">${getSeverityLabel(severity)}</span>
                        </div>
                    </div>
                    <div class="result-details">
                        <div class="result-field full-width">
                            <div class="result-field-label">SHA-256 Hash</div>
                            <div class="result-field-value">${hashHex}</div>
                        </div>
                        <div class="result-field">
                            <div class="result-field-label">Classification</div>
                            <div class="result-field-value">${details.threatType}</div>
                        </div>
                        <div class="result-field">
                            <div class="result-field-label">Severity</div>
                            <div class="result-field-value">${severity}/5 — ${getSeverityLabel(severity)}</div>
                        </div>
                        <div class="result-field">
                            <div class="result-field-label">Reported By</div>
                            <div class="result-field-value">${shortenAddress(details.reporter)}</div>
                        </div>
                        <div class="result-field">
                            <div class="result-field-label">Timestamp</div>
                            <div class="result-field-value">${timestamp.toLocaleString()}</div>
                        </div>
                        <div class="result-field full-width">
                            <div class="result-field-label">Description</div>
                            <div class="result-field-value">${details.description}</div>
                        </div>
                        <div class="result-field">
                            <div class="result-field-label">Status</div>
                            <div class="result-field-value">${details.isActive ? "🔴 Active Threat" : "⚪ Revoked"}</div>
                        </div>
                        <div class="result-field">
                            <div class="result-field-label">Source</div>
                            <div class="result-field-value">ThreatChain Blockchain</div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="search-result-card threat-clean">
                    <div class="result-header">
                        <div class="result-icon">✅</div>
                        <div>
                            <h3>CLEAN — No Threat Found</h3>
                        </div>
                    </div>
                    <div class="result-details">
                        <div class="result-field full-width">
                            <div class="result-field-label">Queried Hash</div>
                            <div class="result-field-value">${hashHex}</div>
                        </div>
                        <div class="result-field full-width">
                            <div class="result-field-label">Result</div>
                            <div class="result-field-value">This hash is NOT in the ThreatChain blockchain registry. File appears clean.</div>
                        </div>
                    </div>
                </div>
            `;
        }

        resultDiv.style.display = "block";

    } catch (err) {
        console.error("Search error:", err);
        showToast("Search failed: " + err.message, "error");
    }
}

// ─── Live Feed ───────────────────────────────────────────────────────────────
function setupEventListener() {
    if (!contract) return;

    const feedStatus = document.getElementById("feed-status");
    feedStatus.innerHTML = '<span class="status-dot connected"></span> Listening for events...';

    // Listen for new ThreatReported events
    contract.on("ThreatReported", (malwareHash, threatType, severity, reporter, timestamp, description) => {
        addFeedItem({
            type: "reported",
            hash: malwareHash,
            threatType,
            severity: Number(severity),
            reporter,
            timestamp: Number(timestamp),
            description,
        });

        showToast(`New threat reported: ${threatType} (Severity ${severity})`, "warning");
        refreshStats();
    });

    // Listen for ThreatRevoked events
    contract.on("ThreatRevoked", (malwareHash, revokedBy, reason, timestamp) => {
        addFeedItem({
            type: "revoked",
            hash: malwareHash,
            revokedBy,
            reason,
            timestamp: Number(timestamp),
        });

        showToast(`Threat revoked: ${reason}`, "info");
        refreshStats();
    });
}

async function loadThreatHistory() {
    if (!contract) {
        showToast("Connect first!", "error");
        return;
    }

    const btn = document.getElementById("btn-load-history");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Loading...';

    try {
        const allHashes = await contract.getAllThreats();

        // Clear feed
        const feedList = document.getElementById("feed-list");
        feedList.innerHTML = "";

        if (allHashes.length === 0) {
            feedList.innerHTML = `
                <div class="feed-empty">
                    <p>No threats registered yet. Be the first analyst to report!</p>
                </div>
            `;
        } else {
            for (const hash of allHashes) {
                const details = await contract.getThreatDetails(hash);
                addFeedItem({
                    type: "reported",
                    hash: hash,
                    threatType: details.threatType,
                    severity: Number(details.severity),
                    reporter: details.reporter,
                    timestamp: Number(details.timestamp),
                    description: details.description,
                    isActive: details.isActive,
                });
            }
        }

        showToast(`Loaded ${allHashes.length} threats from blockchain`, "success");

    } catch (err) {
        console.error("Load history error:", err);
        showToast("Failed to load history: " + err.message, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
            Load History
        `;
    }
}

function addFeedItem(data) {
    const feedList = document.getElementById("feed-list");

    // Remove empty state if present
    const empty = feedList.querySelector(".feed-empty");
    if (empty) empty.remove();

    const item = document.createElement("div");
    item.className = "feed-item";

    const time = new Date(data.timestamp * 1000);
    const timeStr = time.toLocaleString();
    const hashShort = data.hash.substring(0, 14) + "..." + data.hash.substring(data.hash.length - 8);

    if (data.type === "reported") {
        item.innerHTML = `
            <div class="feed-item-icon">🚨</div>
            <div class="feed-item-content">
                <div class="feed-item-title">
                    New Threat: ${data.threatType}
                    <span class="severity-badge severity-${data.severity}">${getSeverityLabel(data.severity)}</span>
                </div>
                <div class="feed-item-hash">${hashShort}</div>
                <div class="feed-item-meta">
                    <span>📍 ${shortenAddress(data.reporter)}</span>
                    <span>🕐 ${timeStr}</span>
                    ${data.isActive === false ? '<span>⚪ Revoked</span>' : ''}
                </div>
            </div>
        `;
    } else if (data.type === "revoked") {
        item.innerHTML = `
            <div class="feed-item-icon" style="background: var(--amber-dim);">⚠️</div>
            <div class="feed-item-content">
                <div class="feed-item-title">Threat Revoked</div>
                <div class="feed-item-hash">${hashShort}</div>
                <div class="feed-item-meta">
                    <span>📍 ${shortenAddress(data.revokedBy)}</span>
                    <span>💬 ${data.reason}</span>
                    <span>🕐 ${timeStr}</span>
                </div>
            </div>
        `;
    }

    feedList.prepend(item);
}

// ─── Analyst Management ──────────────────────────────────────────────────────
async function addAnalyst() {
    if (!contract || !signer) {
        showToast("Connect wallet first!", "error");
        return;
    }

    const address = document.getElementById("input-analyst-address").value.trim();
    if (!address || !address.startsWith("0x")) {
        showToast("Enter a valid Ethereum address", "error");
        return;
    }

    try {
        const tx = await contract.addAnalyst(address);
        showToast("Adding analyst... waiting for confirmation", "info");
        await tx.wait();
        showToast(`✅ Analyst added: ${shortenAddress(address)}`, "success");
        document.getElementById("input-analyst-address").value = "";
    } catch (err) {
        console.error("Add analyst error:", err);
        showToast("Failed: " + err.message, "error");
    }
}

async function removeAnalyst() {
    if (!contract || !signer) {
        showToast("Connect wallet first!", "error");
        return;
    }

    const address = document.getElementById("input-analyst-address").value.trim();
    if (!address || !address.startsWith("0x")) {
        showToast("Enter a valid Ethereum address", "error");
        return;
    }

    try {
        const tx = await contract.removeAnalyst(address);
        showToast("Removing analyst... waiting for confirmation", "info");
        await tx.wait();
        showToast(`✅ Analyst removed: ${shortenAddress(address)}`, "success");
        document.getElementById("input-analyst-address").value = "";
    } catch (err) {
        console.error("Remove analyst error:", err);
        showToast("Failed: " + err.message, "error");
    }
}

// ─── Tab Navigation ──────────────────────────────────────────────────────────
function switchTab(tabId) {
    // Update buttons
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelector(`.tab-btn[data-tab="${tabId}"]`).classList.add("active");

    // Update content
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));
    document.getElementById(`tab-${tabId}`).classList.add("active");
}

// ─── Utility Functions ───────────────────────────────────────────────────────
function hexToBytes32(hex) {
    // Remove 0x prefix if present
    hex = hex.replace(/^0x/, "");
    // Pad or truncate to 64 hex chars (32 bytes)
    hex = hex.padEnd(64, "0").substring(0, 64);
    return "0x" + hex;
}

function shortenAddress(addr) {
    if (!addr) return "Unknown";
    return addr.substring(0, 6) + "..." + addr.substring(addr.length - 4);
}

function getSeverityLabel(level) {
    const labels = { 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "EMERGENCY" };
    return labels[level] || "UNKNOWN";
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
}

// ─── Toast Notifications ─────────────────────────────────────────────────────
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");

    const icons = {
        success: "✅",
        error: "❌",
        warning: "⚠️",
        info: "ℹ️",
    };

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${message}</span>
    `;

    container.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.classList.add("toast-exit");
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}
