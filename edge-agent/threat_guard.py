"""
ThreatChain — Edge Defense Agent (Python)
==========================================
Monitors a target directory for new/modified files, computes their SHA-256 hash,
and queries the ThreatRegistry smart contract on the blockchain. If the hash is
found in the immutable blacklist, the file is immediately quarantined.

Usage:
    python threat_guard.py [--watch-dir PATH] [--quarantine-dir PATH]

Requirements:
    pip install -r requirements.txt
"""

import os
import sys
import json
import time
import hashlib
import shutil
import argparse
import logging
from datetime import datetime
from pathlib import Path

from web3 import Web3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─── Configuration ────────────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# Terminal colors for dramatic output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

SEVERITY_LABELS = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
    5: "EMERGENCY"
}

SEVERITY_COLORS = {
    1: Colors.GREEN,
    2: Colors.YELLOW,
    3: Colors.YELLOW,
    4: Colors.RED,
    5: Colors.RED + Colors.BOLD,
}

# ─── Logging Setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ThreatGuard")

# ─── Blockchain Connection ────────────────────────────────────────────────────

def load_config():
    """Load contract deployment config (address, ABI, RPC URL)."""
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file not found: {CONFIG_FILE}")
        logger.error("Please deploy the smart contract first: npx hardhat run scripts/deploy.js --network localhost")
        sys.exit(1)

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    return config


def connect_blockchain(config):
    """Connect to the blockchain and return a contract instance."""
    w3 = Web3(Web3.HTTPProvider(config["rpcUrl"]))

    if not w3.is_connected():
        logger.error(f"❌ Cannot connect to blockchain at {config['rpcUrl']}")
        logger.error("   Make sure Hardhat node is running: npx hardhat node")
        sys.exit(1)

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(config["contractAddress"]),
        abi=config["abi"]
    )

    logger.info(f"{Colors.GREEN}✅ Connected to blockchain at {config['rpcUrl']}{Colors.RESET}")
    logger.info(f"{Colors.CYAN}📋 Contract address: {config['contractAddress']}{Colors.RESET}")

    return w3, contract


# ─── File Hashing ─────────────────────────────────────────────────────────────

def compute_sha256(filepath):
    """Compute SHA-256 hash of a file and return as bytes32-compatible hex."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        logger.warning(f"⚠️  Cannot read file: {filepath} ({e})")
        return None


def hash_to_bytes32(hex_hash):
    """Convert a hex SHA-256 hash string to bytes32 for the smart contract."""
    # Take the first 32 bytes (64 hex chars) and pad/truncate to bytes32
    hash_bytes = bytes.fromhex(hex_hash[:64])
    return hash_bytes[:32].ljust(32, b'\x00')


# ─── Threat Check ─────────────────────────────────────────────────────────────

def check_threat(contract, file_hash_bytes32):
    """Query the blockchain to check if a hash is a known threat."""
    try:
        exists, severity, threat_type = contract.functions.isThreat(file_hash_bytes32).call()
        return exists, severity, threat_type
    except Exception as e:
        logger.error(f"❌ Blockchain query failed: {e}")
        return False, 0, ""


# ─── Quarantine ───────────────────────────────────────────────────────────────

def quarantine_file(filepath, quarantine_dir, threat_info):
    """Move a malicious file to the quarantine directory."""
    os.makedirs(quarantine_dir, exist_ok=True)

    filename = os.path.basename(filepath)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    quarantine_name = f"{timestamp}_THREAT_{filename}"
    quarantine_path = os.path.join(quarantine_dir, quarantine_name)

    try:
        shutil.move(filepath, quarantine_path)
        logger.info(f"{Colors.MAGENTA}🔒 File quarantined: {quarantine_path}{Colors.RESET}")

        # Write incident report alongside the quarantined file
        report_path = quarantine_path + ".report.txt"
        with open(report_path, "w") as f:
            f.write("═" * 60 + "\n")
            f.write("  THREATCHAIN INCIDENT REPORT\n")
            f.write("═" * 60 + "\n")
            f.write(f"  Timestamp     : {datetime.now().isoformat()}\n")
            f.write(f"  Original File : {filepath}\n")
            f.write(f"  SHA-256 Hash  : {threat_info['hash']}\n")
            f.write(f"  Threat Type   : {threat_info['type']}\n")
            f.write(f"  Severity      : {threat_info['severity']} ({SEVERITY_LABELS.get(threat_info['severity'], 'UNKNOWN')})\n")
            f.write(f"  Action Taken  : FILE QUARANTINED\n")
            f.write(f"  Quarantine Loc: {quarantine_path}\n")
            f.write("═" * 60 + "\n")
            f.write("  Source: ThreatChain Decentralized Registry (Blockchain)\n")
            f.write("═" * 60 + "\n")

        return True
    except Exception as e:
        logger.error(f"❌ Failed to quarantine file: {e}")
        return False


# ─── File System Event Handler ────────────────────────────────────────────────

class ThreatFileHandler(FileSystemEventHandler):
    """Watchdog handler that scans new/modified files against the blockchain."""

    def __init__(self, contract, quarantine_dir):
        super().__init__()
        self.contract = contract
        self.quarantine_dir = quarantine_dir
        self.scanned_files = set()  # Avoid duplicate scans

    def on_created(self, event):
        if not event.is_directory:
            self._scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._scan_file(event.src_path)

    def _scan_file(self, filepath):
        """Core scan logic: hash file → query blockchain → quarantine if threat."""
        # Skip quarantine directory files and already-scanned files
        if self.quarantine_dir in filepath:
            return
        if filepath in self.scanned_files:
            return

        self.scanned_files.add(filepath)

        # Small delay to ensure file write is complete
        time.sleep(0.5)

        if not os.path.exists(filepath):
            return

        logger.info(f"{Colors.CYAN}🔍 Scanning: {os.path.basename(filepath)}{Colors.RESET}")

        # Step 1: Compute SHA-256 hash
        file_hash = compute_sha256(filepath)
        if not file_hash:
            return

        logger.info(f"   SHA-256: {file_hash[:16]}...{file_hash[-8:]}")

        # Step 2: Convert to bytes32 and query blockchain
        hash_bytes32 = hash_to_bytes32(file_hash)
        exists, severity, threat_type = check_threat(self.contract, hash_bytes32)

        # Step 3: Act on result
        if exists:
            sev_color = SEVERITY_COLORS.get(severity, Colors.RED)
            sev_label = SEVERITY_LABELS.get(severity, "UNKNOWN")

            print()
            print(f"{Colors.RED}{Colors.BOLD}{'═' * 60}{Colors.RESET}")
            print(f"{Colors.RED}{Colors.BOLD}  🚨 THREAT DETECTED — BLOCKING EXECUTION 🚨{Colors.RESET}")
            print(f"{Colors.RED}{Colors.BOLD}{'═' * 60}{Colors.RESET}")
            print(f"  File      : {Colors.YELLOW}{os.path.basename(filepath)}{Colors.RESET}")
            print(f"  Hash      : {file_hash[:32]}...")
            print(f"  Type      : {Colors.RED}{threat_type}{Colors.RESET}")
            print(f"  Severity  : {sev_color}{severity}/5 — {sev_label}{Colors.RESET}")
            print(f"  Source    : {Colors.CYAN}ThreatChain Blockchain Registry{Colors.RESET}")
            print(f"{Colors.RED}{Colors.BOLD}{'═' * 60}{Colors.RESET}")
            print()

            # Quarantine the file
            threat_info = {
                "hash": file_hash,
                "type": threat_type,
                "severity": severity,
            }
            quarantine_file(filepath, self.quarantine_dir, threat_info)
        else:
            logger.info(f"   {Colors.GREEN}✅ CLEAN — No threat found on blockchain{Colors.RESET}")

        # Allow re-scanning after a bit
        time.sleep(1)
        self.scanned_files.discard(filepath)


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def print_banner():
    """Print the ThreatGuard startup banner."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║   ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ║
  ║   ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝   ║
  ║      ██║   ███████║██████╔╝█████╗  ███████║   ██║       ║
  ║      ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ║
  ║      ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ║
  ║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ║
  ║                                                          ║
  ║        🛡️  GUARD — Edge Defense Agent v1.0               ║
  ║        Powered by ThreatChain Blockchain Registry        ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
{Colors.RESET}""")


def main():
    parser = argparse.ArgumentParser(description="ThreatChain Edge Defense Agent")
    parser.add_argument(
        "--watch-dir",
        type=str,
        default=os.path.join(os.path.expanduser("~"), "Downloads"),
        help="Directory to monitor for new files (default: ~/Downloads)"
    )
    parser.add_argument(
        "--quarantine-dir",
        type=str,
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".quarantine"),
        help="Directory to move quarantined threats (default: edge-agent/.quarantine)"
    )
    parser.add_argument(
        "--scan-existing",
        action="store_true",
        help="Scan all existing files in the watch directory on startup"
    )
    args = parser.parse_args()

    print_banner()

    # Load config and connect to blockchain
    config = load_config()
    w3, contract = connect_blockchain(config)

    # Verify contract is responsive
    try:
        threat_count = contract.functions.threatCount().call()
        logger.info(f"{Colors.YELLOW}📊 Threats in registry: {threat_count}{Colors.RESET}")
    except Exception as e:
        logger.error(f"❌ Cannot read contract: {e}")
        sys.exit(1)

    # Set up file monitoring
    watch_dir = os.path.abspath(args.watch_dir)
    quarantine_dir = os.path.abspath(args.quarantine_dir)

    if not os.path.exists(watch_dir):
        os.makedirs(watch_dir, exist_ok=True)

    logger.info(f"{Colors.CYAN}👁️  Monitoring: {watch_dir}{Colors.RESET}")
    logger.info(f"{Colors.MAGENTA}🔒 Quarantine: {quarantine_dir}{Colors.RESET}")
    logger.info(f"{Colors.GREEN}{'─' * 60}{Colors.RESET}")
    logger.info(f"{Colors.GREEN}  Agent is ACTIVE — Drop a file to test threat detection{Colors.RESET}")
    logger.info(f"{Colors.GREEN}{'─' * 60}{Colors.RESET}")

    # Scan existing files if requested
    if args.scan_existing:
        logger.info("📂 Scanning existing files...")
        handler = ThreatFileHandler(contract, quarantine_dir)
        for filename in os.listdir(watch_dir):
            filepath = os.path.join(watch_dir, filename)
            if os.path.isfile(filepath):
                handler._scan_file(filepath)

    # Start the watchdog observer
    event_handler = ThreatFileHandler(contract, quarantine_dir)
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  Shutting down ThreatGuard agent...{Colors.RESET}")
        observer.stop()

    observer.join()
    print(f"{Colors.GREEN}✅ Agent stopped cleanly.{Colors.RESET}")


if __name__ == "__main__":
    main()
