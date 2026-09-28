// Helper to run hardhat commands - workaround for & in path
const path = require("path");
const { execSync } = require("child_process");

const hardhatBin = path.join(__dirname, "node_modules", "hardhat", "internal", "cli", "bootstrap.js");
const args = process.argv.slice(2).join(" ");

// Hardhat v2.22 uses CommonJS entry point
const hardhatCli = path.join(__dirname, "node_modules", ".bin", "hardhat");

// Use the direct script approach
try {
    // For Hardhat 2.22.x, the entry point is different
    const hardhatPath = require.resolve("hardhat/internal/cli/bootstrap");
    require(hardhatPath);
} catch (e) {
    // Fallback: just run via npx with the full path quoted
    console.error("Direct require failed, trying alternative...", e.message);
    process.exit(1);
}
