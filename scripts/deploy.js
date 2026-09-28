const hre = require("hardhat");

async function main() {
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  🛡️  ThreatChain — Deploying ThreatRegistry Contract");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const [deployer] = await hre.ethers.getSigners();
  console.log(`\n  📍 Deployer address : ${deployer.address}`);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`  💰 Deployer balance : ${hre.ethers.formatEther(balance)} ETH`);

  // Deploy the contract
  console.log("\n  ⏳ Deploying ThreatRegistry...");
  const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
  const registry = await ThreatRegistry.deploy();
  await registry.waitForDeployment();

  const contractAddress = await registry.getAddress();
  console.log(`  ✅ ThreatRegistry deployed to: ${contractAddress}`);

  // Register a sample threat for demo purposes
  console.log("\n  📝 Registering sample threat for demo...");
  const sampleHash = hre.ethers.encodeBytes32String("EICAR_TEST_FILE");
  const tx = await registry.registerThreat(
    sampleHash,
    "Test_Malware",
    5,
    "EICAR Standard Anti-Malware Test File - Demo Threat"
  );
  await tx.wait();
  console.log(`  ✅ Sample threat registered (hash: ${sampleHash})`);

  // Verify the registration
  const [exists, severity, threatType] = await registry.isThreat(sampleHash);
  console.log(`  🔍 Verification: exists=${exists}, severity=${severity}, type=${threatType}`);

  // Output deployment info for other components
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  📋 DEPLOYMENT SUMMARY");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`  Contract Address : ${contractAddress}`);
  console.log(`  Network          : ${hre.network.name}`);
  console.log(`  Deployer         : ${deployer.address}`);
  console.log(`  Threat Count     : ${await registry.threatCount()}`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  // Save deployment info to a JSON file for frontend & Python agent
  const fs = require("fs");
  const path = require("path");

  // Get the contract ABI from the compiled artifacts
  const artifact = await hre.artifacts.readArtifact("ThreatRegistry");

  const deploymentInfo = {
    contractAddress: contractAddress,
    network: hre.network.name,
    deployer: deployer.address,
    rpcUrl: "http://127.0.0.1:8545",
    abi: artifact.abi,
    deployedAt: new Date().toISOString(),
  };

  // Save for the Python edge agent
  const agentConfigPath = path.join(__dirname, "..", "edge-agent", "config.json");
  fs.mkdirSync(path.dirname(agentConfigPath), { recursive: true });
  fs.writeFileSync(agentConfigPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\n  💾 Config saved to: edge-agent/config.json`);

  // Save for the frontend
  const frontendConfigPath = path.join(__dirname, "..", "frontend", "deployment.json");
  fs.mkdirSync(path.dirname(frontendConfigPath), { recursive: true });
  fs.writeFileSync(frontendConfigPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`  💾 Config saved to: frontend/deployment.json`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
