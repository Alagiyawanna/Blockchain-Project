const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry", function () {
  let registry;
  let owner, analyst1, analyst2, unauthorized;

  // Sample threat data
  const sampleHash = ethers.encodeBytes32String("malware_sample_001");
  const sampleHash2 = ethers.encodeBytes32String("malware_sample_002");
  const threatType = "Ransomware";
  const severity = 5;
  const description = "LockBit 3.0 variant - CVE-2024-XXXX";

  beforeEach(async function () {
    [owner, analyst1, analyst2, unauthorized] = await ethers.getSigners();

    const ThreatRegistry = await ethers.getContractFactory("ThreatRegistry");
    registry = await ThreatRegistry.deploy();
    await registry.waitForDeployment();

    // Add analyst1 as an authorized analyst
    await registry.addAnalyst(analyst1.address);
  });

  // ─── Deployment Tests ────────────────────────────────────────────────
  describe("Deployment", function () {
    it("Should set the deployer as admin and analyst", async function () {
      const ADMIN_ROLE = await registry.DEFAULT_ADMIN_ROLE();
      const ANALYST_ROLE = await registry.ANALYST_ROLE();

      expect(await registry.hasRole(ADMIN_ROLE, owner.address)).to.be.true;
      expect(await registry.hasRole(ANALYST_ROLE, owner.address)).to.be.true;
    });

    it("Should start with zero threats", async function () {
      expect(await registry.threatCount()).to.equal(0);
    });
  });

  // ─── Analyst Management Tests ────────────────────────────────────────
  describe("Analyst Management", function () {
    it("Should allow admin to add an analyst", async function () {
      await expect(registry.addAnalyst(analyst2.address))
        .to.emit(registry, "AnalystAdded")
        .withArgs(analyst2.address, owner.address);

      const ANALYST_ROLE = await registry.ANALYST_ROLE();
      expect(await registry.hasRole(ANALYST_ROLE, analyst2.address)).to.be.true;
    });

    it("Should allow admin to remove an analyst", async function () {
      await expect(registry.removeAnalyst(analyst1.address))
        .to.emit(registry, "AnalystRemoved")
        .withArgs(analyst1.address, owner.address);

      const ANALYST_ROLE = await registry.ANALYST_ROLE();
      expect(await registry.hasRole(ANALYST_ROLE, analyst1.address)).to.be.false;
    });

    it("Should prevent non-admin from adding analysts", async function () {
      await expect(
        registry.connect(unauthorized).addAnalyst(analyst2.address)
      ).to.be.reverted;
    });
  });

  // ─── Threat Registration Tests ───────────────────────────────────────
  describe("Threat Registration", function () {
    it("Should allow an analyst to register a threat", async function () {
      const tx = await registry.connect(analyst1).registerThreat(sampleHash, threatType, severity, description);
      await expect(tx)
        .to.emit(registry, "ThreatReported")
        .withArgs(sampleHash, threatType, severity, analyst1.address, (val) => val > 0, description);

      expect(await registry.threatCount()).to.equal(1);
    });

    it("Should store correct threat details", async function () {
      await registry.connect(analyst1).registerThreat(sampleHash, threatType, severity, description);

      const threat = await registry.getThreatDetails(sampleHash);
      expect(threat.malwareHash).to.equal(sampleHash);
      expect(threat.threatType).to.equal(threatType);
      expect(threat.severity).to.equal(severity);
      expect(threat.reporter).to.equal(analyst1.address);
      expect(threat.description).to.equal(description);
      expect(threat.isActive).to.be.true;
    });

    it("Should reject duplicate hash registration", async function () {
      await registry.connect(analyst1).registerThreat(sampleHash, threatType, severity, description);

      await expect(
        registry.connect(analyst1).registerThreat(sampleHash, "Trojan", 3, "duplicate")
      ).to.be.revertedWithCustomError(registry, "ThreatAlreadyExists");
    });

    it("Should reject empty hash", async function () {
      await expect(
        registry.connect(analyst1).registerThreat(ethers.ZeroHash, threatType, severity, description)
      ).to.be.revertedWithCustomError(registry, "EmptyHash");
    });

    it("Should reject invalid severity (0 or > 5)", async function () {
      await expect(
        registry.connect(analyst1).registerThreat(sampleHash, threatType, 0, description)
      ).to.be.revertedWithCustomError(registry, "InvalidSeverity");

      await expect(
        registry.connect(analyst1).registerThreat(sampleHash, threatType, 6, description)
      ).to.be.revertedWithCustomError(registry, "InvalidSeverity");
    });

    it("Should prevent unauthorized users from registering threats", async function () {
      await expect(
        registry.connect(unauthorized).registerThreat(sampleHash, threatType, severity, description)
      ).to.be.reverted;
    });
  });

  // ─── Threat Lookup Tests ─────────────────────────────────────────────
  describe("Threat Lookup (isThreat)", function () {
    beforeEach(async function () {
      await registry.connect(analyst1).registerThreat(sampleHash, threatType, severity, description);
    });

    it("Should return true for a registered active threat", async function () {
      const [exists, sev, tType] = await registry.isThreat(sampleHash);
      expect(exists).to.be.true;
      expect(sev).to.equal(severity);
      expect(tType).to.equal(threatType);
    });

    it("Should return false for an unknown hash", async function () {
      const unknownHash = ethers.encodeBytes32String("clean_file_hash");
      const [exists, sev, tType] = await registry.isThreat(unknownHash);
      expect(exists).to.be.false;
      expect(sev).to.equal(0);
      expect(tType).to.equal("");
    });
  });

  // ─── Threat Revocation Tests ─────────────────────────────────────────
  describe("Threat Revocation", function () {
    beforeEach(async function () {
      await registry.connect(analyst1).registerThreat(sampleHash, threatType, severity, description);
    });

    it("Should allow admin to revoke a threat", async function () {
      const tx = await registry.revokeThreat(sampleHash, "False positive confirmed");
      await expect(tx)
        .to.emit(registry, "ThreatRevoked")
        .withArgs(sampleHash, owner.address, "False positive confirmed", (val) => val > 0);

      const [exists] = await registry.isThreat(sampleHash);
      expect(exists).to.be.false;
    });

    it("Should preserve revoked threat details for audit trail", async function () {
      await registry.revokeThreat(sampleHash, "False positive");

      const threat = await registry.getThreatDetails(sampleHash);
      expect(threat.isActive).to.be.false;
      expect(threat.reporter).to.equal(analyst1.address);
      // Record still exists — immutable audit trail preserved
    });

    it("Should prevent non-admin from revoking threats", async function () {
      await expect(
        registry.connect(analyst1).revokeThreat(sampleHash, "trying to revoke")
      ).to.be.reverted;
    });

    it("Should revert when revoking a non-existent threat", async function () {
      const unknownHash = ethers.encodeBytes32String("unknown");
      await expect(
        registry.revokeThreat(unknownHash, "does not exist")
      ).to.be.revertedWithCustomError(registry, "ThreatNotFound");
    });
  });

  // ─── Enumeration & Pagination Tests ──────────────────────────────────
  describe("Enumeration & Pagination", function () {
    beforeEach(async function () {
      await registry.connect(analyst1).registerThreat(sampleHash, "Ransomware", 5, "First threat");
      await registry.connect(analyst1).registerThreat(sampleHash2, "Trojan", 3, "Second threat");
    });

    it("Should return all threat hashes", async function () {
      const allHashes = await registry.getAllThreats();
      expect(allHashes.length).to.equal(2);
      expect(allHashes[0]).to.equal(sampleHash);
      expect(allHashes[1]).to.equal(sampleHash2);
    });

    it("Should support paginated queries", async function () {
      const page = await registry.getThreats(0, 1);
      expect(page.length).to.equal(1);
      expect(page[0]).to.equal(sampleHash);

      const page2 = await registry.getThreats(1, 1);
      expect(page2.length).to.equal(1);
      expect(page2[0]).to.equal(sampleHash2);
    });

    it("Should handle out-of-range pagination gracefully", async function () {
      const page = await registry.getThreats(0, 100);
      expect(page.length).to.equal(2);
    });
  });
});
