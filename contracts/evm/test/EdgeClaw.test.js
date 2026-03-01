const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("EdgeClaw EVM Contracts", function () {
  // ─────────────────────────────────────────────────────
  // DeviceRegistry
  // ─────────────────────────────────────────────────────
  describe("DeviceRegistry", function () {
    let registry;
    let owner, user1, user2;

    beforeEach(async function () {
      [owner, user1, user2] = await ethers.getSigners();
      const Factory = await ethers.getContractFactory("EdgeClawDeviceRegistry");
      registry = await Factory.deploy();
    });

    it("should register a device", async function () {
      await registry.connect(user1).registerDevice("pk_001", "desktop-alpha", "desktop");
      expect(await registry.isRegistered("pk_001")).to.be.true;
      expect(await registry.deviceCount()).to.equal(1);
    });

    it("should store device metadata correctly", async function () {
      await registry.connect(user1).registerDevice("pk_meta", "my-laptop", "desktop");
      const device = await registry.getDevice("pk_meta");
      expect(device.publicKey).to.equal("pk_meta");
      expect(device.deviceName).to.equal("my-laptop");
      expect(device.deviceType).to.equal("desktop");
      expect(device.owner).to.equal(user1.address);
      expect(device.active).to.be.true;
    });

    it("should reject duplicate registration", async function () {
      await registry.connect(user1).registerDevice("pk_dup", "dev1", "desktop");
      await expect(
        registry.connect(user1).registerDevice("pk_dup", "dev2", "mobile")
      ).to.be.reverted;
    });

    it("should register multiple devices", async function () {
      await registry.connect(user1).registerDevice("pk_a", "dev-a", "desktop");
      await registry.connect(user2).registerDevice("pk_b", "dev-b", "mobile");
      expect(await registry.deviceCount()).to.equal(2);
    });

    it("should deactivate device by owner", async function () {
      await registry.connect(user1).registerDevice("pk_deact", "dev", "desktop");
      await registry.connect(user1).deactivateDevice("pk_deact");
      expect(await registry.isActive("pk_deact")).to.be.false;
    });

    it("should deactivate device by admin", async function () {
      await registry.connect(user1).registerDevice("pk_admin_d", "dev", "desktop");
      await registry.connect(owner).deactivateDevice("pk_admin_d");
      expect(await registry.isActive("pk_admin_d")).to.be.false;
    });

    it("should reject deactivation by unauthorized user", async function () {
      await registry.connect(user1).registerDevice("pk_unauth", "dev", "desktop");
      await expect(
        registry.connect(user2).deactivateDevice("pk_unauth")
      ).to.be.reverted;
    });

    it("should reactivate device", async function () {
      await registry.connect(user1).registerDevice("pk_react", "dev", "desktop");
      await registry.connect(user1).deactivateDevice("pk_react");
      expect(await registry.isActive("pk_react")).to.be.false;
      await registry.connect(user1).reactivateDevice("pk_react");
      expect(await registry.isActive("pk_react")).to.be.true;
    });

    it("should revert on non-existent device lookup", async function () {
      await expect(registry.getDevice("nonexistent")).to.be.reverted;
    });

    it("should emit DeviceRegistered event", async function () {
      await expect(
        registry.connect(user1).registerDevice("pk_evt", "dev", "desktop")
      ).to.emit(registry, "DeviceRegistered");
    });
  });

  // ─────────────────────────────────────────────────────
  // PolicyNFT
  // ─────────────────────────────────────────────────────
  describe("PolicyNFT", function () {
    let policy;
    let owner, user1, user2;

    beforeEach(async function () {
      [owner, user1, user2] = await ethers.getSigners();
      const Factory = await ethers.getContractFactory("EdgeClawPolicyNFT");
      policy = await Factory.deploy();
    });

    it("should mint a policy NFT", async function () {
      const tx = await policy.mintPolicy(user1.address, "admin", ["file_read", "file_write"], 0);
      await tx.wait();
      expect(await policy.balanceOf(user1.address)).to.equal(1);
    });

    it("should store policy data correctly", async function () {
      await policy.mintPolicy(user1.address, "operator", ["file_read"], 0);
      const p = await policy.getPolicy(0);
      expect(p.role).to.equal("operator");
      expect(p.capabilities[0]).to.equal("file_read");
      expect(p.revoked).to.be.false;
    });

    it("should reject invalid role", async function () {
      await expect(
        policy.mintPolicy(user1.address, "superadmin", ["all"], 0)
      ).to.be.reverted;
    });

    it("should mint all 5 valid roles", async function () {
      const roles = ["owner", "admin", "operator", "viewer", "guest"];
      for (const role of roles) {
        await policy.mintPolicy(user1.address, role, [], 0);
      }
      expect(await policy.balanceOf(user1.address)).to.equal(5);
    });

    it("should validate policy is valid", async function () {
      await policy.mintPolicy(user1.address, "admin", [], 0);
      expect(await policy.isPolicyValid(0)).to.be.true;
    });

    it("should revoke policy", async function () {
      await policy.mintPolicy(user1.address, "admin", [], 0);
      await policy.revokePolicy(0);
      expect(await policy.isRevoked(0)).to.be.true;
      expect(await policy.isPolicyValid(0)).to.be.false;
    });

    it("should reject double revocation", async function () {
      await policy.mintPolicy(user1.address, "admin", [], 0);
      await policy.revokePolicy(0);
      await expect(policy.revokePolicy(0)).to.be.reverted;
    });

    it("should reject revocation by non-issuer", async function () {
      await policy.mintPolicy(user1.address, "viewer", [], 0);
      await expect(
        policy.connect(user2).revokePolicy(0)
      ).to.be.reverted;
    });

    it("should return valid policies of holder", async function () {
      await policy.mintPolicy(user1.address, "admin", [], 0);
      await policy.mintPolicy(user1.address, "viewer", [], 0);
      await policy.revokePolicy(0); // revoke first
      const valid = await policy.validPoliciesOf(user1.address);
      expect(valid.length).to.equal(1);
      expect(valid[0]).to.equal(1); // only second policy
    });

    it("should emit PolicyMinted event", async function () {
      await expect(
        policy.mintPolicy(user1.address, "admin", [], 0)
      ).to.emit(policy, "PolicyMinted");
    });

    it("should only allow owner to mint", async function () {
      await expect(
        policy.connect(user1).mintPolicy(user2.address, "viewer", [], 0)
      ).to.be.reverted;
    });
  });

  // ─────────────────────────────────────────────────────
  // TaskToken (ECLAW)
  // ─────────────────────────────────────────────────────
  describe("TaskToken", function () {
    let token;
    let owner, user1, user2;

    beforeEach(async function () {
      [owner, user1, user2] = await ethers.getSigners();
      const Factory = await ethers.getContractFactory("EdgeClawTaskToken");
      token = await Factory.deploy();
    });

    it("should have correct name and symbol", async function () {
      expect(await token.name()).to.equal("EdgeClaw Task Token");
      expect(await token.symbol()).to.equal("ECLAW");
    });

    it("should start with zero supply", async function () {
      expect(await token.totalSupply()).to.equal(0);
    });

    it("should mint tokens", async function () {
      await token.mint(user1.address, ethers.parseEther("100"));
      expect(await token.balanceOf(user1.address)).to.equal(ethers.parseEther("100"));
    });

    it("should reject mint from non-owner", async function () {
      await expect(
        token.connect(user1).mint(user1.address, ethers.parseEther("100"))
      ).to.be.reverted;
    });

    it("should reward task executor", async function () {
      const taskId = ethers.keccak256(ethers.toUtf8Bytes("task-001"));
      await token.rewardTask(taskId, ethers.parseEther("50"), user1.address);
      expect(await token.balanceOf(user1.address)).to.equal(ethers.parseEther("50"));
    });

    it("should batch reward multiple executors", async function () {
      const ids = [
        ethers.keccak256(ethers.toUtf8Bytes("task-a")),
        ethers.keccak256(ethers.toUtf8Bytes("task-b")),
      ];
      const amounts = [ethers.parseEther("10"), ethers.parseEther("20")];
      await token.batchReward(ids, amounts, [user1.address, user2.address]);
      expect(await token.balanceOf(user1.address)).to.equal(ethers.parseEther("10"));
      expect(await token.balanceOf(user2.address)).to.equal(ethers.parseEther("20"));
    });

    it("should allow burn by holder", async function () {
      await token.mint(user1.address, ethers.parseEther("100"));
      await token.connect(user1).burn(ethers.parseEther("30"));
      expect(await token.balanceOf(user1.address)).to.equal(ethers.parseEther("70"));
    });

    it("should allow transfer between users", async function () {
      await token.mint(user1.address, ethers.parseEther("100"));
      await token.connect(user1).transfer(user2.address, ethers.parseEther("25"));
      expect(await token.balanceOf(user2.address)).to.equal(ethers.parseEther("25"));
    });

    it("should emit TaskReward event", async function () {
      const taskId = ethers.keccak256(ethers.toUtf8Bytes("task-evt"));
      await expect(
        token.rewardTask(taskId, ethers.parseEther("10"), user1.address)
      ).to.emit(token, "TaskReward");
    });

    it("should reject batch reward with mismatched arrays", async function () {
      const ids = [ethers.keccak256(ethers.toUtf8Bytes("t1"))];
      const amounts = [ethers.parseEther("10"), ethers.parseEther("20")];
      await expect(
        token.batchReward(ids, amounts, [user1.address])
      ).to.be.revertedWith("Array length mismatch");
    });
  });

  // ─────────────────────────────────────────────────────
  // AuditAnchor
  // ─────────────────────────────────────────────────────
  describe("AuditAnchor", function () {
    let audit;
    let owner, user1;

    beforeEach(async function () {
      [owner, user1] = await ethers.getSigners();
      const Factory = await ethers.getContractFactory("EdgeClawAuditAnchor");
      audit = await Factory.deploy();
    });

    it("should start with zero anchors", async function () {
      expect(await audit.anchorCount()).to.equal(0);
    });

    it("should anchor first batch", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("audit-batch-1"));
      await audit.anchorAudit(0, 99, hash);
      expect(await audit.anchorCount()).to.equal(1);
      expect(await audit.lastBatchEnd()).to.equal(99);
    });

    it("should anchor sequential batches", async function () {
      const h1 = ethers.keccak256(ethers.toUtf8Bytes("batch-1"));
      const h2 = ethers.keccak256(ethers.toUtf8Bytes("batch-2"));
      const h3 = ethers.keccak256(ethers.toUtf8Bytes("batch-3"));
      await audit.anchorAudit(0, 99, h1);
      await audit.anchorAudit(100, 199, h2);
      await audit.anchorAudit(200, 299, h3);
      expect(await audit.anchorCount()).to.equal(3);
    });

    it("should verify contiguous chain", async function () {
      const h1 = ethers.keccak256(ethers.toUtf8Bytes("v-batch-1"));
      const h2 = ethers.keccak256(ethers.toUtf8Bytes("v-batch-2"));
      await audit.anchorAudit(0, 99, h1);
      await audit.anchorAudit(100, 199, h2);
      expect(await audit.verifyChain()).to.be.true;
    });

    it("should reject overlapping batches", async function () {
      const h1 = ethers.keccak256(ethers.toUtf8Bytes("o-batch-1"));
      const h2 = ethers.keccak256(ethers.toUtf8Bytes("o-batch-2"));
      await audit.anchorAudit(0, 99, h1);
      await expect(audit.anchorAudit(50, 149, h2)).to.be.reverted;
    });

    it("should reject invalid range (start > end)", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("inv"));
      await expect(audit.anchorAudit(100, 50, hash)).to.be.reverted;
    });

    it("should reject anchor from non-owner", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("unauth"));
      await expect(
        audit.connect(user1).anchorAudit(0, 99, hash)
      ).to.be.reverted;
    });

    it("should get specific anchor record", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("record-test"));
      await audit.anchorAudit(0, 99, hash);
      const record = await audit.getAnchor(0);
      expect(record.batchStart).to.equal(0);
      expect(record.batchEnd).to.equal(99);
      expect(record.batchHash).to.equal(hash);
    });

    it("should get anchors in range", async function () {
      for (let i = 0; i < 5; i++) {
        const hash = ethers.keccak256(ethers.toUtf8Bytes(`range-${i}`));
        await audit.anchorAudit(i * 100, i * 100 + 99, hash);
      }
      const records = await audit.getAnchorsInRange(1, 4);
      expect(records.length).to.equal(3);
    });

    it("should emit AuditAnchored event", async function () {
      const hash = ethers.keccak256(ethers.toUtf8Bytes("evt"));
      await expect(
        audit.anchorAudit(0, 99, hash)
      ).to.emit(audit, "AuditAnchored");
    });

    it("should verify empty chain", async function () {
      expect(await audit.verifyChain()).to.be.true;
    });
  });
});
