import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Edgeclaw } from "../target/types/edgeclaw";
import { expect } from "chai";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  createAssociatedTokenAccountInstruction,
} from "@solana/spl-token";

describe("EdgeClaw Solana Programs", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Edgeclaw as Program<Edgeclaw>;
  const admin = provider.wallet;

  // PDA seeds
  const [registryPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    program.programId
  );

  const [auditStorePda] = PublicKey.findProgramAddressSync(
    [Buffer.from("audit_store")],
    program.programId
  );

  const [tokenAuthorityPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("token_authority")],
    program.programId
  );

  const [eclawMintPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("eclaw_mint")],
    program.programId
  );

  const [policyCounterPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("policy_counter")],
    program.programId
  );

  // ─────────────────────────────────────────────────────
  // Device Registry
  // ─────────────────────────────────────────────────────
  describe("DeviceRegistry", () => {
    it("initializes the registry", async () => {
      await program.methods
        .initializeRegistry()
        .accounts({
          registry: registryPda,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const registry = await program.account.registryState.fetch(registryPda);
      expect(registry.admin.toString()).to.equal(admin.publicKey.toString());
      expect(registry.deviceCount.toNumber()).to.equal(0);
    });

    it("registers a device", async () => {
      const pubkey = "ed25519_pk_solana_001";
      const [devicePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("device"), Buffer.from(pubkey)],
        program.programId
      );

      await program.methods
        .registerDevice(pubkey, "test-desktop", "desktop")
        .accounts({
          registry: registryPda,
          device: devicePda,
          owner: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const device = await program.account.deviceRecord.fetch(devicePda);
      expect(device.publicKey).to.equal(pubkey);
      expect(device.deviceName).to.equal("test-desktop");
      expect(device.deviceType).to.equal("desktop");
      expect(device.active).to.be.true;
    });

    it("registers a second device", async () => {
      const pubkey = "ed25519_pk_solana_002";
      const [devicePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("device"), Buffer.from(pubkey)],
        program.programId
      );

      await program.methods
        .registerDevice(pubkey, "test-mobile", "mobile")
        .accounts({
          registry: registryPda,
          device: devicePda,
          owner: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const device = await program.account.deviceRecord.fetch(devicePda);
      expect(device.deviceType).to.equal("mobile");
      expect(device.active).to.be.true;
    });

    it("deactivates a device", async () => {
      const pubkey = "ed25519_pk_solana_001";
      const [devicePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("device"), Buffer.from(pubkey)],
        program.programId
      );

      await program.methods
        .deactivateDevice()
        .accounts({
          registry: registryPda,
          device: devicePda,
          authority: admin.publicKey,
        })
        .rpc();

      const device = await program.account.deviceRecord.fetch(devicePda);
      expect(device.active).to.be.false;
    });

    it("reactivates a device", async () => {
      const pubkey = "ed25519_pk_solana_001";
      const [devicePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("device"), Buffer.from(pubkey)],
        program.programId
      );

      await program.methods
        .reactivateDevice()
        .accounts({
          registry: registryPda,
          device: devicePda,
          authority: admin.publicKey,
        })
        .rpc();

      const device = await program.account.deviceRecord.fetch(devicePda);
      expect(device.active).to.be.true;
    });
  });

  // ─────────────────────────────────────────────────────
  // Audit Anchor
  // ─────────────────────────────────────────────────────
  describe("AuditAnchor", () => {
    it("initializes the audit store", async () => {
      await program.methods
        .initializeAudit()
        .accounts({
          store: auditStorePda,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const store = await program.account.auditStore.fetch(auditStorePda);
      expect(store.anchorCount.toNumber()).to.equal(0);
      expect(store.lastBatchEnd.toNumber()).to.equal(0);
    });

    it("anchors first batch", async () => {
      const batchHash = new Array(32).fill(0);
      batchHash[0] = 0xab;
      batchHash[1] = 0xcd;

      const [anchorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("anchor"),
          Buffer.from(new anchor.BN(0).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      await program.methods
        .anchorAudit(new anchor.BN(0), new anchor.BN(99), batchHash)
        .accounts({
          store: auditStorePda,
          anchorRecord: anchorPda,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const store = await program.account.auditStore.fetch(auditStorePda);
      expect(store.anchorCount.toNumber()).to.equal(1);
      expect(store.lastBatchEnd.toNumber()).to.equal(99);
    });

    it("anchors sequential batch", async () => {
      const batchHash = new Array(32).fill(0);
      batchHash[0] = 0xef;

      const [anchorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("anchor"),
          Buffer.from(new anchor.BN(1).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      await program.methods
        .anchorAudit(new anchor.BN(100), new anchor.BN(199), batchHash)
        .accounts({
          store: auditStorePda,
          anchorRecord: anchorPda,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const store = await program.account.auditStore.fetch(auditStorePda);
      expect(store.anchorCount.toNumber()).to.equal(2);
      expect(store.lastBatchEnd.toNumber()).to.equal(199);
    });

    it("rejects overlapping batch", async () => {
      const batchHash = new Array(32).fill(0);

      const [anchorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("anchor"),
          Buffer.from(new anchor.BN(2).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      try {
        await program.methods
          .anchorAudit(new anchor.BN(150), new anchor.BN(250), batchHash)
          .accounts({
            store: auditStorePda,
            anchorRecord: anchorPda,
            admin: admin.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        expect.fail("should have thrown");
      } catch (err) {
        expect(err.toString()).to.contain("BatchOverlap");
      }
    });

    it("rejects invalid range", async () => {
      const batchHash = new Array(32).fill(0);

      const [anchorPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("anchor"),
          Buffer.from(new anchor.BN(2).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      try {
        await program.methods
          .anchorAudit(new anchor.BN(300), new anchor.BN(200), batchHash)
          .accounts({
            store: auditStorePda,
            anchorRecord: anchorPda,
            admin: admin.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        expect.fail("should have thrown");
      } catch (err) {
        expect(err.toString()).to.contain("InvalidRange");
      }
    });
  });

  // ─────────────────────────────────────────────────────
  // Policy NFT
  // ─────────────────────────────────────────────────────
  describe("PolicyNFT", () => {
    const recipient = Keypair.generate();

    it("initializes the policy counter", async () => {
      await program.methods
        .initializePolicyCounter()
        .accounts({
          counter: policyCounterPda,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const counter = await program.account.policyCounter.fetch(policyCounterPda);
      expect(counter.nextId.toNumber()).to.equal(0);
    });

    it("mints a policy with admin role", async () => {
      // Find the policy PDA for ID=0
      const [policyPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("policy"),
          Buffer.from(new anchor.BN(0).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      await program.methods
        .mintPolicy("admin", ["file_read", "file_write", "process_manage"], new anchor.BN(0))
        .accounts({
          counter: policyCounterPda,
          policy: policyPda,
          owner: recipient.publicKey,
          issuer: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const policy = await program.account.policyRecord.fetch(policyPda);
      expect(policy.role).to.equal("admin");
      expect(policy.revoked).to.be.false;
      expect(policy.owner.toString()).to.equal(recipient.publicKey.toString());
    });

    it("rejects invalid role", async () => {
      const [policyPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("policy"),
          Buffer.from(new anchor.BN(1).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      try {
        await program.methods
          .mintPolicy("superadmin", ["all"], new anchor.BN(0))
          .accounts({
            counter: policyCounterPda,
            policy: policyPda,
            owner: recipient.publicKey,
            issuer: admin.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        expect.fail("should have thrown");
      } catch (err) {
        expect(err.toString()).to.contain("InvalidRole");
      }
    });

    it("revokes a policy", async () => {
      const [policyPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("policy"),
          Buffer.from(new anchor.BN(0).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      await program.methods
        .revokePolicy()
        .accounts({
          policy: policyPda,
          counter: policyCounterPda,
          authority: admin.publicKey,
        })
        .rpc();

      const policy = await program.account.policyRecord.fetch(policyPda);
      expect(policy.revoked).to.be.true;
    });

    it("rejects double revocation", async () => {
      const [policyPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("policy"),
          Buffer.from(new anchor.BN(0).toArrayLike(Buffer, "le", 8)),
        ],
        program.programId
      );

      try {
        await program.methods
          .revokePolicy()
          .accounts({
            policy: policyPda,
            counter: policyCounterPda,
            authority: admin.publicKey,
          })
          .rpc();
        expect.fail("should have thrown");
      } catch (err) {
        expect(err.toString()).to.contain("AlreadyRevoked");
      }
    });
  });

  // ─────────────────────────────────────────────────────
  // Task Token (ECLAW)
  // ─────────────────────────────────────────────────────
  describe("TaskToken", () => {
    it("initializes token mint", async () => {
      await program.methods
        .initializeToken(9) // 9 decimals like SUI
        .accounts({
          authority: tokenAuthorityPda,
          mint: eclawMintPda,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();

      const auth = await program.account.tokenAuthority.fetch(tokenAuthorityPda);
      expect(auth.admin.toString()).to.equal(admin.publicKey.toString());
      expect(auth.totalMinted.toNumber()).to.equal(0);
    });

    it("mints tokens to recipient", async () => {
      const recipient = Keypair.generate();
      const ata = await getAssociatedTokenAddress(
        eclawMintPda,
        recipient.publicKey
      );

      // Create ATA first
      const createAtaIx = createAssociatedTokenAccountInstruction(
        admin.publicKey,
        ata,
        recipient.publicKey,
        eclawMintPda
      );

      const tx = new anchor.web3.Transaction().add(createAtaIx);
      await provider.sendAndConfirm(tx);

      await program.methods
        .mintTokens(new anchor.BN(1_000_000_000)) // 1 ECLAW
        .accounts({
          authority: tokenAuthorityPda,
          mint: eclawMintPda,
          recipientTokenAccount: ata,
          admin: admin.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .rpc();
    });

    it("rewards task executor", async () => {
      const executor = Keypair.generate();
      const ata = await getAssociatedTokenAddress(
        eclawMintPda,
        executor.publicKey
      );

      const createAtaIx = createAssociatedTokenAccountInstruction(
        admin.publicKey,
        ata,
        executor.publicKey,
        eclawMintPda
      );

      const tx = new anchor.web3.Transaction().add(createAtaIx);
      await provider.sendAndConfirm(tx);

      const taskId = new Array(32).fill(0);
      taskId[0] = 0x01;

      await program.methods
        .rewardTask(taskId, new anchor.BN(500_000_000)) // 0.5 ECLAW
        .accounts({
          authority: tokenAuthorityPda,
          mint: eclawMintPda,
          executorTokenAccount: ata,
          admin: admin.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .rpc();
    });

    it("rejects zero amount mint", async () => {
      const recipient = Keypair.generate();
      const ata = await getAssociatedTokenAddress(
        eclawMintPda,
        recipient.publicKey
      );

      const createAtaIx = createAssociatedTokenAccountInstruction(
        admin.publicKey,
        ata,
        recipient.publicKey,
        eclawMintPda
      );
      const tx = new anchor.web3.Transaction().add(createAtaIx);
      await provider.sendAndConfirm(tx);

      try {
        await program.methods
          .mintTokens(new anchor.BN(0))
          .accounts({
            authority: tokenAuthorityPda,
            mint: eclawMintPda,
            recipientTokenAccount: ata,
            admin: admin.publicKey,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .rpc();
        expect.fail("should have thrown");
      } catch (err) {
        expect(err.toString()).to.contain("ZeroAmount");
      }
    });
  });
});
