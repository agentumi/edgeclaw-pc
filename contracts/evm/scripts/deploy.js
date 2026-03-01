const hre = require("hardhat");

async function main() {
  console.log("Deploying EdgeClaw EVM contracts...");

  // 1. Device Registry
  const DeviceRegistry = await hre.ethers.getContractFactory("EdgeClawDeviceRegistry");
  const registry = await DeviceRegistry.deploy();
  await registry.waitForDeployment();
  console.log(`DeviceRegistry: ${await registry.getAddress()}`);

  // 2. Policy NFT
  const PolicyNFT = await hre.ethers.getContractFactory("EdgeClawPolicyNFT");
  const policy = await PolicyNFT.deploy();
  await policy.waitForDeployment();
  console.log(`PolicyNFT: ${await policy.getAddress()}`);

  // 3. Task Token (ECLAW)
  const TaskToken = await hre.ethers.getContractFactory("EdgeClawTaskToken");
  const token = await TaskToken.deploy();
  await token.waitForDeployment();
  console.log(`TaskToken (ECLAW): ${await token.getAddress()}`);

  // 4. Audit Anchor
  const AuditAnchor = await hre.ethers.getContractFactory("EdgeClawAuditAnchor");
  const audit = await AuditAnchor.deploy();
  await audit.waitForDeployment();
  console.log(`AuditAnchor: ${await audit.getAddress()}`);

  console.log("\nAll contracts deployed successfully!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
