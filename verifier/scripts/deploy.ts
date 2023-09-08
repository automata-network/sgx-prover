import { ethers } from "hardhat";

async function main() {
  const verifier = await ethers.deployContract("SGXVerifier", [], {
    // value: lockedAmount,
  });

  let result = await verifier.waitForDeployment();
  let contractAddress = await result.getAddress();

  console.log(`address: ${contractAddress}`);

  let attestor1 = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";


  let is_attestors = await verifier.attestors(attestor1);
  await verifier.addAttestors([attestor1]);

  const [sender] = await ethers.getSigners();

  let charge_accounts = [
    attestor1,
    "0x2939e6db5e0e9d666885f8236526d5caa6002993", // prover relay
  ];
  const amount = ethers.parseEther("1");
  for (const acc in charge_accounts) {
    await sender.sendTransaction({ to: charge_accounts[acc], value: amount });
  }

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
