import { ethers } from "hardhat";

async function main() {
    const SGXVerifier = await ethers.getContractFactory("SGXVerifier");
    let verifier = SGXVerifier.attach("0x9c946ea81253ce63bead0de22102f348e3e7cdfd");
    const sec = await verifier.attestValiditySeconds();
    // await verifier.changeAttestValiditySeconds(3600);
    console.log(sec);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
  