import { ethers } from "hardhat";
import { readFileSync } from 'fs';

async function main() {
    const AutomataDcapV3Attestation = await ethers.getContractFactory("AutomataDcapV3Attestation");
    let attestion = AutomataDcapV3Attestation.attach(process.env.CONTRACT);
    if (process.env.MRENCLAVE) {
        await attestion.setMrEnclave(process.env.MRENCLAVE, true);
    }
    if (process.env.MRSIGNER) {
        await attestion.setMrSigner(process.env.MRSIGNER, true);
    }
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
  