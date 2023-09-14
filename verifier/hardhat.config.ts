import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.18",
  networks: {
    "l1": {
      url: "http://127.0.0.1:18545"
    }
  },
};

export default config;
