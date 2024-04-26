require("dotenv").config();

const { utils } = require("ethers");
const routerArtifact = require("@uniswap/v2-periphery/build/UniswapV2Router02.json");
const usdtArtifact = require("../artifacts/contracts/Tether.sol/Tether.json");
const usdcArtifact = require("../artifacts/contracts/UsdCoin.sol/UsdCoin.json");
const { ethers } = require("hardhat");
const assert = require("assert");

USDT_ADDRESS = process.env.USDT_ADDRESS;
USDC_ADDRESS = process.env.USDC_ADDRESS;
WETH_ADDRESS = process.env.WETH_ADDRESS;
FACTORY_ADDRESS = process.env.FACTORY_ADDRESS;
PAIR_ADDRESS = process.env.PAIR_ADDRESS;
ROUTER_ADDRESS = process.env.ROUTER_ADDRESS;

const main = async () => {
  const [owner, trader] = await ethers.getSigners();
  if (!owner || !owner.address || !trader || !trader.address) {
    throw new Error("Could not get owner and trader addresses");
  }
  const router = await ethers.getContractAt(routerArtifact.abi, ROUTER_ADDRESS);
  const usdt = await ethers.getContractAt(usdtArtifact.abi, USDT_ADDRESS);
  const usdc = await ethers.getContractAt(usdcArtifact.abi, USDC_ADDRESS);

  const getBalance = async (signerObj) => {
    let ethBalance;
    let usdtBalance;
    let usdcBalance;
    let balances;
    ethBalance = await signerObj.getBalance();
    usdtBalance = await usdt.balanceOf(signerObj.address);
    usdcBalance = await usdc.balanceOf(signerObj.address);
    balances = {
      ethBalance: ethBalance,
      usdtBalance: usdtBalance,
      usdcBalance: usdcBalance,
    };
    console.log(`balances of ${signerObj.address}`, balances);
    return balances;
  };

  console.log(
    `Starting with owner=${owner.address} and trader=${trader.address}`,
  );

  const ownerBalanceBefore = await getBalance(owner);
  const traderBalanceBefore = await getBalance(trader);

  const tx = await router
    .connect(trader)
    .swapExactTokensForTokens(
      utils.parseUnits("2", 18),
      utils.parseUnits("1", 18),
      [USDT_ADDRESS, USDC_ADDRESS],
      trader.address,
      Math.floor(Date.now() / 1000) + 60 * 10,
      {
        gasLimit: 1000000,
      },
    );

  await tx.wait();
  const ownerBalanceAfter = await getBalance(owner);
  const traderBalanceAfter = await getBalance(trader);

  // trader wallet is changed
  assert(traderBalanceBefore.ethBalance.gt(traderBalanceAfter.ethBalance));
  assert(traderBalanceBefore.usdtBalance.gt(traderBalanceAfter.usdtBalance));
  assert(traderBalanceBefore.usdcBalance.lt(traderBalanceAfter.usdcBalance));
};

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
