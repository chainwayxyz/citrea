### Uniswap demo follow these steps:

1. Deploys `uniswap-v2` contracts.
2. Adds liquidity to the USDT <> USDC pair.
3. Executes a swap.

### How to run tests:
1. Run `npm install` inside uniswap directory.
2. Run sequencer.
3. Deploy `uniswap-v2` contracts and add liquidity with:
`npx hardhat run --network citrea scripts/01_deploy.js`
4. Execute a swap:
`npx hardhat run --network citrea scripts/02_swap.js` 
