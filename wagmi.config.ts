import { defineConfig } from '@wagmi/cli';
import fs from 'fs';
import path from 'path';
// Read all .sol folders in out/
const outDir = 'out';
const solFolders = fs.readdirSync(outDir).filter(f => f.endsWith('.sol'));

const contractNames = [
    'Orderbook',
    'RoyaltyPaymentSplitter',
    'TokenVendingMachine',
    'TokenVendingMachineStorage',
    'RenaissRegistryV3',
    'IbToken',
    'NftEscrow',
    'ERC20',
    'IPermit2',
    'UUPSUpgradeable',
    'ISignatureTransfer',
    'Groth16Verifier'
]

const contracts = solFolders.flatMap(folder => {
  const contractDir = path.join(outDir, folder);
  const jsonFiles = fs.readdirSync(contractDir).filter(f => f.endsWith('.json'));
    
  return jsonFiles
    .filter(jsonFile => {
      const contractName = path.basename(jsonFile, '.json');
      return contractNames.includes(contractName); // Filter here
    })
    .map(jsonFile => {
      const artifact = JSON.parse(
        fs.readFileSync(path.join(contractDir, jsonFile), 'utf8')
      );
      return {
        name: path.basename(jsonFile, '.json'),
        abi: artifact.abi,
      };
    });
});
export default defineConfig({
  out: 'src/generated/wagmi.ts',
  contracts,
});

// export default defineConfig({
//     out: 'src/generated/wagmi.ts',
//     plugins: [
//       foundry({
//         project: '.',
//         artifacts: 'out/',
//         include: [
//           'Orderbook.sol/**',
//           'RoyaltyPaymentSplitter.sol/**',
//           'TokenVendingMachine.sol/**',
//           'RenaissRegistryV3.sol/**',
//           'IbToken.sol/**',
//           'NftEscrow.sol/**',
//           'MockERC20.sol/**',
//         ],
//       }),
//     ],
//   });
