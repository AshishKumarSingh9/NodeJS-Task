//* Sending native coins from your wallet.

// This is 'send.js 'file

// When you want to send some of your native coins, you must digitally sign the data using ECDSA with your private key and encrypt it before its sent to the receiver. The receiver can verify the signature using your public key.

const { getDefaultProvider, Wallet, utils } = require('ethers');
const { readFileSync } = require('fs');

async function sendTransaction(_receiverAddress, _ethAmount) {
  const network = 'rinkeby';
  const provider = getDefaultProvider(network);

  const accountRawData = readFileSync(`${__dirname}/account 1.json`, 'utf8');
  const accountData = JSON.parse(accountRawData);

  const privateKey = Object.values(accountData.privateKey);

  const signer = new Wallet(privateKey, provider);

  const transaction = await signer.sendTransaction({
    to: _receiverAddress,
    value: utils.parseEther(_ethAmount)
  });

  console.log(transaction);
}


module.exports = sendTransaction;
/*

Run in the terminal:

node send.js “receiverAddress” “amount”


OUTPUT: 


*/
