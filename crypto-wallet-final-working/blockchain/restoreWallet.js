//* To restore a wallet using your mnemonic

// This is 'restoreWallet.js' file.

const { writeFileSync } = require('fs');
const { mnemonicToEntropy } = require('ethereum-cryptography/bip39');
const { wordlist } = require('ethereum-cryptography/bip39/wordlists/english');
const { HDKey } = require('ethereum-cryptography/hdkey');
const { getPublicKey } = require('ethereum-cryptography/secp256k1');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { bytesToHex } = require('ethereum-cryptography/utils');
const User = require('./../models/userModel');

// To restore a wallet using your mnemonic
async function restoreWallet(_mnemonic) {
  const entropy = mnemonicToEntropy(_mnemonic, wordlist);
  const hdRootKey = HDKey.fromMasterSeed(entropy); //root key
  const { privateKey } = hdRootKey.deriveChild(0); //private key
  const publicKey = getPublicKey(privateKey);
  const address = keccak256(publicKey).slice(-20);

  const restoredWalletAddress = bytesToHex(address);

  console.log(`Restored Wallet Address: 0x${restoredWalletAddress}`);

  const accountOne = {
    privateKey: privateKey,
    publicKey: publicKey,
    address: address
  };
  const accountOneData = JSON.stringify(accountOne);
  writeFileSync(
    `${__dirname}./../blockchain/restoredAccount.json`,
    accountOneData
  );

  //* Finding a user based on email and updating the wallet address after signing up.
  const user = await User.findOne({
    walletAddress: `0x${restoredWalletAddress}`
  });
  console.log(`Your email ID is: ${user.email}`);
}

module.exports = restoreWallet;

/*

To run it, type 'node restoreWallet.js' and your seed phrase.

node restoreWallet.js "cram crisp slice clerk entry waste fabric visit stamp direct rice dinosaur person hotel ginger excess initial spring boost apple ceiling section gap diet"


OUTPUT: 

Account One Wallet Address: 0xe31935cc053df03d922f3c5c56dec093141c4aaf

*/
