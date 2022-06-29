//* To generate a new account in a wallet.

// This is 'newAccount.js' file.

const {
  generateMnemonic,
  mnemonicToEntropy
} = require('ethereum-cryptography/bip39'); //importing Bitcoin Improvement Proposal 39, a specification for generating mnemonic or seed phrases

const { wordlist } = require('ethereum-cryptography/bip39/wordlists/english');
const { HDKey } = require('ethereum-cryptography/hdkey'); // BIP-32 is a specification for creating Hierarchical Deterministic (HD) wallets

const { getPublicKey } = require('ethereum-cryptography/secp256k1'); //secp256k1 elliptic curve for cryptographic computations.

const { keccak256 } = require('ethereum-cryptography/keccak'); // To calculate an address from the public key

const { writeFileSync } = require('fs');
const { bytesToHex } = require('ethereum-cryptography/utils');
const User = require('./../models/userModel');

// a function to generate a mnemonic
function _generateMnemonic() {
  const strength = 256; // 256 bits for 24 words; default is 128 bits for 12 words
  const mnemonic = generateMnemonic(wordlist, strength);
  const entropy = mnemonicToEntropy(mnemonic, wordlist); // 'entropy' is a random number , which needs to be a multiple of 32 bits (strength % 32 == 0) and between 128- and 256-bits long. A 128 bits-long entropy will produce a mnemonic consisting of 12 words, while a 256 bits-long entropy will produce a mnemonic of 24 words. The larger the entropy, the more mnemonic words generated, and the greater the security of your wallets.

  return { mnemonic, entropy };
}

// To generate the root key for Hierarchical Deterministic (HD) wallets
function _getHdRootKey(_mnemonic) {
  return HDKey.fromMasterSeed(_mnemonic);
}

// To generate private key from the root key
function _generatePrivateKey(_hdRootKey, _accountIndex) {
  return _hdRootKey.deriveChild(_accountIndex).privateKey;
}

// Each account’s public key is derived from a corresponding private key using the Elliptic Curve Digital Signature Algorithm or ECDSA
function _getPublicKey(_privateKey) {
  return getPublicKey(_privateKey);
}

// To calculate an address from the public key, we need to apply the Keccak-256 hashing alghorithm to the public key, and take the last (least significant) 20 bytes of the result.
function _getEthAddress(_publicKey) {
  return keccak256(_publicKey).slice(-20);
}

// To store our keys in a file system
function _store(_privateKey, _publicKey, _address) {
  const accountOne = {
    privateKey: _privateKey,
    publicKey: _publicKey,
    address: _address
  };
  const accountOneData = JSON.stringify(accountOne);
  writeFileSync(`${__dirname}/account 1.json`, accountOneData);
}

// To generate a new wallet mnemonic and the first account out of it
async function newAccount(req) {
  const { mnemonic, entropy } = _generateMnemonic();
  console.log(`WARNING! Never disclose your Seed Phrase:\n ${mnemonic}`);

  const hdRootKey = _getHdRootKey(entropy);

  const accountOneIndex = 0;
  const accountOnePrivateKey = _generatePrivateKey(hdRootKey, accountOneIndex);

  const accountOnePublicKey = _getPublicKey(accountOnePrivateKey);

  const accountOneAddress = _getEthAddress(accountOnePublicKey);
  console.log(`Account One Wallet Address: 0x${bytesToHex(accountOneAddress)}`);
  const walletAddress = `0x${bytesToHex(accountOneAddress)}`;

  _store(accountOnePrivateKey, accountOnePublicKey, accountOneAddress);

  //* Finding a user based on email and updating the wallet address after signing up.
  const user = await User.findOne({ email: req.body.email });
  user.walletAddress = walletAddress;
  await user.save({ validateBeforeSave: false });
}

module.exports = newAccount;

/*

Run in the terminal:

node newAccount.js


OUTPUT: 

WARNING! Never disclose your Seed Phrase:

cram crisp slice clerk entry waste fabric visit stamp direct rice dinosaur person hotel ginger excess initial spring boost apple ceiling section gap diet

Account One Wallet Address: 0xe31935cc053df03d922f3c5c56dec093141c4aaf


------------------------------------------------------------------------------------------------


leader mail scan fan copy fine observe maze legend inner hood shaft next waste crazy crash business start solar hedgehog attract depend youth bitter

Account Two Wallet Address: 0x81daa630890bb08486b040aee94ed43ebf384860


--------------------------------------------------------------------------------


slab into smart claim resist dune page tiny drama toy large logic draft health involve rack spy strong idea flat toast build mystery wood
Account One Wallet Address: 0x552e613c3528b9fda186cb85b104beecd10cce37

*/
