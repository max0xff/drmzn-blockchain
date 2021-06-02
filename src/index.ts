import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';

import ES from 'elliptic';
import SHA256 from 'crypto-js/sha256';

const { ec: elliptic } = ES;
const ec = new elliptic('secp256k1');

const DIFFICULTY = 3;
const MINING_REWARD = 10000;

const pendingTransactions: TransactionType[] = [];
const chain: ChainType = [];

type ChainType = BlockType[];

type BlockType = {
  timestamp: string;
  transactions: TransactionType[];
  previousHash?: string;
  nonce?: number;
  hash?: string;
  size?: number;
  version?: number;
};

type TransactionType = {
  sender: string;
  receiver: string;
  amount: number;
  timestamp?: string;
  hash?: string;
  signature?: string;
  meta?: Object;
}

/** Returns hashed transaction */
function Transaction(params: TransactionType) {
  const { sender, receiver, amount, timestamp = generateTimestamp(), meta = undefined } = params;
  const hash = SHA256(sender + receiver + amount + timestamp + meta).toString();
  return { ...params, hash, timestamp };
}

/** Returns hashed block */
function Block(params: BlockType) {
  const { timestamp, transactions = [], previousHash } = params;
  const hash = calculateBlockHash({ timestamp, transactions, previousHash });
  return { timestamp, transactions, previousHash, hash };
}

/** Returns block hash */
function calculateBlockHash(params: BlockType) {
  const { timestamp, transactions, previousHash, nonce = 0 } = params;
  const hash: string = SHA256(previousHash + timestamp + JSON.stringify(transactions) + nonce).toString();
  return hash;
}

/** Returns mined hash and nonce */
function mineBlock(params: BlockType) {
  const { timestamp, transactions, previousHash, nonce = 0 } = params;
  let n = nonce;
  let hash = SHA256(previousHash + timestamp + JSON.stringify(transactions) + n).toString();
  while (hash.substring(0, DIFFICULTY) !== Array(DIFFICULTY + 1).join("0")) {
    n++;
    hash = calculateBlockHash({ timestamp, transactions, previousHash, nonce: n });
  }
  return { minedBlockHash: hash, nonce: n };
}

/** Mines new block with pending transacions, adds the block to the chain */
function minePendingTransactions({ minigRewardAddress }) {
  const previousHash = chain[chain.length - 1].hash;
  const miningRewardTransaction = Transaction({ sender: undefined, receiver: minigRewardAddress, amount: MINING_REWARD, meta: { label: 'mining reward' } });
  // validate pending transactions
  if (!hasValidTransactions(pendingTransactions)) {
    console.log('pending transactions are invalid!');
    return false;
  }
  // generate block
  const block = Block({ timestamp: generateTimestamp(), transactions: [miningRewardTransaction, ...pendingTransactions], previousHash });
  const { minedBlockHash, nonce } = mineBlock(block);
  // validate block
  const newBlock = { timestamp: block.timestamp, transactions: block.transactions, previousHash, nonce };
  const validated = calculateBlockHash({ ...newBlock });
  if (validated === minedBlockHash && isChainValid(chain)) {
    // validate chain
    const validatedChain = chain.slice();
    validatedChain.push({ ...newBlock, previousHash, hash: minedBlockHash, nonce });
    if (isChainValid(validatedChain)) {
      chain.push({ ...newBlock, previousHash, hash: minedBlockHash, nonce });
      pendingTransactions.length = 0;
    }
  }
  return false;
}

function addGenesisBlock() {
  const timestamp = generateTimestamp();
  const previousHash = "none";
  const block = Block({ timestamp, transactions: [], previousHash });
  const hash = calculateBlockHash({ timestamp, previousHash, transactions: [] });
  if (chain.length === 0) {
    chain.push({ ...block, previousHash, timestamp, hash, nonce: 0 });
  }
  return false;
}

function addPendingTransaction(params: TransactionType) {
  const transaction = Transaction({ ...params });
  if (isTransactionValid(transaction)) {
    pendingTransactions.push(transaction);
  }
}

function signTransaction(signingKey: ES.ec.KeyPair, transactionData: TransactionType) {
  const transaction = Transaction(transactionData);
  if (signingKey.getPublic('hex') !== transaction.sender) {
    throw new Error('Error bro!');
  }
  const transactionHash = SHA256(transaction.sender + transaction.receiver + transaction.amount + transaction.timestamp + transaction.meta).toString();
  const sig = signingKey.sign(transactionHash, 'base64');
  const signature = sig.toDER('hex');
  return { ...transaction, signature };
}

function isTransactionValid(transaction: TransactionType) {
  if (!transaction.sender) {
    return true;
  };
  if (transaction.sender === transaction.receiver) {
    console.log('sender is the same as receiver!')
    return false;
  };
  if (transaction.amount < 1) {
    console.log('amount is less then 1!');
    return false;
  };
  const senderBalance = getBalanaceOfAddress(transaction.sender);
  if ((senderBalance - transaction.amount) < 0) {
    console.log('sender balance is too low!');
    return false;
  };
  if (!transaction.signature) {
    console.log('missing transaction signature!');
    return false;
  }
  const transactionHash = SHA256(transaction.sender + transaction.receiver + transaction.amount + transaction.timestamp + transaction.meta).toString();
  const publicKey = ec.keyFromPublic(transaction.sender, 'hex');
  const isValid = publicKey.verify(transactionHash, transaction.signature);
  return isValid;
}

function hasValidTransactions(transactions: TransactionType[]) {
  for (const tx of transactions) {
    if (!isTransactionValid(tx)) {
      return false;
    }
  }
  return true;
}

function isChainValid(chain: ChainType) {
  for (let i = 1; i < chain.length; i++) {
    const currentBlock = chain[i];
    const previousBlock = chain[i - 1];
    const computedHash = calculateBlockHash({ ...currentBlock });
    if (!hasValidTransactions(currentBlock.transactions)) {
      console.log('chain contains invalid transactions!');
      return false;
    }
    if (currentBlock.hash !== computedHash) {
      console.log('hash validation failed!');
      return false;
    }
    if (currentBlock.previousHash !== previousBlock.hash) {
      console.log('current block hash and prev block hash dont match!');
      return false;
    }
  }
  return true;
}

function generateTimestamp() {
  return new Date().getTime().toString();
}

const getBalanaceOfAddress = (address: string) => {
  let balance = 0;
  for (const block of <ChainType>chain) {
    for (const trans of block.transactions) {
      if (trans.sender === address) {
        balance -= trans.amount;
      }
      if (trans.receiver === address) {
        balance += trans.amount;
      }
    }
  }
  return balance;
};

const getTransactionsOfAddress = (address: string) => {
  let incoming = [];
  let outgoing = [];
  for (const block of <ChainType>chain) {
    for (const trans of block.transactions) {
      if (trans.sender === address) {
        outgoing.push(trans);
      }
      if (trans.receiver === address) {
        incoming.push(trans);
      }
    }
  }
  return { incoming, outgoing };
}

// add genesis block
addGenesisBlock();

// testing
const myKey = ec.keyFromPrivate('bfe05794fb26b8dcbb0132f00eee9efd1dda5e757223fcbef73ab2e100acbdad');
const myWalletAddress = myKey.getPublic('hex');

const tprk1 = ec.keyFromPrivate('4b90aa6905fe6d7cfc5f77137048f3f13dc0c0a73bf22bae974f3f70e861f8b6');
const tpuk1 = tprk1.getPublic('hex');

const tprk2 = ec.keyFromPrivate('6a0ffd6d2ad320ed4a3af1824fff751189029f6b7fbe4574b698b22d99e110ae');
const tpuk2 = tprk2.getPublic('hex');

const tprk3 = ec.keyFromPrivate('fa8ece008ce244603edb2eb3946d8247bbfe18ee3f16df345cfb0901486b09c0');
const tpuk3 = tprk3.getPublic('hex');

minePendingTransactions({ minigRewardAddress: myWalletAddress });
minePendingTransactions({ minigRewardAddress: myWalletAddress });
minePendingTransactions({ minigRewardAddress: myWalletAddress });

addPendingTransaction(signTransaction(myKey, { sender: myWalletAddress, receiver: tpuk1, amount: 3000, meta: { label: 'Payment #12345' } }));
addPendingTransaction(signTransaction(myKey, { sender: myWalletAddress, receiver: tpuk2, amount: 4000 }));
addPendingTransaction(signTransaction(myKey, { sender: myWalletAddress, receiver: tpuk3, amount: 5000 }));

minePendingTransactions({ minigRewardAddress: myWalletAddress });
minePendingTransactions({ minigRewardAddress: myWalletAddress });
minePendingTransactions({ minigRewardAddress: myWalletAddress });

addPendingTransaction(signTransaction(tprk1, { sender: tpuk1, receiver: tpuk3, amount: 150 }));
addPendingTransaction(signTransaction(tprk2, { sender: tpuk2, receiver: tpuk1, amount: 720 }));
addPendingTransaction(signTransaction(tprk3, { sender: tpuk3, receiver: tpuk2, amount: 2400 }));

minePendingTransactions({ minigRewardAddress: myWalletAddress });
minePendingTransactions({ minigRewardAddress: myWalletAddress });
minePendingTransactions({ minigRewardAddress: myWalletAddress });

console.log('chain', JSON.stringify(chain, undefined, 4));
console.log('is chain valid?', isChainValid(chain));

console.log(getBalanaceOfAddress(tpuk1));
console.log(getBalanaceOfAddress(tpuk2));
console.log(getBalanaceOfAddress(tpuk3));
console.log(getBalanaceOfAddress(myWalletAddress));


// api

const app = new Koa();
const router = new Router();

app.use(bodyParser());

const defaultRoute = (ctx) => {
  ctx.body = 'hello world';
}

const getPendingTransactions = (ctx) => {
  ctx.body = { pendingTransactions };
}

const getTransactions = (ctx) => {
  const { address } = ctx.params;
  const transactions = getTransactionsOfAddress(address);
  ctx.body = { transactions };
}

const getChain = (ctx) => {
  ctx.body = { chain };
}

const getLatestBlock = (ctx) => {
  ctx.body = { chain };
}

const minePending = (ctx) => {
  minePendingTransactions({ minigRewardAddress: myWalletAddress });
  ctx.body = { chain };
}

const getBalance = (ctx) => {
  const { address } = ctx.params;
  ctx.body = { address, balance: getBalanaceOfAddress(address) };
}

const createWallet = (ctx) => {
  const key = ec.genKeyPair();
  const publicKey = key.getPublic('hex');
  const privateKey = key.getPrivate('hex');
  ctx.body = { publicKey, privateKey };
}

const sendTransaction = (ctx) => {
  const { sender, receiver, amount, signature } = ctx.request.body;
  const senderKey = ec.keyFromPrivate(signature);
  addPendingTransaction(signTransaction(senderKey, { sender, receiver, amount }));
  ctx.body = { sender, receiver, amount };
}

router
  .get('/', defaultRoute)
  .get('/getChain', getChain)
  .get('/getLatestBlock', getLatestBlock)
  .get('/getPendingTransactions', getPendingTransactions)
  .get('/getBalance/:address', getBalance)
  .get('/getTransactions/:address', getTransactions)
  .get('/createWallet', createWallet)
  .get('/minePending', minePending)
  .post('/sendTransaction', sendTransaction);

app.use(router.routes());

console.log('starting server on localhost:3000');
app.listen(3000);
