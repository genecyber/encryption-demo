var _Mnemonic = require("./mnemonic.js")
var bitcore = require("bitcore")
var bitcoin = require("bitcoinjs-lib")
var ethUtil = require('ethereumjs-util')
var msg = "RcjbSHVpqDiK6uNLtLd6EGPjE1WxTmq1bs01469934350-test"
var m = new _Mnemonic.fromWords("been cry mist pure damn abuse throw selfish perfectly forgive self forward".split(" "))
var pk = bitcore.HDPrivateKey.fromSeed(m.toHex(), bitcore.Networks.mainnet)
var d = pk.derive("m/0'/0/0")
var value = d.privateKey.toBuffer()
var hash = bitcore.crypto.Hash.sha256(value)
var privateKey = bitcore.PrivateKey.fromBuffer(hash, bitcore.Networks.mainnet)
var wif = privateKey.toWIF(bitcore.Networks.mainnet) 
var keyPair = bitcoin.ECPair.fromWIF(wif,bitcoin.networks.bitcoin)
var sig = sign(keyPair, msg)
var signerAddress = pretty(address(keyPair))
console.log("xcp address", d.privateKey.toAddress().toString())
console.log("btc address", privateKey.toAddress().toString())
console.log("loyyal address", pretty(address(keyPair)))
console.log("public", pretty(privateKey.toBuffer()))
console.log("v", pretty(sig.v))
console.log("r", pretty(sig.r))
console.log("s", pretty(sig.s))
console.log("btc sigcheck", verifyUncompressed(privateKey.toAddress().toString(), sig, msg))

function verifyUncompressed(address, sig, msg) {
	return bitcoin.message.verify(address, contractSig2BitcoinSig(sig.v, sig.s, sig.r), msg)
}

function contractSig2BitcoinSig(v, s, r) {
	var bar = []
	var joined = v + "," + r.join() + "," + s.join()
	joined.split(",").forEach(
		function(item){bar.push(Number(item))
	})
	return new Buffer(bar)
}

//var bitcoin = require('bitcoinjs-lib')
//var ethUtil = require('ethereumjs-util')

function pretty(buf) {
  if (!Buffer.isBuffer(buf)) {
    return buf
  }
  var ret = buf.toString('hex')
  if (ret.length % 2)
    return '0x0' + ret
  else
    return '0x' + ret
}

function generatePayload(msg, key){
  if (bitcoin.bitcoin) {
    bitcoin = bitcoin.bitcoin
  }
  var value = new Buffer(key)
  var hash = bitcore.crypto.Hash.sha256(value)
  var privateKey = bitcore.PrivateKey.fromBuffer(hash)
  var hdPrivateKey = bitcore.HDPrivateKey.fromBuffer(value)
  var wif = privateKey.toWIF()
      value = new Buffer(msg)
      hash = bitcore.crypto.Hash.sha256(value)
  var keyPair = bitcoin.ECPair.fromWIF(wif,bitcoin.networks.coval)
  var sig = sign(keyPair, msg)
  var signerAddress = pretty(address(keyPair))
  return {
    coval: bitcoreSign(msg, hdPrivateKey.privateKey),
    contract: {
      signerAddress: signerAddress,
      signatureVersion: sig.v,
      signatureR: pretty(sig.r),
      signatureS: pretty(sig.s)
    }
  }      
}

function bitcoreSign(msg, key) {
  var _msg = bitcore.Message
  var m = _msg(msg)
  var s = m.sign(key)
  var covalAddress = key.toAddress().toString()
  return {
    toSign: msg,
    covalAddress: covalAddress,
    signature: s
  }
}

function address(keyPair) {
  return ethUtil.publicToAddress(keyPair.getPublicKeyBuffer(), true)
}

function parseSignature(signature) {
  return {
    // Since we decompress the key for the address,
    // we only need to know the sign of the signature
    v: ((signature[0] - 27) & 1) + 27,
    r: signature.slice(1, 33),
    s: signature.slice(33)
  }
}
function sign(keyPair, message) {
  var signature = bitcoin.message.sign(keyPair, message)
  return parseSignature(signature)
}
