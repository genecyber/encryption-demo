var sodium = require('sodium-native')
var alloc = require('buffer-alloc')
var bufferConcat = require('buffer-concat')
var bitcore = require('bitcore')
var recipient = new Buffer('@alice')
var bob = generatePrivateKey()
var bobNonce = generateNonce()
var alice = generatePrivateKey()
var aliceNonce = generateNonce()
var wallet = generatePrivateKey()
var aliceEncryptedWallet, bobEncryptedWallet, aliceDecryptedWallet, bobDecryptedWallet

getEncryptionKey([bob.toPublicKey().toBuffer(), recipient, wallet.toPublicKey().toAddress().toBuffer(), aliceNonce], function(result){
    var encryptedWalletKeyBuffer = encryptPayload(wallet.toBuffer(), aliceNonce, result.key)
    var encryptedWalletKey = encryptedWalletKeyBuffer.toString("hex")
        aliceEncryptedWallet = encryptedWalletKey
    var encryptionKey = result.key.toString("hex")
    var decryptedWalletKeyBuffer = decryptCipher(encryptedWalletKeyBuffer, aliceNonce, result.key)
    var keyHexToSha = ""
    result.hex.forEach(function(part, index){
        handleSecretPart(part, index)
        keyHexToSha += part.toString("hex")
    })
    console.log("****---Alice---*****")
    console.log("Combined secret", keyHexToSha)    
    console.log("Alice Encryption Key sha256(secret)", encryptionKey)
    console.log("Encrypted wallet key", encryptedWalletKey)
    console.log("---------")
    console.log("IN:  Wallet to encrypt   ", wallet.toString("hex"))
    console.log("OUT: Decrypted wallet key", decryptedWalletKeyBuffer.toString("hex"))
    console.log("---------")
})

getEncryptionKey([bob.toPublicKey().toBuffer(), recipient, wallet.toPublicKey().toAddress().toBuffer(), aliceNonce, bobNonce], function(result){
    var encryptedWalletKeyBuffer = encryptPayload(wallet.toBuffer(), aliceNonce, result.key)
    var encryptedWalletKey = encryptedWalletKeyBuffer.toString("hex")
        bobEncryptedWallet = encryptedWalletKey
    var encryptionKey = result.key.toString("hex")
    var decryptedWalletKeyBuffer = decryptCipher(encryptedWalletKeyBuffer, aliceNonce, result.key)
    var keyHexToSha = ""
    result.hex.forEach(function(part, index){
        handleSecretPart(part, index)
        keyHexToSha += part.toString("hex")
    })
    console.log("****---Bob---*****")
    console.log("Combined secret", keyHexToSha)    
    console.log("Bob Encryption Key sha256(secret)", encryptionKey)    
    console.log("Encrypted wallet key", encryptedWalletKey)
    console.log("-----------")
    console.log("IN:  Wallet to encrypt   ", wallet.toString("hex"))
    console.log("OUT: Decrypted wallet key", decryptedWalletKeyBuffer.toString("hex"))
    console.log("---------")
})

var databaseKeyBuffer = bufferConcat([bob.toPublicKey().toBuffer(), recipient, wallet.toPublicKey().toAddress().toBuffer()])    
    databaseKey = sha256(databaseKeyBuffer)
    console.log("FOR BOB   :", "Secret Piece                                              ", bobNonce.toString("hex"))
    console.log("FOR BOB   :", "Sender Encrypted Wallet                                   ", bobEncryptedWallet) 
    console.log("         ")
    console.log("FOR ALICE :", "Secret Piece                                              ", aliceNonce.toString("hex"))
    console.log("FOR ALICE :", "Recipient Encrypted Wallet                                ", aliceEncryptedWallet)
    console.log("         ")
    console.log("FOR SERVER:", "Key sha256(bob.pubkey, recipient[@alice], wallet.address) ", databaseKey.toString("hex") )
    console.log("FOR SERVER:", "Recipient Piece                                           ", aliceNonce.toString("hex") )
    console.log("FOR SERVER:", "Recipient Encrypted Wallet                                ", aliceEncryptedWallet)
    console.log("FOR SERVER:", "Sender Encrypted Wallet                                   ", bobEncryptedWallet) 
    console.log("         ")

function handleSecretPart(part, index){
    var name = "", pieceIn
    switch (index) {
        case 0: name = "Sender pubkey"
        pieceIn = bob.toPublicKey().toString("hex")
        pieceOut = part.toString("hex")
        break;
        case 1: name = "Recipient Social Identifier"
        pieceIn = recipient.toString("ascii")
        pieceOut = part.toString("ascii")
        break;
        case 2: name = "Recipient Wallet Address"
        pieceIn = wallet.toPublicKey().toAddress().toString("hex")
        pieceOut = new bitcore.Address(part).toString("hex")
        break;
        case 3: name = "Secret Nonce (Alice)"
        pieceIn = aliceNonce.toString("hex")
        pieceOut = part.toString("hex")
        break;
        case 4: name = "Secret Nonce (Bob)"
        pieceIn = bobNonce.toString("hex")
        pieceOut = part.toString("hex")
        break;
    }
    console.log("Piece "+index+"", name, ": piece in matches piece out: [", pieceIn === pieceOut, "]")  
}


function decryptCipher(cipher, nonce, key ){
    var output = alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_open_easy(output, cipher, nonce, key)
    return output || new Buffer("ERROR!")
}

function encryptPayload(payload, nonce, key){
    var cipher = new Buffer(payload.length + sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_easy(cipher, payload, nonce, key)
    return cipher
}

function getEncryptionKey(parts, cb){   
    var hexParts = []
    parts.forEach(function(part){
        hexParts[hexParts.length] = part
    })
    
    var joinedStreams = bufferConcat(parts)    
    shaKey = sha256(joinedStreams)
    var returnVal = {key: shaKey, hex: hexParts, buffer: joinedStreams}
    return cb(returnVal)
}

function sha256(source){
    var sha = alloc(sodium.crypto_secretbox_KEYBYTES)
    var instance = sodium.crypto_hash_sha256_instance()
        instance.update(source)
        instance.final(sha)
    return sha
}

function generatePrivateKey(){
    return new bitcore.PrivateKey()
}

function generateNonce(){
    var nonce =  new Buffer(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)
    return nonce
}


