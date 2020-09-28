const crypto = require('crypto');
var readlineSync = require('readline-sync');

const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});
const keyPair2 = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

const bobPrivateKey = keyPair["privateKey"];
const bobPublicKey = keyPair["publicKey"];
const alicePrivateKey = keyPair["privateKey"];
const alicePublicKey = keyPair["publicKey"];

// const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
//     modulusLength: 2048,
//   });


// This is the data Bob want to send to Alice
const dataTobeSentByBob = readlineSync.question('Bob, enter the message you want to send to Alice: ');


// Bob encrypt the document using a symmetric key
const algorithm = 'aes-192-cbc';
const password = readlineSync.question('Bob, enter the password you want to use to generate the symmetric key: '); // Password used to generate key
const symmetricKey = crypto.scryptSync(password, 'salt', 24); // keylen:24

const iv = crypto.randomBytes(16); // Initialization vector.

const cipher = crypto.createCipheriv(algorithm, symmetricKey, iv);

let encryptedData = cipher.update(dataTobeSentByBob, 'utf8', 'hex');
encryptedData += cipher.final('hex');
// Bob will send encrypted data and iv to Alice.




// Bob encrypts the symmetric key using Alice's public key
const encryptedSymmetricKey = crypto.publicEncrypt(
	{
		key: alicePublicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	// We convert the data string to a buffer using `Buffer.from`
	symmetricKey//Buffer.from(symmetricKey)
)

// Bob signs the doocument using his private key.
const sign = crypto.createSign('SHA256');
sign.write(encryptedSymmetricKey.toString());
sign.end();
const signature = sign.sign(bobPrivateKey, 'hex');





// ************** Transmit step *******************
// Bob sends digital signature, encrypted symmetric key, iv(used to generate decipher), and encrypted document to Alice.
console.log("\nBob will send the following information to Alice, which everyone can see.\n");
console.log("Digital signature: \n" + signature);
console.log("RSA encrypted symmetric key:");
console.log(encryptedSymmetricKey);
console.log("iv: ");
console.log(iv);
console.log("Symmetric encrypted data: \n" + encryptedData);
console.log();





// Alice steps
// Alice verifies the digital signature using Bob's public key to make sure the data actually comes from Bob. 
const verify = crypto.createVerify('SHA256');
verify.write(encryptedSymmetricKey.toString());
verify.end();
const isVerified = verify.verify(bobPublicKey, signature, 'hex');

console.log("Alice verifies the digital signature using Bob's public key to make sure the data actually comes from Bob: " + isVerified);
if (isVerified)
{
    // After verifying, Alice decrypts the encrypted symmetric key using her private key
    const decryptedSymmetricKey = crypto.privateDecrypt(
        {
            key: alicePrivateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        encryptedSymmetricKey
    );
    console.log("Decrypted Symmetric Key: ");
    console.log(decryptedSymmetricKey);

    
    console.log("Alice decrypts the encrypted data using the symmetric key she just decrypted.");
    const decipher = crypto.createDecipheriv(algorithm, decryptedSymmetricKey, iv);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    console.log("Original data sent from Bob: " + decrypted);
} else {
    console.log("fail to verify! Data is not from Bob!");
}