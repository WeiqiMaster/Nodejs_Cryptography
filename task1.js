const crypto = require('crypto');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

const { bobPrivateKey, BobPublicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    // console.log(publicKey);
    // console.log(publicKey2);

// This is the data we want to encrypt
const document = "my secret data"


// Bob encrypt the document using symmetric key
const algorithm = 'aes-192-cbc';
const password = 'Password used to generate key';
const symmetricKey = crypto.scryptSync(password, 'salt', 24);
//console.log(symmetricKey);

const iv = crypto.randomBytes(16); // Initialization vector.
//console.log(iv == null);

const cipher = crypto.createCipheriv(algorithm, symmetricKey, iv);


let encrypted = cipher.update(document, 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log(encrypted);

// will send encrypted data and iv to Alice.




// Encrypt the symmetric key using Alice's public key
const encryptedData = crypto.publicEncrypt(
	{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	// We convert the data string to a buffer using `Buffer.from`
	symmetricKey//Buffer.from(symmetricKey)
)

// sign the doocument using the private key.
const sign = crypto.createSign('SHA256');
sign.write(encryptedData.toString());
sign.end();
const signature = sign.sign(privateKey, 'hex');





// *********** Transmit
// Bob sends digital signature, encrypted symmetric key, iv(used to generate decipher), and encrypted document to Alice.
console.log("signature: " + signature);
console.log("encrypted symmetric key: " + encryptedData.toString());
console.log("iv: " + iv);
console.log("symmetric encrypted document: " + encrypted);





// Alice steps
const verify = crypto.createVerify('SHA256');
verify.write(encryptedData.toString());
verify.end();
const isVerified = verify.verify(publicKey, signature, 'hex');
console.log(isVerified);

if (isVerified)
{
    // After verifying, decrypt the data using Alice's private key
    const decryptedSymmetricKey = crypto.privateDecrypt(
        {
            key: privateKey,
            // In order to decrypt the data, we need to specify the
            // same hashing function and padding scheme that we used to
            // encrypt the data in the previous step
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        encryptedData
    );

    // The decrypted data is of the Buffer type, which we can convert to a
    // string to reveal the original data
    //console.log("decrypted data: ", decryptedData.toString())


    console.log(decryptedSymmetricKey);
    const decipher = crypto.createDecipheriv(algorithm, decryptedSymmetricKey, iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    console.log(decrypted);
} else {
    Console.log("fail to verify!");
}