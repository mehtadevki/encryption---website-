let encryptedAESKey = "";
let encryptedMessage = "";
let aesKey = "";

// Generate RSA key pair once
const rsaEncryptor = new JSEncrypt();
const rsaDecryptor = new JSEncrypt();
rsaDecryptor.generateKeyPair();
rsaEncryptor.setPublicKey(rsaDecryptor.getPublicKey());

function encrypt() {
  const message = document.getElementById("plainText").value;

  // Generate AES key
  aesKey = CryptoJS.lib.WordArray.random(16).toString();

  // Encrypt message with AES key
  encryptedMessage = CryptoJS.AES.encrypt(message, aesKey).toString();

  // Encrypt AES key with RSA
  encryptedAESKey = rsaEncryptor.encrypt(aesKey);

  document.getElementById("cipherText").value = encryptedMessage;
}

function decrypt() {
  // Decrypt AES key using RSA private key
  rsaDecryptor.setPrivateKey(rsaDecryptor.getPrivateKey());
  const decryptedAESKey = rsaDecryptor.decrypt(encryptedAESKey);

  // Decrypt message using AES key
  const decrypted = CryptoJS.AES.decrypt(encryptedMessage, decryptedAESKey).toString(CryptoJS.enc.Utf8);

  document.getElementById("decryptedText").value = decrypted;
}
