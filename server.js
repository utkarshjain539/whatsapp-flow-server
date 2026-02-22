const crypto = require("crypto");
const fs = require("fs");

// Generate RSA 2048 PKCS8 key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

console.log("===== PUBLIC KEY =====");
console.log(publicKey);

console.log("===== PRIVATE KEY =====");
console.log(privateKey);

process.exit();
