const crypto = require("crypto");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

console.log("--- COPY THIS TO META DEVELOPER PORTAL (PUBLIC KEY) ---");
console.log(publicKey);
console.log("\n--- COPY THIS TO YOUR SERVER.JS (PRIVATE KEY) ---");
console.log(privateKey);
