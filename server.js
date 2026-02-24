const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 1. Safe Key Loading
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 2. Decrypt the AES Key (Try SHA-256 for v7.3/3.0)
    let aesKey;
    try {
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      }, Buffer.from(encrypted_aes_key, "base64"));
    } catch (e) {
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1",
      }, Buffer.from(encrypted_aes_key, "base64"));
    }

    // 3. Prepare response for v3.0 Data API
    const responsePayload = {
      version: "3.0",
      data: { status: "success" }
    };

    // 4. Strict Encryption
    const responseIv = crypto.randomBytes(12); // Must be 12
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    const body = JSON.stringify(responsePayload);
    // Explicitly set encoding to prevent Node.js from adding extra bytes
    let encrypted = cipher.update(body, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 5. THE FIX: Explicitly convert Buffers to Base64 strings immediately
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    // 6. Force clean JSON output with no extra spaces
    const jsonString = JSON.stringify(finalResponse);
    
    res.set({
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(jsonString)
    });
    
    return res.status(200).send(jsonString);

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
