const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    let aesKey;
    // Try SHA-1 (Meta's Default)
    try {
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1",
      }, Buffer.from(encrypted_aes_key, "base64"));
      console.log("✅ Decrypted with SHA-1");
    } catch (e) {
      // Try SHA-256 (Fallback)
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      }, Buffer.from(encrypted_aes_key, "base64"));
      console.log("✅ Decrypted with SHA-256");
    }

    // MANDATORY: Use version 3.0 unless your Flow JSON explicitly says 2.1
    const responsePayload = {
      version: "3.0", 
      data: { status: "healthy" }
    };

    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    
    // Explicit UTF-8 stringification
    const body = JSON.stringify(responsePayload);
    let encrypted = cipher.update(body, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // The Payload Meta expects
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    console.log("📤 Sending Encrypted Response...");
    res.set("Content-Type", "application/json");
    // Send as a single-line string to prevent any parsing errors
    return res.status(200).send(JSON.stringify(finalResponse));

  } catch (err) {
    console.error("❌ CRYPTO ERROR:", err.message);
    return res.status(500).json({ error: "Encryption failure", details: err.message });
  }
});

app.listen(process.env.PORT || 3000);
