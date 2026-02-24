const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 1. IMPROVED KEY LOADING (Fixes line break issues in Render)
const getPrivateKey = () => {
  let key = process.env.PRIVATE_KEY;
  if (!key) return null;
  // If Render stripped newlines, this restores them properly
  if (!key.includes("\n") && key.includes("-----BEGIN")) {
    key = key.replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n")
             .replace("-----END PRIVATE KEY-----", "\n-----END PRIVATE KEY-----")
             .replace(/\s(?=[^]*-----END)/g, "\n");
  }
  return key.replace(/\\n/g, "\n");
};

const privateKey = getPrivateKey();

app.get("/", (req, res) => res.send("Flow Server Active"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 2. DECRYPTION WITH EXPLICIT OAEP PARAMETERS
    let aesKey;
    try {
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256", // v7.3/3.0 usually uses SHA-256
        mgf1Hash: "sha256"  // Explicitly set MGF1 to match SHA-256
      }, Buffer.from(encrypted_aes_key, "base64"));
    } catch (e) {
      // Fallback to SHA-1 if SHA-256 fails
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1",
        mgf1Hash: "sha1"
      }, Buffer.from(encrypted_aes_key, "base64"));
    }

    // 3. RESPONSE STRUCTURE (v7.3/3.0 REQUIRES data_api_version: "3.0")
    const responsePayload = {
      version: "3.0", // This refers to the data_api_version
      data: { status: "success" }
    };

    // 4. ENCRYPTION
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    
    const body = JSON.stringify(responsePayload);
    let encrypted = cipher.update(body, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 5. STRICT JSON OUTPUT
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, // Exact same string back
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    res.set("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify(finalResponse));

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    // If the error is still 'oaep decoding error', your PRIVATE_KEY on Render 
    // definitely does not match the PUBLIC_KEY on Meta.
    return res.status(500).json({ error: "Encryption failure", details: err.message });
  }
});

app.listen(process.env.PORT || 3000);
