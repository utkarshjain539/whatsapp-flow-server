const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Load key and fix common Render formatting issues
const getPrivateKey = () => {
  const rawKey = process.env.PRIVATE_KEY;
  if (!rawKey) return null;
  
  if (rawKey.includes("-----BEGIN")) {
    return rawKey.replace(/\\n/g, "\n");
  }
  // If the key was pasted without headers, this wraps it (rare but happens)
  return `-----BEGIN PRIVATE KEY-----\n${rawKey}\n-----END PRIVATE KEY-----`;
};

const privateKey = getPrivateKey();

app.get("/", (req, res) => res.send("Flow Server is Live"));

app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  if (!encrypted_aes_key) {
    return res.status(200).json({ version: "3.0", data: { status: "healthy" } });
  }

  try {
    let aesKey;
    
    // STRATEGY: Meta uses OAEP. Node defaults to sha256, but Meta often uses sha1.
    // We try sha256 first, then fallback to sha1 if it fails.
    try {
      aesKey = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (e) {
      console.log("SHA256 failed, trying SHA1...");
      aesKey = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha1",
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    }

    // Decrypt flow data
    const decipher = crypto.createDecipheriv(
      "aes-128-gcm",
      aesKey,
      Buffer.from(initial_vector, "base64")
    );

    decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

    let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
    decrypted += decipher.final("utf8");

    const flowRequest = JSON.parse(decrypted);

    // Prepare response
    const responsePayload = JSON.stringify({
      version: "3.0",
      screen: flowRequest.screen || "SUCCESS",
      data: { status: "success" }
    });

    // Encrypt response
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    let encrypted = cipher.update(responsePayload, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    return res.status(200).json({
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    });

  } catch (err) {
    // THIS IS WHAT WE NEED TO SEE IN RENDER LOGS
    console.error("CRITICAL FLOW ERROR:", err.message);
    return res.status(500).json({ 
      error: "Encryption failure", 
      message: err.message,
      stack: err.stack 
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Port ${PORT}`));
