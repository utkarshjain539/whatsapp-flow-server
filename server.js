const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 1. Load Private Key
const rawKey = process.env.PRIVATE_KEY;
if (!rawKey) {
  console.error("❌ PRIVATE_KEY missing in environment variables");
  process.exit(1);
}
const privateKey = rawKey.replace(/\\n/g, "\n");

// --- FIXED: GET route so you don't see "Cannot GET /" ---
app.get("/", (req, res) => {
  res.status(200).send("WhatsApp Flow Server is Online and Ready.");
});

// --- WhatsApp Flow POST Endpoint ---
app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  if (!encrypted_aes_key) {
    return res.status(200).send("OK");
  }

  try {
    // 2. Decrypt the AES Key
    let aesKey;
    try {
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1", // Try SHA-1 first (Standard for WhatsApp)
      }, Buffer.from(encrypted_aes_key, "base64"));
    } catch (e) {
      console.log("SHA-1 failed, trying SHA-256...");
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      }, Buffer.from(encrypted_aes_key, "base64"));
    }

    // 3. Prepare the response
    // IMPORTANT: Version must match your Flow settings (3.0 or 2.1)
    let responsePayload = {
      version: "3.0",
      data: { status: "healthy" }
    };

    // If there is flow data, it's a real interaction, not just a ping
    if (encrypted_flow_data) {
      // For now, we send a generic success to verify the connection
      responsePayload = {
        version: "3.0",
        data: { acknowledged: true }
      };
    }

    // 4. Encrypt the Response
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    const bodyString = JSON.stringify(responsePayload);
    let encrypted = cipher.update(bodyString, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 5. Construct the JSON exactly as Meta wants it
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, // MUST be the exact string from Meta
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    // Use send() instead of json() to ensure no extra whitespace is added
    res.set("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify(finalResponse));

  } catch (err) {
    console.error("Encryption failure:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
