const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Load key from Render
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Flow Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  // Health check ping from Meta
  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 1. Decrypt AES Key using SHA-256 (Required for latest Graph versions)
    const aesKey = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    }, Buffer.from(encrypted_aes_key, "base64"));

    // 2. Prepare Payload targeting your specific screen "APPOINTMENT"
    const responsePayload = JSON.stringify({
      version: "3.0",
      screen: "APPOINTMENT", // <--- MATCHES YOUR SCREEN ID
      data: {
        status: "success"
      }
    });

    // 3. Encrypt the response
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    
    let encrypted = cipher.update(responsePayload, "utf8", "base64");
    encrypted += cipher.final("base64");
    const responseAuthTag = cipher.getAuthTag().toString("base64");

    // 4. Construct the standard response object
    const finalResponseObj = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag
    };

    // 5. THE "BASE64" FIX: Encode the entire JSON string as Base64
    const finalString = JSON.stringify(finalResponseObj);
    const base64Body = Buffer.from(finalString).toString("base64");

    // 6. Return as plain text per Meta requirements for full-body Base64
    res.set("Content-Type", "text/plain");
    return res.status(200).send(base64Body);

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    // If decryption fails, it's likely a SHA-256 vs SHA-1 issue or key mismatch
    return res.status(500).json({ error: "Encryption failure" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));
