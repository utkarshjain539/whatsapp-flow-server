const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "5mb" }));

// 🔐 Paste your PRIVATE KEY here
const privateKey = `-----BEGIN PRIVATE KEY-----
PASTE_YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----`;

app.post("/", (req, res) => {
  try {
    const body = req.body;

    // Health check
    if (!body.encrypted_aes_key) {
      return res.json({ status: "healthy" });
    }

    // 1️⃣ Decrypt AES key using RSA-OAEP SHA256
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(body.encrypted_aes_key, "base64")
    );

    // 2️⃣ Prepare Flow response
    const responsePayload = JSON.stringify({
      data: {}
    });

    // 3️⃣ Encrypt response using AES-256-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);

    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    return res.json({
      encrypted_flow_data: encrypted.toString("base64"),
      initial_vector: iv.toString("base64"),
      authentication_tag: authTag.toString("base64")
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/", (req, res) => {
  res.json({ status: "healthy" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
