const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 🔐 YOUR PRIVATE KEY
const privateKey = `-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----`;

// ✅ Health Check Route (Important for Render)
app.get("/", (req, res) => {
  res.status(200).send("WhatsApp Flow Server Running 🚀");
});

// ✅ WhatsApp Flow Endpoint
app.post("/", (req, res) => {
  try {
    const {
      encrypted_aes_key,
      encrypted_flow_data,
      initial_vector,
      authentication_tag
    } = req.body;

    if (
      !encrypted_aes_key ||
      !encrypted_flow_data ||
      !initial_vector ||
      !authentication_tag
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // 1️⃣ Decrypt AES Key using RSA Private Key
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // 2️⃣ Decrypt Incoming Payload (AES-128-GCM)
    const decipher = crypto.createDecipheriv(
      "aes-128-gcm",
      aesKey,
      Buffer.from(initial_vector, "base64")
    );

    decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

    let decrypted = decipher.update(
      Buffer.from(encrypted_flow_data, "base64")
    );

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    console.log("✅ Decrypted Request:");
    console.log(decrypted.toString());

    // 3️⃣ Prepare Response Payload
    const responsePayload = JSON.stringify({
      version: "3.0",
      data: { status: "healthy" }
    });

    // 4️⃣ Encrypt Response Using NEW IV
    const responseIv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
      "aes-128-gcm",
      aesKey,
      responseIv
    );

    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    // 5️⃣ Return Encrypted JSON
    return res.status(200).json({
      encrypted_flow_data: encrypted.toString("base64"),
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: authTag.toString("base64")
    });

  } catch (error) {
    console.error("❌ Flow Error:", error);
    return res.status(500).json({ error: "Server error" });
  }
});

// ✅ REQUIRED FOR RENDER (VERY IMPORTANT)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
