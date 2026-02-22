const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ✅ Safe private key loading
const rawKey = process.env.PRIVATE_KEY;

if (!rawKey) {
  console.error("❌ PRIVATE_KEY not set in environment variables");
  process.exit(1);
}

const privateKey = rawKey.replace(/\\n/g, "\n");

app.post("/", (req, res) => {
  try {
    const {
      encrypted_aes_key,
      encrypted_flow_data,
      initial_vector,
      authentication_tag
    } = req.body;

    if (!encrypted_aes_key) {
      return res.status(200).end();
    }

    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

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

    console.log("Decrypted:", decrypted.toString());

    const responsePayload = JSON.stringify({
      version: "3.0",
      data: { status: "healthy" }
    });

    const responseIv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
      "aes-128-gcm",
      aesKey,
      responseIv
    );

    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    return res.status(200).json({
      encrypted_flow_data: encrypted.toString("base64"),
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: authTag.toString("base64")
    });

  } catch (err) {
    console.error("Flow error:", err);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.get("/", (req, res) => {
  res.send("Server running");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
