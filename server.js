const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const rawKey = process.env.PRIVATE_KEY;
const privateKey = rawKey ? rawKey.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 1. Decrypt AES Key
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

    // 2. Prepare Response
    const responsePayload = {
      version: "3.0",
      data: { status: "success" }
    };

    // 3. ENCRYPTION - STRICT 12-BYTE IV
    const responseIv = crypto.randomBytes(12); // MUST BE 12, NOT 16
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    const body = JSON.stringify(responsePayload);
    let encrypted = cipher.update(body, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 4. Construct Final Response
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    res.set("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify(finalResponse));

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
