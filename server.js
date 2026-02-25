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

    // 2. Prepare Payload
    const responsePayload = {
      version: "3.0",
      data: { status: "success" }
    };

    // 3. Encrypt
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    
    let encrypted = cipher.update(JSON.stringify(responsePayload), "utf8", "base64");
    encrypted += cipher.final("base64");
    const responseAuthTag = cipher.getAuthTag();

    // 4. Construct the JSON Object
    const finalJsonResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    // 5. THE CRITICAL STEP: Base64 encode the WHOLE JSON string
    const jsonString = JSON.stringify(finalJsonResponse);
    const base64Response = Buffer.from(jsonString).toString("base64");

    // 6. Return ONLY the Base64 string
    res.set("Content-Type", "text/plain"); // Meta expects plain text when it's full Base64
    return res.status(200).send(base64Response);

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
