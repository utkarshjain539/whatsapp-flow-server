const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const rawKey = process.env.PRIVATE_KEY;
if (!rawKey) {
  console.error("❌ PRIVATE_KEY missing");
  process.exit(1);
}
const privateKey = rawKey.replace(/\\n/g, "\n");

app.get("/", (req, res) => res.send("Server is up!"));

app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 1. Decrypt the AES Key
    // IMPORTANT: Try "sha1" if "sha256" keeps giving the Base64 error
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1", // <--- CHANGED TO SHA1 (Common fix for Meta)
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    let responsePayload;

    // 2. Decide Response (Health Check vs Data)
    if (!encrypted_flow_data) {
      responsePayload = {
        version: "3.0",
        data: { status: "healthy" }
      };
    } else {
      // Decrypt incoming data
      const decipher = crypto.createDecipheriv(
        "aes-128-gcm",
        aesKey,
        Buffer.from(initial_vector, "base64")
      );
      decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
      
      let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
      decrypted += decipher.final("utf8");
      const flowRequest = JSON.parse(decrypted);

      responsePayload = {
        version: "3.0",
        screen: flowRequest.screen,
        data: { success: true }
      };
    }

    // 3. Encrypt the Response
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    // Ensure we stringify the payload correctly
    const body = JSON.stringify(responsePayload);
    let encrypted = cipher.update(body, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 4. Send back the response
    return res.status(200).json({
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, // Must be exact original string
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    });

  } catch (err) {
    console.error("Crypto Error:", err.message);
    // If it fails with sha1, the error will log here
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
