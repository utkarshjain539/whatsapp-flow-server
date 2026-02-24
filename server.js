const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

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
        oaepHash: "sha1",
      }, Buffer.from(encrypted_aes_key, "base64"));
    } catch (e) {
      aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      }, Buffer.from(encrypted_aes_key, "base64"));
    }

    // 2. Build Response
    let responsePayload = { version: "3.0", data: { status: "healthy" } };

    if (encrypted_flow_data) {
      // (Optional: Add your decryption logic here if you want to read the request)
      responsePayload = {
        version: "3.0",
        screen: "SUCCESS", // Replace with your actual first screen ID
        data: { success: true }
      };
    }

    // 3. Encrypt Response - THE CRITICAL PART
    const responseIv = crypto.randomBytes(12); // MUST BE 12
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    
    // We must use a Buffer for the payload to ensure no encoding weirdness
    const payloadBuffer = Buffer.from(JSON.stringify(responsePayload), "utf-8");
    let encrypted = cipher.update(payloadBuffer, null, "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 4. Send the response as a RAW object to avoid res.json formatting issues
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    res.set("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify(finalResponse));

  } catch (err) {
    console.error("Error:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
