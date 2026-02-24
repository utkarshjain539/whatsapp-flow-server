const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 1. Safe Private Key Loading
const rawKey = process.env.PRIVATE_KEY;
if (!rawKey) {
  console.error("❌ PRIVATE_KEY not set in Render environment variables");
  process.exit(1);
}
const privateKey = rawKey.replace(/\\n/g, "\n");

// --- GET ROUTE (For Browser/Render Health Check) ---
app.get("/", (req, res) => {
  res.status(200).send("Server is Online - WhatsApp Flow Endpoint is ready at POST /");
});

// --- POST ROUTE (For WhatsApp Flow) ---
app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  // If request is missing the key, it's not a valid Flow request
  if (!encrypted_aes_key) {
    return res.status(400).send("Missing encrypted_aes_key");
  }

  try {
    // 2. Decrypt the AES Key
    // WhatsApp uses RSA-OAEP. Try sha256; switch to sha1 if you get 500 errors.
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256", 
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    let responsePayload;

    // 3. Handle Health Check vs Actual Data
    if (!encrypted_flow_data || !initial_vector || !authentication_tag) {
      responsePayload = {
        version: "3.0",
        data: { status: "healthy" }
      };
    } else {
      // Decrypt the incoming Flow data
      const decipher = crypto.createDecipheriv(
        "aes-128-gcm",
        aesKey,
        Buffer.from(initial_vector, "base64")
      );

      decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

      let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
      decrypted += decipher.final("utf8");

      const flowRequest = JSON.parse(decrypted);
      console.log("Decrypted Data:", flowRequest);

      // Your Logic Here
      responsePayload = {
        version: "3.0",
        screen: flowRequest.screen,
        data: { success: true }
      };
    }

    // 4. Encrypt the Response
    const responseIv = crypto.randomBytes(12); // Must be 12 bytes
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    let encrypted = cipher.update(JSON.stringify(responsePayload), "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 5. Send Response back to Meta
    return res.status(200).json({
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, // Return the same key received
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    });

  } catch (err) {
    console.error("Crypto Error:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
