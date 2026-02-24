const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Load and format Private Key for Render environment
const rawKey = process.env.PRIVATE_KEY;
if (!rawKey) {
  console.error("❌ PRIVATE_KEY not set in environment variables");
  process.exit(1);
}
const privateKey = rawKey.replace(/\\n/g, "\n");

app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  // Basic guard for non-WhatsApp pings
  if (!encrypted_aes_key) {
    return res.status(200).send("Endpoint Active");
  }

  try {
    // 1. Decrypt the AES Key provided by Meta
    // If "sha256" fails, switch this to "sha1"
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256", 
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    let responsePayload;

    // 2. Check if this is a health check or a real request
    if (!encrypted_flow_data || !initial_vector || !authentication_tag) {
      // HEALTH CHECK RESPONSE
      responsePayload = {
        version: "3.0",
        data: { status: "healthy" }
      };
    } else {
      // ACTUAL DATA DECRYPTION
      const decipher = crypto.createDecipheriv(
        "aes-128-gcm",
        aesKey,
        Buffer.from(initial_vector, "base64")
      );

      decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

      let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
      decrypted += decipher.final("utf8");

      const flowRequest = JSON.parse(decrypted);
      console.log("Decrypted Flow Request:", flowRequest);

      // 3. Define your Flow logic here
      responsePayload = {
        version: "3.0",
        screen: flowRequest.screen,
        data: {
          extension_message_response: {
            params: {
              status: "success",
              message: "Data processed successfully"
            }
          }
        }
      };
    }

    // 4. Encrypt the Response (Crucial: This fixes the Base64 error)
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    let encrypted = cipher.update(JSON.stringify(responsePayload), "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 5. Return the mandatory 4-field encrypted object
    return res.status(200).json({
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    });

  } catch (err) {
    console.error("Encryption/Decryption Error:", err.message);
    // Returning 500 tells Meta's debugger there was a logic/key failure
    return res.status(500).json({ error: "Encryption failure", details: err.message });
  }
});

app.get("/", (req, res) => {
  res.send("Flow Server is running.");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
