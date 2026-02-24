const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 1. Safe Private Key Loading
const rawKey = process.env.PRIVATE_KEY;
if (!rawKey) {
  console.error("❌ PRIVATE_KEY is not set in Render environment variables");
  process.exit(1);
}
// Handles the \n newline issue common in Render/Windows
const privateKey = rawKey.replace(/\\n/g, "\n");

// --- Health Check for Browser ---
app.get("/", (req, res) => {
  res.status(200).send("WhatsApp Flow Server is Running!");
});

// --- WhatsApp Flow Endpoint ---
app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  // Basic guard for non-WhatsApp requests
  if (!encrypted_aes_key) {
    return res.status(200).send("Endpoint Active");
  }

  try {
    let aesKey;

    // 2. Decrypt the AES Key with Dual-Hash Fallback
    // This solves the 'oaep decoding error'
    try {
      aesKey = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha1", // Meta's preferred hash for OAEP
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    } catch (sha1Error) {
      console.log("SHA-1 failed, trying SHA-256...");
      aesKey = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, "base64")
      );
    }

    let responsePayload;

    // 3. Handle Health Check vs Actual Data
    if (!encrypted_flow_data || !initial_vector || !authentication_tag) {
      // If Meta pings the endpoint to verify it
      responsePayload = {
        version: "3.0",
        data: { status: "healthy" }
      };
    } else {
      // 4. Decrypt the actual Flow Data
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

      // --- YOUR BUSINESS LOGIC HERE ---
      responsePayload = {
        version: "3.0",
        screen: flowRequest.screen,
        data: { 
          extension_message_response: { 
            params: { status: "success" } 
          } 
        }
      };
    }

    // 5. Encrypt the Response (Crucial for fixing 'Not Base64 Encoded' error)
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    let encrypted = cipher.update(JSON.stringify(responsePayload), "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 6. Final Mandatory JSON Structure
    return res.status(200).json({
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, // Send back the exact key received
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    });

  } catch (err) {
    console.error("CRITICAL ENCRYPTION ERROR:", err.message);
    return res.status(500).json({ 
      error: "Encryption failure", 
      details: err.message 
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
