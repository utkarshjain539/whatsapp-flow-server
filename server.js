const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Load private key and handle potential newline issues from Render env
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

  // 1. Health Check / Incomplete Payload Guard
  // WhatsApp often sends a "ping" or header-only request to verify your endpoint.
  if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector || !authentication_tag) {
    console.log("Health check or incomplete payload received");
    return res.status(200).json({
      version: "3.0",
      data: { status: "healthy" }
    });
  }

  try {
    // 2. Decrypt the AES Key using RSA-OAEP
    // Note: If "sha256" fails, try "sha1" as some older Flow versions required it.
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256", 
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // 3. Decrypt the Flow Data (AES-128-GCM)
    const decipher = crypto.createDecipheriv(
      "aes-128-gcm",
      aesKey,
      Buffer.from(initial_vector, "base64")
    );

    decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

    let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
    decrypted += decipher.final("utf8");

    const flowData = JSON.parse(decrypted);
    console.log("Decrypted Flow Request:", flowData);

    // 4. Prepare your Response Payload
    // This MUST be a stringified JSON object following the Flows schema
    const responsePayload = JSON.stringify({
      version: "3.0",
      screen: flowData.screen, // Echoing the screen or logic for next screen
      data: {
        extension_message_response: { 
            params: { 
                status: "success",
                message: "Data received successfully" 
            } 
        }
      }
    });

    // 5. Encrypt the Response
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    let encrypted = cipher.update(responsePayload, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 6. Send Response
    return res.status(200).json({
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, // Meta expects the same key back
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    });

  } catch (err) {
    console.error("Decryption/Encryption error:", err.message);
    // Returning 500 triggers the "Encryption failure" message in the Meta debugger
    return res.status(500).json({ error: "Encryption failure", details: err.message });
  }
});

app.get("/", (req, res) => {
  res.send("Flow Server is active and running on Render.");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
