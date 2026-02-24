const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const rawKey = process.env.PRIVATE_KEY;
const privateKey = rawKey ? rawKey.replace(/\\n/g, "\n") : null;

app.post("/", (req, res) => {
  const {
    encrypted_aes_key,
    encrypted_flow_data,
    initial_vector,
    authentication_tag
  } = req.body;

  if (!encrypted_aes_key) {
    return res.status(200).send("Endpoint Active");
  }

  try {
    // 1. Decrypt the AES Key
    // Try "sha256" first; if it fails, switch to "sha1"
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256", 
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    let responsePayload;

    // 2. Determine if it's a health check or a data request
    if (!encrypted_flow_data || !initial_vector || !authentication_tag) {
      responsePayload = {
        version: "3.0",
        data: { status: "healthy" }
      };
    } else {
      const decipher = crypto.createDecipheriv(
        "aes-128-gcm",
        aesKey,
        Buffer.from(initial_vector, "base64")
      );

      decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

      let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
      decrypted += decipher.final("utf8");

      const flowRequest = JSON.parse(decrypted);
      
      // Default response structure
      responsePayload = {
        version: "3.0",
        screen: flowRequest.screen,
        data: { acknowledged: true }
      };
    }

    // 3. Encrypt the Response
    // IMPORTANT: IV must be 12 bytes for aes-128-gcm
    const responseIv = crypto.randomBytes(12); 
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    const stringifiedPayload = JSON.stringify(responsePayload);
    
    let encrypted = cipher.update(stringifiedPayload, "utf8", "base64");
    encrypted += cipher.final("base64");

    // Auth Tag is 16 bytes by default in Node.js for GCM
    const responseAuthTag = cipher.getAuthTag();

    // 4. Construct the final response
    // Ensure we return the EXACT encrypted_aes_key string from the request
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key, 
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    return res.status(200).json(finalResponse);

  } catch (err) {
    console.error("Crypto Error:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
