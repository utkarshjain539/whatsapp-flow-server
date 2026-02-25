const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Flow Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 1. Decrypt AES Key
    const aesKey = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    }, Buffer.from(encrypted_aes_key, "base64"));

    // 2. Flip IV (Mandatory for 3.0)
    const requestIv = Buffer.from(initial_vector, "base64");
    const responseIv = Buffer.alloc(requestIv.length);
    for (let i = 0; i < requestIv.length; i++) {
      responseIv[i] = ~requestIv[i];
    }

    // 3. Prepare Payload
    let responsePayload;

    // Check if this is a health check (ping) or actual data exchange
    // Meta's health check usually doesn't include flow_data or has a specific 'ping' action
    if (!encrypted_flow_data) {
        responsePayload = JSON.stringify({
            data: { status: "active" } // THIS IS THE EXPECTED RESULT
        });
    } else {
        // This is a real user interaction
        responsePayload = JSON.stringify({
            version: "3.0",
            screen: "APPOINTMENT",
            data: {
                department: [
                    { id: "gujarat", title: "Gujarat" },
                    { id: "maharashtra", title: "Maharashtra" }
                ],
                location: [
                    { id: "ahmedabad", title: "Ahmedabad" }
                ],
                is_location_enabled: true
            }
        });
    }

    // 4. Encrypt using AES-GCM
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // 5. Append Tag to Ciphertext (3.0 spec)
    const authTag = cipher.getAuthTag();
    const finalBuffer = Buffer.concat([encrypted, authTag]);

    // 6. Return Base64
    res.set("Content-Type", "text/plain");
    return res.status(200).send(finalBuffer.toString("base64"));

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return res.status(500).send("Encryption failure");
  }
});

app.listen(process.env.PORT || 3000);
