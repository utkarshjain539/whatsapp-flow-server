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

    // 2. Prepare IV for response (Bitwise NOT of request IV)
    const requestIv = Buffer.from(initial_vector, "base64");
    const responseIv = Buffer.alloc(requestIv.length);
    for (let i = 0; i < requestIv.length; i++) {
      responseIv[i] = ~requestIv[i];
    }

    // 3. Prepare Response Payload for your specific JSON structure
    const responsePayload = JSON.stringify({
      version: "3.0",
      screen: "APPOINTMENT",
      data: {
        // We include the initial data your Flow JSON expects
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

    // 4. Encrypt using AES-GCM
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // 5. THE 3.0 SPEC: Append Tag to Ciphertext
    const authTag = cipher.getAuthTag();
    const finalBuffer = Buffer.concat([encrypted, authTag]);

    // 6. Return ONLY the Base64 string of the combined buffer
    res.set("Content-Type", "text/plain");
    return res.status(200).send(finalBuffer.toString("base64"));

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return res.status(500).send("Encryption failure");
  }
});

app.listen(process.env.PORT || 3000);
