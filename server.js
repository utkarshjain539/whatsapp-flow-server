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

    // 2. Flip IV bits (Mandatory for Data API 3.0)
    const requestIv = Buffer.from(initial_vector, "base64");
    const responseIv = Buffer.alloc(requestIv.length);
    for (let i = 0; i < requestIv.length; i++) {
      responseIv[i] = ~requestIv[i];
    }

    // 3. Prepare Payload
    // 3. Prepare Payload based on the "action"
    let responsePayload;

    if (!encrypted_flow_data) {
        // HEALTH CHECK
        responsePayload = { data: { status: "active" } };
    } else {
        const decryptedBody = JSON.parse(decrypted); // The user's selection
        const { action, data } = decryptedBody;

        if (action === "INIT") {
            // INITIAL LOAD: Send the departments
            responsePayload = {
                version: "3.0",
                screen: "APPOINTMENT",
                data: {
                    department: [
                        { id: "gujarat", title: "Gujarat" },
                        { id: "maharashtra", title: "Maharashtra" }
                    ],
                    location: [], // Empty until department is picked
                    is_location_enabled: false
                }
            };
        } else if (data && data.trigger === "department_selected") {
            // DATA EXCHANGE: User picked a state, now send the cities
            // In a real app, you'd fetch these from your Google Sheet or Database
            responsePayload = {
                version: "3.0",
                screen: "APPOINTMENT",
                data: {
                    location: [
                        { id: "ahmedabad", title: "Ahmedabad" },
                        { id: "surat", title: "Surat" }
                    ],
                    is_location_enabled: true
                }
            };
        }
    }

    // 4. Encrypt using AES-GCM
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // 5. Append Tag to Ciphertext (Data API 3.0 Requirement)
    const authTag = cipher.getAuthTag();
    const finalBuffer = Buffer.concat([encrypted, authTag]);

    // 6. Return Base64 of combined buffer
    res.set("Content-Type", "text/plain");
    return res.status(200).send(finalBuffer.toString("base64"));

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return res.status(500).send("Encryption failure");
  }
});

app.listen(process.env.PORT || 3000);
