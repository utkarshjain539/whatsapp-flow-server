const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Flow Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  // Basic Health Check (Pre-encryption)
  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 1. Decrypt AES Key
    const aesKey = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    }, Buffer.from(encrypted_aes_key, "base64"));

    // 2. Flip IV bits (Mandatory for 3.0)
    const requestIv = Buffer.from(initial_vector, "base64");
    const responseIv = Buffer.alloc(requestIv.length);
    for (let i = 0; i < requestIv.length; i++) {
      responseIv[i] = ~requestIv[i];
    }

    // 3. Logic to determine if we are Health Checking or Processing Data
    let responsePayload;

    // IF NO FLOW DATA IS SENT -> IT IS A HEALTH CHECK
    if (!encrypted_flow_data) {
        responsePayload = JSON.stringify({
            data: { status: "active" }
        });
    } else {
        // REAL DATA EXCHANGE
        try {
            // Decrypt the incoming flow data to see what the user did
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);

            // Respond with the actual screen data
            responsePayload = JSON.stringify({
                version: "3.0",
                screen: "APPOINTMENT",
                data: {
                    department: [
                        { id: "andhra_pradesh", title: "Andhra Pradesh" },
                        { id: "gujarat", title: "Gujarat" }
                    ],
                    location: [
                        { id: "location_1", title: "Main Center" }
                    ],
                    is_location_enabled: true
                }
            });
        } catch (decryptionError) {
            // If decryption of flow_data fails, fallback to health check
            console.log("Decryption of body failed, falling back to health check response");
            responsePayload = JSON.stringify({ data: { status: "active" } });
        }
    }

    // 4. Encrypt Response
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // 5. Append Tag (3.0 spec)
    const authTag = cipher.getAuthTag();
    const finalBuffer = Buffer.concat([encrypted, authTag]);

    // 6. Return Base64
    res.set("Content-Type", "text/plain");
    return res.status(200).send(finalBuffer.toString("base64"));

  } catch (err) {
    console.error("❌ CRITICAL ERROR:", err.message);
    // Return a 200 even on error to see if Meta gives a better error message
    return res.status(200).send("Handshake Error"); 
  }
});

app.listen(process.env.PORT || 3000);
