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
      oaepHash: "sha256", // Try sha256 for newer versions
    }, Buffer.from(encrypted_aes_key, "base64"));

    // 2. THE SECRET SAUCE: Flip the IV
    const requestIv = Buffer.from(initial_vector, "base64");
    const responseIv = Buffer.alloc(requestIv.length);
    for (let i = 0; i < requestIv.length; i++) {
      responseIv[i] = ~requestIv[i]; // Bitwise NOT (Flip bits)
    }

    // 3. Prepare Response (Match your v3.0 Data API)
    const responsePayload = {
      version: "3.0",
      data: { status: "success" }
    };

    // 4. Encrypt with the Flipped IV
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
    const body = JSON.stringify(responsePayload);
    
    let encrypted = cipher.update(body, "utf8", "base64");
    encrypted += cipher.final("base64");
    const responseAuthTag = cipher.getAuthTag();

    // 5. Final Structure
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    // Use send() to avoid any extra JSON formatting
    res.set("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify(finalResponse));

  } catch (err) {
    // Second try with SHA-1 if Decrypt failed
    console.error("Encryption retry...");
    return res.status(500).json({ error: "Check Render logs for key mismatch" });
  }
});

app.listen(process.env.PORT || 3000);
