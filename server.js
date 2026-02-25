const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Ensure the private key is loaded correctly from Render
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("Server is Online"));

app.post("/", (req, res) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  try {
    // 1. Decrypt the AES key
    const aesKey = crypto.privateDecrypt({
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    }, Buffer.from(encrypted_aes_key, "base64"));

    // 2. Prepare the Payload (Minified, No Spaces)
    const responsePayload = {
      version: "3.0",
      screen: "APPOINTMENT",
      data: { status: "success" }
    };

    // 3. Encrypt the Response
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    // We stringify the payload with NO spaces
    const bodyString = JSON.stringify(responsePayload);
    let encrypted = cipher.update(bodyString, "utf8", "base64");
    encrypted += cipher.final("base64");

    const responseAuthTag = cipher.getAuthTag();

    // 4. Construct the Final Object
    const finalResponse = {
      encrypted_flow_data: encrypted,
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: responseAuthTag.toString("base64")
    };

    // 5. THE CRITICAL CHANGE: Return the JSON, then Base64 encode the WHOLE THING
    // Meta requires the response to be a single Base64 string of the JSON object.
    const finalJsonString = JSON.stringify(finalResponse);
    const base64ResponseBody = Buffer.from(finalJsonString).toString("base64");

    // 6. Set Content-Type to text/plain so Meta doesn't try to parse it as JSON first
    res.set("Content-Type", "text/plain");
    return res.status(200).send(base64ResponseBody);

  } catch (err) {
    console.error("Encryption failure:", err.message);
    return res.status(500).json({ error: "Encryption failure" });
  }
});

app.listen(process.env.PORT || 3000);
