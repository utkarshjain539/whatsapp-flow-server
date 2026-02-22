const express = require("express");
const crypto = require("crypto");

const app = express();

// Meta sends JSON, but we must respond with text/plain (the Base64 string)
app.use(express.json({ limit: "5mb" }));

// 🔐 Your Private Key
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCktvBiUl5h6U4m
5OJi+sg1/INPYgvFA7jYCYHY1m8qL6wLFQmJXt+ErePoXelHIYfOMlGhpV6N3KQf
Ya+UrDsCIghtO++F0RTy845Zly9q4zZioeKGis1RUAAhO6eMTUvue6lCdxDIalVS
0sZNYDzScFVgAWLAahZJB7IpT6nCf37Slh5XKPy1KB4EDkUBP96CuuqTAroLPOWH
x8qEODh1nvtgvo0+VbAxwzBpRlVwt5GN/YZlDh+uoDKn/a4mZXWYvKOlmWJYV76h
zYQ/ha+nS716S4V3LbrkaZLVb2njzgL3U0gNf8ENjCq3Ug7GPvyraEkDSnQUlSd5
H2JdymGpAgMBAAECggEACWUpQKUhHrrvixa6y67b9P8HwGM/zPI252piE9ZmCy/N
Q5Pkx4dNVDnqSjVHxUJmMX6Q8G7zKJVWw+F5tzm8Yz/stMpakbVI2XNyAa3hda/V
yM93ZnmMAjYqzmUi2++xbpNy0UiNq64rsBM3XhoorfoxVyNibhuUVNW8YFCGcYJm
V7LRtrx4r47kHWEJdVQ5k/2WgXngT10iz9Wou6IBsbY+wKhOZWFn4uheF9/oBCog
vcFPdaRN3DZphHuO17Ti52eehpPphoMwZFwOnpsYIdPRoNZg/9GG7etAHGgW1xZ+
lsn2K4nI5DgdqrX6zDi1KVGgXulyBtugVCj0Tk153wKBgQDhoCCZ3edl14Kaxhx1
cr05Y40zsrt8+hwj8q6VMrrSeVPxSpSBn0eYm2yQr0tw6TDh451UTKSDCPbpfDki
cCbuLsmLYCeFw2g5rQIUlk9bBT3fcEVlhi9G93qb1sMkr7o+RWw4uSIK8xD/gFrP
Jq9tUA/CDSxjZasY4rZUaJPxIwKBgQC645n6qOJ7x2JmLOS1G9LJoZTK5yVjckwa
65JFD48LZu+1ahAh5lBDMHbbPodKMtlFfbLZ4aR77xz7rbJ9W6j9QLXAG+oKtcf/
+3DkWC62dGEoJk6LiYDWpaox1WX6i4qBXk3yVqnP2koY6E2mflLNC+uakVLKKNNx
5An9yiy8wwKBgQCI2DsNt8YyQbzoLMJ0Bax5E0VAFuaaTYQl1XpH6aXgJFBiZ86c
s8OT7qixNHC4QecxCoGQ8I9THmvLf1mT5pvmGKCLFT3DZppfaOx7GhN1bD9ztr+Q
bQtdqppFzMM9DAwU2rxhxv+7zmL/5JSvUZJS5Z05IA5NFwvoIxFdLrSUKwKBgCoz
oR6wKkyHLpoiAxc+jC/J0/6piZDWS4c8sM/1fni1quWNaM0u4+r4M664hPZlWxjN
FKkMwgbWbPYMOCUEoLlndmNGKmh2ug386nY1z36V8yaM1+m8iCJwUGlmZdvYzNL/
x5w0o63y/g53zqkNF4eD7JT/wfEynOS3+OWdVNLfAoGBAM91FZmyUvdyKTRePKwr
xx/t9GGYzLqUBazMoBDUdo+65AjQmkyxCnVbk8/j4sB9h5RX4VJUBKGJIsGG7sb5
q9pMUDrZaKcQAYgXWTz+QcawgrrPS7nrGUxaBQ3yvyiuiP5IMDW6bkXOyiocN3t9
7qyEr3mqqgwWz/UAZvUdGuR+
-----END PRIVATE KEY-----`;

app.post("/", (req, res) => {
  try {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector, authentication_tag } = req.body;

    /*
    |--------------------------------------------------------------------------
    | 1️⃣ Decrypt the AES Key sent by Meta
    |--------------------------------------------------------------------------
    */
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    /*
    |--------------------------------------------------------------------------
    | 2️⃣ Handle Health Check vs. Real Request
    |--------------------------------------------------------------------------
    */
    let responseData;

    if (!authentication_tag) {
      // It's a Health Check
      responseData = {
        version: "3.0",
        data: { status: "healthy" }
      };
    } else {
      // It's a real user interaction - Decrypt the request
      const requestIv = Buffer.from(initial_vector, "base64");
      const requestCiphertext = Buffer.from(encrypted_flow_data, "base64");
      const requestTag = Buffer.from(authentication_tag, "base64");

      const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
      decipher.setAuthTag(requestTag);

      let decryptedBody = decipher.update(requestCiphertext, "base64", "utf8");
      decryptedBody += decipher.final("utf8");
      
      const decryptedJson = JSON.parse(decryptedBody);
      console.log("Decrypted Request:", decryptedJson);

      // Prepare your real logic response here
      responseData = {
        version: "3.0",
        screen: decryptedJson.screen,
        data: {
          // Your logic goes here
          message: "Data received successfully"
        }
      };
    }

    /*
    |--------------------------------------------------------------------------
    | 3️⃣ Encrypt the Response (AES-128-GCM)
    |--------------------------------------------------------------------------
    */
    const responsePayload = JSON.stringify(responseData);
    const responseIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

    let encryptedResponse = cipher.update(responsePayload, "utf8");
    encryptedResponse = Buffer.concat([encryptedResponse, cipher.final()]);
    
    const responseTag = cipher.getAuthTag();

    /*
    |--------------------------------------------------------------------------
    | 4️⃣ Return as Base64 String (Required by Meta)
    |--------------------------------------------------------------------------
    | Meta expects: Base64(encrypted_data + auth_tag)
    */
    const finalB64Response = Buffer.concat([encryptedResponse, responseTag]).toString("base64");

    res.set("Content-Type", "text/plain");
    return res.status(200).send(finalB64Response);

  } catch (error) {
    console.error("Encryption/Decryption Error:", error.message);
    return res.status(500).send("Internal Server Error");
  }
});

// Simple GET for browser testing
app.get("/", (req, res) => {
  res.send("Server is running!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Meta Flow Endpoint running on port ${PORT}`);
});
