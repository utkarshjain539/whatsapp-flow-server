const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Load Private Key from Render Env Variables
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("WhatsApp Flow Server is Online"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // 1. SAFETY CHECK: Respond to simple pings if key is missing
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 2. Decrypt AES Key with explicit SHA-256
        // This fixes the "oaep decoding error"
        const aesKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        // 3. Prepare IV for response (Bitwise NOT of request IV - 3.0 Spec)
        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        let responsePayload;

        // 4. Determine if Health Check or Data Exchange
        // Check if flow data exists before trying to decrypt it to avoid "undefined" error
        if (!encrypted_flow_data || !authentication_tag) {
            responsePayload = JSON.stringify({
                data: { status: "active" }
            });
        } else {
            // DECRYPT INCOMING DATA
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action } = flowRequest;

            if (action === "INIT") {
                const mobileNumber = "8488861504"; 
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobileNumber}`;
                
                let memberData = { name: "", dob: "", mobile: mobileNumber };
                try {
                    const apiRes = await axios.get(apiUrl);
                    if (apiRes.data) memberData = apiRes.data;
                } catch (apiErr) {
                    console.error("External API Fetch Failed:", apiErr.message);
                }

                responsePayload = JSON.stringify({
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: {
                        prefilled_name: memberData.name || "",
                        prefilled_dob: memberData.dob || "",
                        prefilled_mobile: Number(memberData.mobile || mobileNumber) // Send as Number
                    }
                });
            } else {
                responsePayload = JSON.stringify({
                    version: "3.0",
                    data: { status: "success" }
                });
            }
        }

        // 5. Encrypt Response using AES-GCM
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        // 6. Append Tag to Ciphertext (Data API 3.0 Requirement)
        const authTag = cipher.getAuthTag();
        const finalBuffer = Buffer.concat([encrypted, authTag]);

        // 7. Return Base64 as plain text
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ ERROR:", err.message);
        // Use 500 status to help debug, or 200 with error message
        return res.status(500).send("Encryption failure");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
