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

    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 1. Decrypt AES Key with SHA-256
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

        let responsePayloadObj;

        // 3. Handle different request types
        if (!encrypted_flow_data || !authentication_tag) {
            // Background Health Check Ping
            responsePayloadObj = {
                data: { status: "active" }
            };
        } else {
            // Decrypt incoming Flow Data
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action } = flowRequest;

            // 4. Critical Logic: Distinguish between INIT and Health Check
            if (action === "ping") {
                responsePayloadObj = {
                    version: "3.0",
                    data: { status: "active" }
                };
            } else if (action === "INIT") {
                // Fetch member details from your API
                const mobileNumber = "8488861504"; 
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobileNumber}`;
                
                let memberData = { name: "", dob: "", mobile: mobileNumber };
                try {
                    const apiRes = await axios.get(apiUrl);
                    if (apiRes.data) memberData = apiRes.data;
                } catch (e) { console.error("API Error:", e.message); }

                // MUST include 'screen' and 'version' for INIT
                responsePayloadObj = {
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: {
                        prefilled_name: memberData.name || "",
                        prefilled_dob: memberData.dob || "",
                        prefilled_mobile: Number(memberData.mobile || mobileNumber)
                    }
                };
            } else {
                // Default success response
                responsePayloadObj = {
                    version: "3.0",
                    data: { status: "success" }
                };
            }
        }

        // 5. Encrypt and send response (Data API 3.0 Spec)
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const authTag = cipher.getAuthTag();
        const finalBuffer = Buffer.concat([encrypted, authTag]);

        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ ERROR:", err.message);
        return res.status(500).send("Encryption failure");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));
