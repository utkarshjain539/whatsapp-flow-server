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
        // 1. Decrypt the AES key (SHA-256 for Data API 3.0)
        const aesKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        }, Buffer.from(encrypted_aes_key, "base64"));

        // 2. Prepare IV for response (Bitwise NOT of request IV - 3.0 Spec)
        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        let responsePayload;

        // 3. Determine if Health Check or Data Exchange
        if (!encrypted_flow_data) {
            // HEALTH CHECK RESPONSE
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
                // FETCH DATA FROM YOUR PHP API
                // For production, you can get the mobile from flow_token or flowRequest
                const mobileNumber = "8488861504"; 
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobileNumber}`;
                
                let memberData = { name: "", dob: "", mobile: mobileNumber };
                try {
                    const apiRes = await axios.get(apiUrl);
                    // Assuming API returns { name, dob, mobile }
                    if (apiRes.data) {
                        memberData = apiRes.data;
                    }
                } catch (apiErr) {
                    console.error("External API Fetch Failed:", apiErr.message);
                }

                // RESPONSE WITH PREFILLED DATA
                responsePayload = JSON.stringify({
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: {
                        prefilled_name: memberData.name || "",
                        prefilled_dob: memberData.dob || "",
                        prefilled_mobile: memberData.mobile || mobileNumber,
                        department: [
                            { id: "gujarat", title: "Gujarat" },
                            { id: "maharashtra", title: "Maharashtra" }
                        ],
                        location: [],
                        is_location_enabled: false
                    }
                });
            } else {
                // Standard Success Response for other actions
                responsePayload = JSON.stringify({
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: { status: "success" }
                });
            }
        }

        // 4. Encrypt using AES-GCM
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        // 5. Append Tag to Ciphertext (3.0 spec requirement)
        const authTag = cipher.getAuthTag();
        const finalBuffer = Buffer.concat([encrypted, authTag]);

        // 6. Return Base64 of combined buffer as plain text
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ CRITICAL ERROR:", err.message);
        return res.status(500).send("Encryption failure");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
