const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("WhatsApp Flow Server is Online"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        const aesKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        let responsePayload;

        if (!encrypted_flow_data) {
            responsePayload = JSON.stringify({ data: { status: "active" } });
        } else {
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action } = flowRequest;

            if (action === "INIT") {
                const mobileNumber = "8488861504"; // Use dynamic mobile from flow_token if needed
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobileNumber}`;
                
                let memberData = { name: "", dob: "", mobile: mobileNumber };
                try {
                    const apiRes = await axios.get(apiUrl);
                    if (apiRes.data) memberData = apiRes.data;
                } catch (e) { console.error("API Error:", e.message); }

                responsePayload = JSON.stringify({
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: {
                        prefilled_name: memberData.name || "",
                        prefilled_dob: memberData.dob || "",
                        prefilled_mobile: memberData.mobile || mobileNumber
                    }
                });
            } else {
                responsePayload = JSON.stringify({ version: "3.0", data: { status: "success" } });
            }
        }

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

app.listen(process.env.PORT || 3000);
