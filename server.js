const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("🚀 WhatsApp Flow Server is Online!"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // 1. Respond to simple Meta pings (Health Check)
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 2. Decrypt AES Key - Explicitly forcing SHA-256 to fix "oaep decoding error"
        const aesKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        // 3. Prepare IV for response (Bitwise NOT of request IV)
        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        let responsePayloadObj;

        // 4. Guard against "undefined" - If no flow data, it is a Health Check
        if (!encrypted_flow_data || !authentication_tag) {
            responsePayloadObj = { data: { status: "active" } };
        } else {
            // Decrypt incoming Flow Data
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action, flow_token } = flowRequest;

            // Fetch live member data
            if (action === "INIT" || action === "ping") {
                const mobile = flow_token || "8488861504";
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`;
                
                let member = { name: "", dob: "", mobile: mobile };
                try {
                    const apiRes = await axios.get(apiUrl);
                    if (apiRes.data) member = apiRes.data;
                } catch (e) { console.error("PHP API Offline"); }

                responsePayloadObj = {
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: {
                        prefilled_name: member.name || "",
                        prefilled_dob: member.dob || "",
                        prefilled_mobile: Number(member.mobile || mobile)
                    }
                };
            } else {
                responsePayloadObj = { version: "3.0", data: { status: "success" } };
            }
        }

        // 5. Encrypt and send (3.0 Spec)
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);

        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Encryption Error:", err.message);
        // If decryption still fails, tell Meta to refresh the key
        return res.status(421).send("Key Refresh Required"); 
    }
});

app.listen(process.env.PORT || 3000);
