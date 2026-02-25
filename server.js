const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Enhanced Private Key loading
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("🚀 Server is Online!"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // Handle Health Check
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 1. Decrypt AES Key
        const aesKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        // 2. Setup IVs
        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        let responsePayloadObj;

        // 3. Handle data if present
        if (!encrypted_flow_data || !authentication_tag) {
            responsePayloadObj = { data: { status: "active" } };
        } else {
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const mobile = flowRequest.flow_token || "8488861504";

            // 4. Fetch data from PHP
            let member = { name: "", dob: "", mobile: mobile };
            try {
                // We add a timeout so the Flow doesn't hang and error out
                const apiRes = await axios.get(`https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`, { timeout: 3000 });
                if (apiRes.data) member = apiRes.data;
            } catch (e) {
                console.log("PHP API failed, using fallback data to prevent Flow crash.");
            }

            // 5. Build Response - MUST match Flow JSON IDs
            responsePayloadObj = {
                version: "3.0",
                screen: "APPOINTMENT", 
                data: {
                    prefilled_name: member.name || "Enter Name",
                    prefilled_dob: member.dob || "YYYY-MM-DD",
                    prefilled_mobile: Number(member.mobile || mobile)
                }
            };
        }

        // 6. Encrypt Response
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        // This log is vital! Check Render for this text if it still fails.
        console.error("❌ CRITICAL ERROR:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

app.listen(process.env.PORT || 3000);
