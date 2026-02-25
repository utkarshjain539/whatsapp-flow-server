const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// 1. Private Key Handling (Fixes "oaep decoding error")
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

app.get("/", (req, res) => res.send("🚀 WhatsApp Flow Server is Online!"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // Health Check (sent by Meta without encryption keys)
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 2. RSA Decryption with forced SHA-256
        const aesKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i]; // Bitwise NOT for Data API 3.0
        }

        let responsePayloadObj;

        // 3. Handle Flow Data
        if (!encrypted_flow_data || !authentication_tag) {
            // Background ping
            responsePayloadObj = { data: { status: "active" } };
        } else {
            // Decrypt incoming payload
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action, flow_token } = flowRequest;

            // 4. PREFILL LOGIC: Fetch from your PHP API
            const mobile = "8488861504";
            const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`;
            
            let member = { name: "", dob: "", mobile: mobile };
            try {
                const apiRes = await axios.get(apiUrl);
                if (apiRes.data) {
                    member = apiRes.data;
                    console.log("✅ Data fetched from PHP:", member);
                }
            } catch (e) {
                console.error("❌ PHP API Offline, using defaults");
            }

            // 5. THE CRITICAL FIX: Response MUST have 'version' and 'screen' at the top level
            // This satisfies Interactive Mode requirements
            responsePayloadObj = {
    version: "3.0",
    screen: "APPOINTMENT",
    data: {
        // These keys must match the Flow JSON "data" section exactly
        prefilled_name: member.name || "N/A", 
        prefilled_dob: member.dob || "N/A",
        prefilled_mobile: Number(member.mobile)
    }
};
        }

        // 6. Encrypt and Send
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);

        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Encryption/Logic Error:", err.message);
        // Status 421 helps sync keys if they were recently changed
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server listening on ${PORT}`));
