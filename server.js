const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Load Private Key from Render Env Variables
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

// Browser GET request fix
app.get("/", (req, res) => {
    res.send("🚀 WhatsApp Flow Server is Online!");
});

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // 1. Respond to simple Meta Health Checks (sent without keys)
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

        let responsePayloadObj;

        // 2. Determine if we have data to decrypt (Interaction vs. Health Check)
        if (!encrypted_flow_data || !authentication_tag) {
            // This is a background ping from Meta
            responsePayloadObj = { data: { status: "active" } };
        } else {
            // 3. This is a real user opening the Flow or Interactive Mode
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const mobile = flowRequest.flow_token || "8488861504";

            // LOG FOR DEBUGGING - Check your Render logs for this!
            console.log(`🚀 Processing Flow: ${flowRequest.action} for Screen: APPOINTMENT`);

            // Fetch live member data
            let member = { name: "", dob: "", mobile: mobile };
            try {
                const apiRes = await axios.get(`https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`);
                if (apiRes.data) member = apiRes.data;
            } catch (e) { 
                console.error("⚠️ PHP API Error: Using default values"); 
            }

            // 4. THE FIX: Explicitly set the top-level keys required by Meta
            responsePayloadObj = {
                version: "3.0",
                screen: "APPOINTMENT", // <--- THIS PREVENTS THE "MISSING SCREEN" ERROR
                data: {
                    prefilled_name: member.name || "",
                    prefilled_dob: member.dob || "",
                    prefilled_mobile: Number(member.mobile || mobile)
                }
            };
        }

        // 5. Encrypt and Send back as Base64
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Encryption/Logic Error:", err.message);
        // Force a key refresh if there's an encryption mismatch
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));
