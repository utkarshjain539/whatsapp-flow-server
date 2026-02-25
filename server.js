const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Load Private Key from Render Env Variables
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

// Browser GET request fix
app.get("/", (req, res) => {
    res.send("🚀 WhatsApp Flow Server is Online and waiting for POST requests!");
});

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // 1. Respond to simple Meta pings (Health Check without data)
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 2. Decrypt AES Key - Explicitly using SHA-256 for WhatsApp compliance
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

        // 4. Logic Gate: Health Check vs. Real Interaction
        if (!encrypted_flow_data || !authentication_tag) {
    // This is for background health pings ONLY
    responsePayloadObj = {
        data: { status: "active" }
    };
} else {
    // This handles the real user opening the flow (INIT)
    const flowRequest = JSON.parse(decrypted);
    const { action, flow_token } = flowRequest;

    // FETCH DATA LOGIC
    const mobile = flow_token || "8488861504";
    const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`;
    
    let member = { name: "", dob: "", mobile: mobile };
    try {
        const apiRes = await axios.get(apiUrl);
        if (apiRes.data) member = apiRes.data;
    } catch (e) { console.error("API Error"); }

    // THE CRITICAL PART: You MUST include "screen" here
    responsePayloadObj = {
        version: "3.0",
        screen: "APPOINTMENT", // This must match your Screen ID in the Flow JSON
        data: {
            prefilled_name: member.name || "",
            prefilled_dob: member.dob || "",
            prefilled_mobile: Number(member.mobile || mobile)
        }
    };
}

        // 6. Encrypt Response (Data API 3.0 Spec)
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);

        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Encryption Error:", err.message);
        // Status 421 tells Meta to download your new public key if there is a mismatch
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));
