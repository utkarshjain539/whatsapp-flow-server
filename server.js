const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Load Private Key from Render Env Variables
const privateKey = process.env.PRIVATE_KEY ? process.env.PRIVATE_KEY.replace(/\\n/g, "\n") : null;

// FIX: Handle browser GET requests
app.get("/", (req, res) => {
    res.send("🚀 WhatsApp Flow Server is running and waiting for POST requests!");
});

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

        let responsePayloadObj;

        if (!encrypted_flow_data) {
            responsePayloadObj = { data: { status: "active" } };
        } else {
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action, flow_token } = flowRequest;

            const mobileNumber = flow_token || "8488861504";

            if (action === "INIT" || action === "ping") {
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobileNumber}`;
                console.log(`Fetching: ${apiUrl}`);

                let memberData = { name: "", dob: "", mobile: mobileNumber };
                try {
                    const apiRes = await axios.get(apiUrl);
                    if (apiRes.data) memberData = apiRes.data;
                } catch (e) { console.error("API Fetch Error"); }

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
                responsePayloadObj = { version: "3.0", data: { status: "success" } };
            }
        }

        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("Encryption failure:", err.message);
        return res.status(500).send("Encryption failure");
    }
});

app.listen(process.env.PORT || 3000);
