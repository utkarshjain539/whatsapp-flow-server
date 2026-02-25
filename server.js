const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// FIXED: Advanced Private Key Loader to handle Render formatting issues
const privateKeyInput = process.env.PRIVATE_KEY || "";
const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY") 
    ? privateKeyInput.replace(/\\n/g, "\n") 
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

app.get("/", (req, res) => res.send("🚀 Flow Server is Online!"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        let responsePayloadObj;

        if (!encrypted_flow_data || !authentication_tag) {
            responsePayloadObj = { data: { status: "active" } };
        } else {
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));
            
            let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), "base64", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            
            // Fix: Use the flow_token passed from your curl command
            const mobile = flowRequest.flow_token || "8488861504";
            const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`;

            let member = { name: "Guest", dob: "1990-01-01", mobile: mobile };

            try {
                const apiRes = await axios.get(apiUrl, { timeout: 3000 });
                const apiData = apiRes.data;

                if (apiData && apiData.Status === "success") {
                    member.name = apiData.MemberName;
                    // Date Format Conversion: DD-MM-YYYY -> YYYY-MM-DD
                    if (apiData.dob && apiData.dob.includes("-")) {
                        const parts = apiData.dob.split("-");
                        member.dob = `${parts[2]}-${parts[1]}-${parts[0]}`; 
                    }
                    member.mobile = apiData.MobileNo;
                }
            } catch (e) {
                console.log("API Fetch failed, using safety defaults.");
            }

            // REQUIRED: Every successful response must have 'version' and 'screen'
            responsePayloadObj = {
                version: "3.0",
                screen: "APPOINTMENT",
                data: {
                    prefilled_name: member.name || "",
                    prefilled_dob: member.dob || "",
                    prefilled_mobile: Number(member.mobile) 
                }
            };
        }

        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Handshake failure:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

app.listen(process.env.PORT || 3000);
