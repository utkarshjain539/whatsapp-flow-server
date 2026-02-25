const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Robust Private Key loading to handle Render environment formatting
const privateKeyInput = process.env.PRIVATE_KEY || "";
const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY") 
    ? privateKeyInput.replace(/\\n/g, "\n") 
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

app.get("/", (req, res) => res.send("🚀 WhatsApp Flow Server is Online!"));

app.post("/", async (req, res) => {
    console.log("📢 RECEIVED A REQUEST FROM META!");
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // 1. Respond to simple Meta health pings
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 2. Decrypt AES Key using RSA-OAEP with SHA-256
        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i]; // Bitwise NOT for Data API 3.0 response IV
        }

        let responsePayloadObj;

        // 3. Logic Gate: Health Check vs. Real Interaction
        if (!encrypted_flow_data) {
            responsePayloadObj = { data: { status: "active" } };
        } else {
            // 4. Decrypt Flow Data with fallback for missing authentication_tag
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            
            const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
            let tag = authentication_tag ? Buffer.from(authentication_tag, "base64") : flowDataBuffer.slice(-16);
            let encryptedContent = authentication_tag ? flowDataBuffer : flowDataBuffer.slice(0, -16);

            decipher.setAuthTag(tag);
            
            let decrypted = decipher.update(encryptedContent, "binary", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            console.log("🔓 Decrypted Flow Request:", flowRequest);

            // 5. Fetch live member data from PHP API
            const mobile = flowRequest.flow_token || "8488861504";
            const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`;
            
            let member = { name: "Guest", dob: "1990-01-01", mobile: mobile };
            try {
                const apiRes = await axios.get(apiUrl, { timeout: 3000 });
                const apiData = apiRes.data;
                console.log("API RAW DATA:", apiData);

                if (apiData && apiData.Status === "success") {
                    // Mapping specific keys: MemberName -> name, MobileNo -> mobile
                    member.name = apiData.MemberName;
                    
                    // Converting DD-MM-YYYY to YYYY-MM-DD for WhatsApp compatibility
                    if (apiData.dob && apiData.dob.includes("-")) {
                        const parts = apiData.dob.split("-");
                        member.dob = `${parts[2]}-${parts[1]}-${parts[0]}`; 
                    }
                    member.mobile = apiData.MobileNo;
                }
            } catch (e) {
                console.error("PHP API Fetch Error:", e.message);
            }

            // 6. Final Response Structure (Data API 3.0)
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

        // 7. Encrypt Response
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);

        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Handshake Error:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
