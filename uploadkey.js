const axios = require('axios');

const ACCESS_TOKEN = 'EAALZAyj90w9YBQxz0uKzAmZAD1C8mf11kLO0fgGHZCjnSyZB39PTSsPnxTMTZBdkxirZCBf0WHYeeUrM07ZBzZAZAEu4pqJXOUt0OCCZAZBTOTVqM0vZCH8kQL9fpCaEZAJKxFmObeMyZBZBlnilmmL82LFvQyvuuQZCmm81gEJW9eSPUX9R3BnNMAfo6ROFFLMQOQ222cUz7OLvBFiWAPChSZAGmJ5mdeOboRrjuefhehXF3igdmBTXerbe8t7w0W3Fi8ImlLVdOHhenC8PfJvsUS6e9U3PeXc7Q';
const WABA_ID = '185660454629908';
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy/wDkYb7yslBlEHs9UEL
oIyIeni/+lBjGk86Kunp8O3VBARN5mOC36x5kRKKcc8kHmHWsKYw+iMGLaLeCjro
V1CMv5De8fu1vwUfifaBGRpKitDtCIyCPg7FIn5aXkVt6gIH5aRvu03j9oFqRPF0
BUNcrK7QalmHzZzlNYcdgJVszcyuB0D2HG7La/5FLTU7jfRqBmwXgE8BH9NuQryG
IgZUFLN5e7RRfqBsn+Ezf+UII2+Slks6dTbzxk+bwgNuh8wkIYYWF76eZx15A8bu
F48JerX04Gr/iZw07JKDx8Ri794S9366OQUB+GleCEm+0GcKxGF6TaiVDXvQm2sr
RwIDAQAB
-----END PUBLIC KEY-----`;

async function uploadKey() {
    try {
        const response = await axios.post(
            `https://graph.facebook.com/v22.0/${WABA_ID}/whatsapp_business_encryption`,
            { business_public_key: PUBLIC_KEY },
            { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } }
        );
        console.log('✅ Key Uploaded Successfully:', response.data);
    } catch (error) {
        console.error('❌ Upload Failed:', error.response ? error.response.data : error.message);
    }
}

uploadKey();
