const axios = require('axios');

const ACCESS_TOKEN = 'EAALZAyj90w9YBQ6XkIMVB6EJtupjWweVYZA9NHZCfSbuIXH40yAMeZAn6fJWm6s5g7vP6nTgdjQLo9igWCoz54b7t7KBpKRkj8zxpcbQccx3hmQXmQ5jck81ZABMrR2OwMkz7KXyskNetbmA563rcZAhTplHCLDYCX5o4k6gMfLBAoxNTHlX1NIRI2IG3eQuBA1aYBc5xZCRVRRO8HPJkZAZChF3HQUnQeXmUaSzyUjfBVQtU2rhCmwgcD55ruIKNvgcoZAhvbeiT4b32bNfabMzU9RnW1Ej0FHqsUxQZDZD';
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
