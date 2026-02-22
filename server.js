const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// 🔐 YOUR PRIVATE KEY
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDL/AORhvvKyUGU
Qez1QQugjIh6eL/6UGMaTzoq6enw7dUEBE3mY4LfrHmREopxzyQeYdawpjD6IwYt
ot4KOuhXUIy/kN7x+7W/BR+J9oEZGkqK0O0IjII+DsUiflpeRW3qAgflpG+7TeP2
gWpE8XQFQ1ysrtBqWYfNnOU1hx2AlWzNzK4HQPYcbstr/kUtNTuN9GoGbBeATwEf
025CvIYiBlQUs3l7tFF+oGyf4TN/5Qgjb5KWSzp1NvPGT5vCA26HzCQhhhYXvp5n
HXkDxu4Xjwl6tfTgav+JnDTskoPHxGLv3hL3fro5BQH4aV4ISb7QZwrEYXpNqJUN
e9CbaytHAgMBAAECggEAFcQJWXDu0x+QeNJkB3NuWy5DrdXOnlYPjRIhIc0d4lBu
Z2RSL6A0qctMmXdCAIzazMch0m2ZUkeEdEApsyu/+PkmW5aIw4dZSE2ypNUBx3zv
sUpD0KK1jwuia2DSIbcE2HBpCU73gSP5jCcZAMxG1fzvGZn5sS9md0EjkAef1UVr
mj9cXB0llMvM8BKT239R8ACmEoJq/zfHe6mor1SlFuhxAAT8+LfSIaUQmxerGgSV
8A8zzQdewYfZWMznwy4oUkjJxMDKqm00atLbN6HTHoq0VIpNvKAHNjchic2R5ZZy
qveOzC0BKyn21TC/XffxqglKKTvbD9Uy5ZtDuZkSMQKBgQD0nV0Ed9zzqhOUHXxq
Hxekje1waYIRC3Naj0mR9Q+sHtXfx2HkwNX2Gm6F0eb8pLQA4ERLmyK0rqLl1ZNU
Rf3VpOrurefLfegv/ZlooQGx2kM1jn9T8BWRVq5nTAMetif+cv0my4C0boekvJcD
amu5lyozVcijDtcPAZUbRjkBKQKBgQDVeog9n0vuwPCWKA+jf+xoyfjqMfbRynSu
5SJuHRWSYwvZgaHKHX+MNZ9QVv3CFotqTNQVAK4KOioUI9S/2TqWWBg6jpPz3lYE
GfTjcytYHxB9qku0arkVYQGB4zgrOOpSWgT9delA1WTfoDdfKp0gt4l91T7PkbCD
WDkZ068m7wKBgFN77YYb3nXuwtXXsiQATpJjufiWmcR1cv4iTwqYZ6vnrji8lIV8
5skihjv3wmzRTXnLEKP5I2QlAgWM2cZ2SMaEjYW+JpEFvJu8YoIaCTkI880wf/ZG
xyWePtGUWLA/nPCzkACQjbGG05Z+os+Qn4lstQNmMJ6t7un5MUloswXZAoGBANIF
xtu5SJ8PuqI/r4MPa6p8aiMeHNGw+LLIQuNKQdrPDu1iF6Yc90sdxiroKqc0PtzJ
0S0IijENoDBIQBquwHEBInUZqH2YE8/dKYxL1izQAw1e6TQKeySJV05OGQiM6hsy
7Q3fXyelyaQon9FEv2lcqCvgC/dyQdI2jZbXJ86JAoGBAJurHxwqNw2CwiPgdI7w
kvONnwthGORVWYV41MNyblQ/M5ebpgt2eQhG6noC8Q8JmqDkp3UE07n50kcaJJAw
WxSzeBYDCsH1dHg3/BJmPORRwKmTUlYtGp17uCm1UNmcog9merg92WMShlF4ajah
MenuoTnhnR+OmQ4t3WqlRmFeD/K7
-----END PRIVATE KEY-----`;
app.post("/", (req, res) => {
  try {
    const {
      encrypted_aes_key,
      encrypted_flow_data,
      initial_vector,
      authentication_tag
    } = req.body;

    // ❗ If Meta didn't send encryption fields, just exit safely
    if (!encrypted_aes_key) {
      return res.status(200).end();
    }

    // 1️⃣ Decrypt AES Key
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // 2️⃣ Decrypt Request Payload
    const decipher = crypto.createDecipheriv(
      "aes-128-gcm",
      aesKey,
      Buffer.from(initial_vector, "base64")
    );

    decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

    let decrypted = decipher.update(
      Buffer.from(encrypted_flow_data, "base64")
    );

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    console.log("Decrypted Request:", decrypted.toString());

    // 3️⃣ Prepare response
    const responsePayload = JSON.stringify({
      version: "3.0",
      data: { status: "healthy" }
    });

    // 4️⃣ Encrypt response
    const responseIv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
      "aes-128-gcm",
      aesKey,
      responseIv
    );

    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    return res.status(200).json({
      encrypted_flow_data: encrypted.toString("base64"),
      encrypted_aes_key: encrypted_aes_key,
      initial_vector: responseIv.toString("base64"),
      authentication_tag: authTag.toString("base64")
    });

  } catch (err) {
    console.error("Flow error:", err);
    return res.status(500).end();
  }
});

// Required for Render
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
