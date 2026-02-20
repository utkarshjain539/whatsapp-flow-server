const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "5mb" }));

// 🔐 Paste your PRIVATE KEY here
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArX1/0AC6fs5hrjVYPiAvhWj1C/5KbYsOYkXjBRKbsJkZsCYo
9VYPaml+LItinfksZQHrbl5DvYtDW9jt24hU7zeExw8sX5+acSt7WsEaFyJcX7SD
ZDuyAXcx9A4oOSIXJklQgpYK0TOxhEVGY+ZsphYV2BwpO5hffH4g9P7sPq6a/HQ5
oyJVaL0STJ92Nikhrr3KJzpB4UVtkyQQXM2FajU+9UDqpC9yPBzQps37yIA/cBh6
QqCgt9c661sF03EPU0GRqjbBxpSQb3KxxWv9QwRqureqS5hXfg05z89VWuHC7aAC
im1msPEFjTOQ2JKBkbhugA+mduhw6rp013H9wQIDAQABAoIBAEt9kXEL8BqfaSep
tKUL0kHF4uL+GprB6Fdgu6EIcNCOPfxFDot6kCiokKuHVzkQJH4rMKuMvwMqJvw/
T3i4QOT6jn8jnhZZ15Uo63sZDWZFoFZQsN+bjiBPImBlDKGXsOUK/8piyYAwcyzw
C+oKaPp4H7cywcpZyircozCYAGphTg/LGlJyyU03qk2ZswYpIswfjMZou8vLRl/P
oWfXgEPEKloln/4DtDKi9xv06W9L4JpO7Qh8yHuiFuQEv45kdelrN3f0/bAepWdN
6+2oUhC5aU7bkiBCJKfpmVnfM4h8i1xbmcWqw6M4QN6RBHz4uaM0ZvgFZiVFi1dk
lH8Uh3ECgYEA3dbsS1p1xUYCPg42HSk/8HGvCBgZzL8PmNsO/K5MdbcboN6X05yt
9xdzZTnvzdz8H8LFZmAJdlw6h445hwdJtkM7V98poUC6L4ta/pYwe8XuS0lwIvYh
/KnbzAVuKzOaSFIyyfPEOqhHBuuKANs5U5RoAHwhqrgYChl6QgEANfUCgYEAyDSc
bKrkPcMB3DaMLGP/D5lW0XI6u0/XGmFvcD2E6VsjeSv/0QUoETONp95o+tRVnUGM
t3G2zRBn4jbdXOhcDweOyVOUc3hks7I7GDUlaBwlu9SFuN766VS0/GWEULsYcLca
eA3hgnKTrUF0rYiLndOtkxiQjqQAk4PS8HR+vR0CgYBDTLJ+4cCcynJftRwBmMQH
A9Yf1H/vN39Z1gsj6RTVGWnOUfkpf3zfW0Psz7jKcWIjmIkeV8BHIg+3lBQrvLBG
FPtp2w/cFbDmP5apaZLn2dJDENJuKNGCv10o9fTIMm15x0YVMlizmt2BYe+J9vfb
PUiX7RChpBvW5IfMglU4CQKBgQCRbp5e1fj84IaeaEWFDZK/yxzlArylSscv0622
9Alz1o+7OvoW5U8Ix9FUK11JMCuNE4vbylAHQK6mBkLhda1CAbR4jS1egAtu+b6x
xBGLQj8q5aPJ+rh7/NuIKVpnprGHV4tzwGmbcA3UoqLWWEVLffQt0X9ZDsuYXP9D
SuyyBQKBgQDJKD6HeH4ixkoJRUGfMP/CW/MCIq73NX68LXkgvz5Z5HWOgXDUF0W9
Fa+CyijAMV5KCrwZ4tnPIx84JmqWAZnSebHzaEbQjQe8AgnKkdjm1E0ktneQXtpU
1+E0FbzkBLiJ0NbPJrScEF4JFSX19SjQv0Rf8yR+yyNWz/HX0eNo3g==
-----END RSA PRIVATE KEY-----
`;

app.post("/", (req, res) => {
  try {
    const body = req.body;

    // Health check
    if (!body.encrypted_aes_key) {
      return res.json({ status: "healthy" });
    }

    // 1️⃣ Decrypt AES key using RSA-OAEP SHA256
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(body.encrypted_aes_key, "base64")
    );

    // 2️⃣ Prepare Flow response
    const responsePayload = JSON.stringify({
      data: {}
    });

    // 3️⃣ Encrypt response using AES-256-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);

    let encrypted = cipher.update(responsePayload, "utf8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    return res.json({
      encrypted_flow_data: encrypted.toString("base64"),
      initial_vector: iv.toString("base64"),
      authentication_tag: authTag.toString("base64")
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/", (req, res) => {
  res.json({ status: "healthy" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
