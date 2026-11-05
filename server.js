
const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
app.use(express.json());

const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const PATH = "code82437";
const BRANCH = "main";

const API = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${PATH}`;

const challenges = new Map();

function headers() {
    return {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SCP-Key-Generator"
    };
}

// API TEST
app.get("/api/test", (req, res) => {
    res.json({
        success: true,
        message: "SCP API çalışıyor!"
    });
});

// Geri sayım başlat
app.post("/api/start", (req, res) => {
    const challenge = crypto.randomBytes(32).toString("hex");

    challenges.set(challenge, {
        createdAt: Date.now(),
        used: false
    });

    res.json({
        success: true,
        challenge
    });
});

// GitHub dosyasına key ekle
async function saveKey(line) {
    for (let i = 0; i < 5; i++) {
        const response = await fetch(
            `${API}?ref=${BRANCH}`,
            { headers: headers() }
        );

        if (!response.ok) {
            throw new Error("GitHub dosyası okunamadı: " + await response.text());
        }

        const file = await response.json();

        const oldContent = Buffer.from(
            file.content.replace(/\s/g, ""),
            "base64"
        ).toString("utf8");

        const newContent =
            oldContent.replace(/\s*$/, "") + "\n" + line + "\n";

        const update = await fetch(API, {
            method: "PUT",
            headers: {
                ...headers(),
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: "New SCP 24h key",
                content: Buffer.from(newContent).toString("base64"),
                sha: file.sha,
                branch: BRANCH
            })
        });

        if (update.ok) return true;

        if (update.status !== 409 && update.status !== 422) {
            throw new Error("GitHub kayıt hatası: " + await update.text());
        }
    }

    throw new Error("GitHub dosyası güncellenemedi.");
}

// Key üret
app.post("/api/generate", async (req, res) => {
    try {
        if (!process.env.GITHUB_TOKEN) {
            throw new Error("GitHub token bulunamadı.");
        }

        const challenge = String(req.body.challenge || "");
        const session = challenges.get(challenge);

        if (!session || session.used) {
            return res.status(403).json({
                error: "Geçersiz işlem. Tekrar başlat."
            });
        }

        if (Date.now() - session.createdAt < 30000) {
            return res.status(429).json({
                error: "30 saniye henüz dolmadı."
            });
        }

        session.used = true;

        const key = "SCP-" +
            crypto.randomBytes(16).toString("hex").toUpperCase();

        const expires = Date.now() + 86400000;

        await saveKey(`${key}|${expires}`);

        challenges.delete(challenge);

        res.json({
            success: true,
            key,
            expires
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: error.message
        });
    }
});

// Key doğrulama
app.post("/api/verify", async (req, res) => {
    try {
        const key = String(req.body.key || "");

        if (!/^SCP-[A-F0-9]{32}$/.test(key)) {
            return res.json({ valid: false });
        }

        const response = await fetch(
            `${API}?ref=${BRANCH}`,
            { headers: headers() }
        );

        if (!response.ok) {
            throw new Error("GitHub okunamadı.");
        }

        const file = await response.json();

        const content = Buffer.from(
            file.content.replace(/\s/g, ""),
            "base64"
        ).toString("utf8");

        const row = content.split(/\r?\n/).find(
            line => line.split("|")[0] === key
        );

        if (!row) {
            return res.json({ valid: false });
        }

        const expiry = Number(row.split("|")[1]);

        res.json({
            valid: Number.isFinite(expiry) && expiry > Date.now(),
            expires: expiry
        });

    } catch (error) {
        res.status(500).json({
            valid: false,
            error: error.message
        });
    }
});

// HTML dosyaları
app.use(express.static("public"));

// Bulunamayan adresler
app.use((req, res) => {
    res.status(404).json({
        error: "API adresi bulunamadı: " + req.path
    });
});

app.listen(PORT, () => {
    console.log("SCP KEY GENERATOR hazır!");
    console.log("http://localhost:" + PORT);
});
