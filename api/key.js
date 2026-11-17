"use strict";

const crypto = require("node:crypto");

// SENİN GITHUB BİLGİLERİN
const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const FILE = "code82437";
const BRANCH = "main";

const WAIT_MS = 30 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const KEY_LIFETIME_MS = 24 * HOUR_MS;
const CHALLENGE_MAX_AGE_MS = WAIT_MS + 10 * 60 * 1000;

// SCP-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX (ilk grup üretim saati)
const KEY_PATTERN = /^SCP-([0-9A-F]{6})(?:-[0-9A-F]{6}){5}$/;

const GITHUB_URL = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${FILE}?ref=${BRANCH}`;

function send(res, status, data) {
    res.setHeader("Cache-Control", "no-store");
    return res.status(status).json(data);
}

function getBody(req) {
    if (req.body && typeof req.body === "object") return req.body;
    if (typeof req.body === "string") return JSON.parse(req.body);
    return {};
}

function getSecrets() {
    const token = process.env.GITHUB_TOKEN;
    const secret = process.env.KEY_SIGNING_SECRET;

    if (!token) throw new Error("Vercel'de GITHUB_TOKEN ayarlanmamış.");
    if (!secret || secret.length < 32) throw new Error("Vercel'de KEY_SIGNING_SECRET eksik veya çok kısa (en az 32 karakter olmalı).");

    return { token, secret };
}

function githubHeaders(token) {
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28"
    };
}

// Sunucu tarafından imzalanmış doğrulama bileti.
function createChallenge(secret) {
    const payload = { issuedAt: Date.now(), nonce: crypto.randomBytes(24).toString("hex") };
    const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
    return encoded + "." + signature;
}

// Doğrulama biletinin imzasını kontrol et.
function readChallenge(ticket, secret) {
    if (typeof ticket !== "string") return null;
    const parts = ticket.split(".");
    if (parts.length !== 2) return null;
    const [encoded, signature] = parts;
    const expected = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

    try {
        const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
        if (!Number.isSafeInteger(payload.issuedAt) || typeof payload.nonce !== "string" || !/^[a-f0-9]{48}$/.test(payload.nonce)) return null;
        return payload;
    } catch {
        return null;
    }
}

// Key üret: ilk grup üretim saati (saat cinsinden, hex), kalan kısım HMAC.
function deriveKey(secret, nonce, issuedHour) {
    const hex = crypto.createHmac("sha256", secret).update("key:" + nonce).digest("hex").toUpperCase().slice(0, 30);
    const timePart = issuedHour.toString(16).toUpperCase().padStart(6, "0");
    const groups = (timePart + hex).match(/.{6}/g);
    return "SCP-" + groups.join("-");
}

// Key'den üretim saatini oku. Geçersiz formatsa null döner.
function keyHour(key) {
    const match = KEY_PATTERN.exec(key);
    if (!match) return null;
    return parseInt(match[1], 16);
}

function keyExpiresAt(key) {
    const hour = keyHour(key);
    if (hour === null) return null;
    return hour * HOUR_MS + KEY_LIFETIME_MS;
}

function isLive(key, now) {
    const expiresAt = keyExpiresAt(key);
    return expiresAt !== null && now < expiresAt;
}

function parseKeys(content) {
    return content.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}

async function getGithubFile(token) {
    const result = await fetch(GITHUB_URL, { headers: githubHeaders(token), cache: "no-store" });
    if (!result.ok) throw new Error("GitHub dosyası okunamadı. HTTP " + result.status);
    const data = await result.json();
    if (!data.sha || typeof data.content !== "string") throw new Error("GitHub dosya içeriği geçersiz.");
    const content = Buffer.from(data.content.replace(/\s/g, ""), "base64").toString("utf8");
    return { sha: data.sha, content };
}

// Süresi dolmuş (14 saat geçmiş) ve bozuk satırları silerek key'i dosyaya ekle.
async function appendGithubKey(token, key) {
    for (let attempt = 0; attempt < 4; attempt++) {
        const file = await getGithubFile(token);
        const now = Date.now();
        const live = parseKeys(file.content).filter(k => isLive(k, now));

        if (live.includes(key)) return;
        live.push(key);

        const newContent = live.join("\n") + "\n";

        const result = await fetch(GITHUB_URL, {
            method: "PUT",
            headers: { ...githubHeaders(token), "Content-Type": "application/json" },
            body: JSON.stringify({
                message: "New SCP key generated",
                branch: BRANCH,
                sha: file.sha,
                content: Buffer.from(newContent, "utf8").toString("base64")
            })
        });

        if (result.ok) return;
        if ((result.status === 409 || result.status === 422) && attempt < 3) continue;
        throw new Error("GitHub dosyasına yazılamadı. HTTP " + result.status);
    }
    throw new Error("GitHub güncelleme çakışması.");
}

async function verifyKey(token, key) {
    if (typeof key !== "string") return { valid: false, reason: "invalid" };
    key = key.trim().toUpperCase();
    if (!KEY_PATTERN.test(key)) return { valid: false, reason: "invalid" };

    const file = await getGithubFile(token);
    const keys = parseKeys(file.content);
    if (!keys.includes(key)) return { valid: false, reason: "not_found" };

    const expiresAtMs = keyExpiresAt(key);
    if (expiresAtMs === null || expiresAtMs <= Date.now()) {
        return { valid: false, reason: "expired" };
    }

    return { valid: true, reason: "active", expiresAt: new Date(expiresAtMs).toISOString() };
}

module.exports = async function handler(req, res) {
    if (req.method !== "POST") return send(res, 405, { error: "Sadece POST isteği kabul edilir." });

    // CORS Kontrolü
    const origin = req.headers.origin;
    const host = req.headers.host;
    if (!origin || !host) return send(res, 403, { error: "İstek kaynağı doğrulanamadı." });

    try {
        if (new URL(origin).host !== host) {
            return send(res, 403, { error: "İstek kaynağı kabul edilmedi." });
        }
    } catch {
        return send(res, 403, { error: "Geçersiz istek kaynağı." });
    }

    try {
        const { token, secret } = getSecrets();
        const body = getBody(req);

        if (body.action === "start") {
            const challenge = createChallenge(secret);
            const serverTime = Date.now();
            return send(res, 200, { success: true, challenge, serverTime, readyAt: serverTime + WAIT_MS });
        }

        if (body.action === "complete") {
            const payload = readChallenge(body.challenge, secret);
            if (!payload) return send(res, 403, { success: false, error: "Doğrulama bileti geçersiz." });

            const elapsed = Date.now() - payload.issuedAt;
            if (elapsed < WAIT_MS) return send(res, 425, { success: false, error: "Bekleme süresi tamamlanmadı.", remainingMs: WAIT_MS - elapsed });
            if (elapsed > CHALLENGE_MAX_AGE_MS) return send(res, 410, { success: false, error: "Doğrulama biletinin süresi doldu." });

            const issuedHour = Math.floor(Date.now() / HOUR_MS);
            const key = deriveKey(secret, payload.nonce, issuedHour);
            await appendGithubKey(token, key);

            const expiresAt = new Date(issuedHour * HOUR_MS + KEY_LIFETIME_MS).toISOString();
            return send(res, 200, { success: true, key, expiresAt });
        }

        if (body.action === "verify") {
            const result = await verifyKey(token, body.key);
            return send(res, 200, result);
        }

        return send(res, 400, { error: "Bilinmeyen işlem." });
    } catch (error) {
        console.error("SCP KEY API:", error.message);
        return send(res, 500, { error: "Sunucu işlemi tamamlayamadı: " + error.message });
    }
};
