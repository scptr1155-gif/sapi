
"use strict";

const crypto = require("node:crypto");

const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const FILE = "code82437";
const BRANCH = "main";

const WAIT_MS = 30 * 1000;
const KEY_LIFETIME_MS = 24 * 60 * 60 * 1000;
const CHALLENGE_MAX_AGE_MS = WAIT_MS + 10 * 60 * 1000;

const GITHUB_URL =
    `https://api.github.com/repos/${OWNER}/${REPO}/contents/${FILE}?ref=${BRANCH}`;

function send(res, status, data) {
    res.setHeader("Cache-Control", "no-store");
    return res.status(status).json(data);
}

function getBody(req) {
    if (req.body && typeof req.body === "object") {
        return req.body;
    }

    if (typeof req.body === "string") {
        return JSON.parse(req.body);
    }

    return {};
}

function getSecrets() {
    const token = process.env.GITHUB_TOKEN;
    const secret = process.env.KEY_SIGNING_SECRET;

    if (!token) {
        throw new Error("GITHUB_TOKEN ayarlanmamış.");
    }

    if (!secret || secret.length < 32) {
        throw new Error("KEY_SIGNING_SECRET eksik veya çok kısa.");
    }

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
    const payload = {
        issuedAt: Date.now(),
        nonce: crypto.randomBytes(24).toString("hex")
    };

    const encoded = Buffer
        .from(JSON.stringify(payload))
        .toString("base64url");

    const signature = crypto
        .createHmac("sha256", secret)
        .update(encoded)
        .digest("base64url");

    return encoded + "." + signature;
}

// Doğrulama biletinin imzasını kontrol et.
function readChallenge(ticket, secret) {
    if (typeof ticket !== "string") return null;

    const parts = ticket.split(".");

    if (parts.length !== 2) return null;

    const [encoded, signature] = parts;

    const expected = crypto
        .createHmac("sha256", secret)
        .update(encoded)
        .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)
    ) {
        return null;
    }

    try {
        const payload = JSON.parse(
            Buffer.from(encoded, "base64url").toString("utf8")
        );

        if (
            !Number.isSafeInteger(payload.issuedAt) ||
            typeof payload.nonce !== "string" ||
            !/^[a-f0-9]{48}$/.test(payload.nonce)
        ) {
            return null;
        }

        return payload;

    } catch {
        return null;
    }
}

// Rastgele ve imzalı biletten benzersiz key üret.
function deriveKey(secret, nonce) {
    const raw = crypto
        .createHmac("sha256", secret)
        .update("key:" + nonce)
        .digest("hex")
        .toUpperCase()
        .slice(0, 36);

    const groups = raw.match(/.{6}/g);

    return "SCP-" + groups.join("-");
}

// GitHub'da gerçek key yerine SHA-256 sakla.
function hashKey(key) {
    return crypto
        .createHash("sha256")
        .update(key)
        .digest("hex");
}

// GitHub dosyasını oku.
async function getGithubFile(token) {
    const result = await fetch(GITHUB_URL, {
        headers: githubHeaders(token),
        cache: "no-store"
    });

    if (!result.ok) {
        throw new Error(
            "GitHub dosyası okunamadı. HTTP " + result.status
        );
    }

    const data = await result.json();

    if (
        !data.sha ||
        typeof data.content !== "string"
    ) {
        throw new Error("GitHub dosya içeriği geçersiz.");
    }

    const content = Buffer
        .from(data.content.replace(/\s/g, ""), "base64")
        .toString("utf8");

    return {
        sha: data.sha,
        content
    };
}

// Hash ve bitiş tarihini bul.
function findRecord(content, hash) {
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
        const parts = line.trim().split("|");

        if (parts.length !== 2) continue;
        if (parts[0] !== hash) continue;

        const expiresAt = Date.parse(parts[1]);

        if (!Number.isFinite(expiresAt)) continue;

        return {
            expiresAt,
            date: parts[1]
        };
    }

    return null;
}

// Yeni key kaydını GitHub dosyasına ekle.
async function appendGithubRecord(token, hash) {
    for (let attempt = 0; attempt < 4; attempt++) {

        const file = await getGithubFile(token);

        // Aynı istek tekrar geldiyse yeniden kayıt oluşturma.
        const existing = findRecord(file.content, hash);

        if (existing) {
            return existing.date;
        }

        // 24 saatlik süre key oluşturulduğu anda başlar.
        const expiresAt = new Date(
            Date.now() + KEY_LIFETIME_MS
        ).toISOString();

        const record = `${hash}|${expiresAt}`;

        const oldContent = file.content.replace(/\s+$/, "");

        const newContent =
            (oldContent ? oldContent + "\n" : "") +
            record + "\n";

        const result = await fetch(GITHUB_URL, {
            method: "PUT",
            headers: {
                ...githubHeaders(token),
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: "New SCP key generated",
                branch: BRANCH,
                sha: file.sha,
                content: Buffer
                    .from(newContent, "utf8")
                    .toString("base64")
            })
        });

        if (result.ok) {
            return expiresAt;
        }

        // Başka bir işlem dosyayı güncellediyse tekrar oku.
        if (
            (result.status === 409 || result.status === 422) &&
            attempt < 3
        ) {
            continue;
        }

        throw new Error(
            "GitHub dosyasına yazılamadı. HTTP " + result.status
        );
    }

    throw new Error("GitHub güncelleme çakışması.");
}

// Key geçerliliğini sunucu tarafında kontrol et.
async function verifyKey(token, key) {
    if (typeof key !== "string") {
        return { valid: false, reason: "invalid" };
    }

    key = key.trim().toUpperCase();

    const pattern =
        /^SCP-(?:[A-F0-9]{6}-){5}[A-F0-9]{6}$/;

    if (!pattern.test(key)) {
        return { valid: false, reason: "invalid" };
    }

    const hash = hashKey(key);

    const file = await getGithubFile(token);

    const record = findRecord(file.content, hash);

    if (!record) {
        return {
            valid: false,
            reason: "not_found"
        };
    }

    if (record.expiresAt <= Date.now()) {
        return {
            valid: false,
            reason: "expired",
            expiresAt: record.date
        };
    }

    return {
        valid: true,
        reason: "active",
        expiresAt: record.date
    };
}

module.exports = async function handler(req, res) {

    if (req.method !== "POST") {
        return send(res, 405, {
            error: "Sadece POST isteği kabul edilir."
        });
    }

    // API'yi yalnızca aynı siteden gelen tarayıcı
    // isteklerine aç.
    const origin = req.headers.origin;
    const host = req.headers.host;

    if (!origin || !host) {
        return send(res, 403, {
            error: "İstek kaynağı doğrulanamadı."
        });
    }

    try {
        if (new URL(origin).host !== host) {
            return send(res, 403, {
                error: "İstek kaynağı kabul edilmedi."
            });
        }
    } catch {
        return send(res, 403, {
            error: "Geçersiz istek kaynağı."
        });
    }

    try {
        const { token, secret } = getSecrets();
        const body = getBody(req);

        // 1. Sayaç başlat.
        if (body.action === "start") {

            const challenge = createChallenge(secret);
            const serverTime = Date.now();

            return send(res, 200, {
                success: true,
                challenge,
                serverTime,
                readyAt: serverTime + WAIT_MS
            });
        }

        // 2. Sayaç tamamlandıktan sonra key üret.
        if (body.action === "complete") {

            const payload = readChallenge(
                body.challenge,
                secret
            );

            if (!payload) {
                return send(res, 403, {
                    success: false,
                    error: "Doğrulama bileti geçersiz."
                });
            }

            const elapsed = Date.now() - payload.issuedAt;

            if (elapsed < WAIT_MS) {
                return send(res, 425, {
                    success: false,
                    error: "Bekleme süresi tamamlanmadı.",
                    remainingMs: WAIT_MS - elapsed
                });
            }

            if (elapsed > CHALLENGE_MAX_AGE_MS) {
                return send(res, 410, {
                    success: false,
                    error: "Doğrulama biletinin süresi doldu."
                });
            }

            const key = deriveKey(
                secret,
                payload.nonce
            );

            const hash = hashKey(key);

            const savedExpiry = await appendGithubRecord(
                token,
                hash
            );

            return send(res, 200, {
                success: true,
                key,
                expiresAt: savedExpiry
            });
        }

        // 3. Key doğrula.
        if (body.action === "verify") {

            const result = await verifyKey(
                token,
                body.key
            );

            return send(res, 200, result);
        }

        return send(res, 400, {
            error: "Bilinmeyen işlem."
        });

    } catch (error) {
        console.error("SCP KEY API:", error.message);

        return send(res, 500, {
            error: "Sunucu işlemi tamamlayamadı."
        });
    }
};
