
const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(express.static("public"));

const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const PATH = "code82437";
const BRANCH = "main";
const API = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${PATH}`;

const headers = {
  "Authorization": `Bearer ${process.env.GITHUB_TOKEN}`,
  "Accept": "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "SCP-Key-Generator"
};

app.post("/api/generate", async (req, res) => {
  if (!process.env.GITHUB_TOKEN) {
    return res.status(500).json({error:"GitHub token ayarlanmamış."});
  }

  const key = "SCP-" + crypto.randomBytes(16).toString("hex").toUpperCase();
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  const line = `${key}|${expires}`;

  try {
    let saved = false;

    for (let attempt = 0; attempt < 4; attempt++) {
      const get = await fetch(`${API}?ref=${BRANCH}`, {headers});
      if (!get.ok) throw new Error("GitHub dosyası okunamadı.");

      const file = await get.json();
      const oldContent = Buffer.from(file.content, "base64").toString("utf8");
      const newContent = oldContent.replace(/\s*$/, "") + "\n" + line + "\n";

      const put = await fetch(API, {
        method: "PUT",
        headers,
        body: JSON.stringify({
          message: "New 24-hour SCP key",
          content: Buffer.from(newContent).toString("base64"),
          sha: file.sha,
          branch: BRANCH
        })
      });

      if (put.ok) {
        saved = true;
        break;
      }

      if (put.status !== 409 && put.status !== 422) {
        const error = await put.text();
        throw new Error("GitHub yazma hatası: " + error);
      }
    }

    if (!saved) throw new Error("GitHub güncellemesi başarısız.");

    res.json({success:true, key, expires});
  } catch (error) {
    console.error(error);
    res.status(500).json({error:"Key GitHub'a kaydedilemedi."});
  }
});

app.post("/api/verify", async (req, res) => {
  try {
    const key = String(req.body.key || "");
    if (!key || key.length > 100) {
      return res.status(400).json({valid:false});
    }

    const response = await fetch(`${API}?ref=${BRANCH}`, {headers});
    if (!response.ok) throw new Error("GitHub okunamadı.");

    const file = await response.json();
    const content = Buffer.from(file.content, "base64").toString("utf8");

    const record = content.split(/\r?\n/).find(row => {
      const [storedKey] = row.split("|");
      return storedKey === key;
    });

    if (!record) return res.json({valid:false});

    const [, expiry] = record.split("|");
    const valid = Number(expiry) > Date.now();

    res.json({valid});
  } catch {
    res.status(500).json({valid:false, error:"Doğrulama yapılamadı."});
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log("SCP KEY GENERATOR hazır.");
});
