
const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

app.disable("x-powered-by");
app.use(express.json({limit:"10kb"}));

const PORT = process.env.PORT || 3000;

const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const PATH = "code82437";
const BRANCH = "main";

const API =
 `https://api.github.com/repos/${OWNER}/${REPO}/contents/${PATH}`;

const challenges = new Map();

function githubHeaders(){
 return {
  "Authorization": `Bearer ${process.env.GITHUB_TOKEN}`,
  "Accept": "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "SCP-Key-Generator"
 };
}

async function githubRequest(url, options = {}){
 const response = await fetch(url,{
  ...options,
  headers:{
   ...githubHeaders(),
   ...(options.headers || {})
  }
 });

 const raw = await response.text();
 let data;

 try {
  data = JSON.parse(raw);
 } catch {
  throw new Error(
   `GitHub geçersiz cevap verdi (HTTP ${response.status}): ${raw.slice(0,150)}`
  );
 }

 if(!response.ok){
  throw new Error(
   `GitHub API ${response.status}: ${data.message || "İşlem başarısız"}`
  );
 }

 return data;
}

async function saveKey(line){
 for(let attempt=0;attempt<5;attempt++){
  const file = await githubRequest(
   `${API}?ref=${encodeURIComponent(BRANCH)}`
  );

  if(!file.sha || typeof file.content !== "string"){
   throw new Error("GitHub dosya içeriği okunamadı.");
  }

  const oldContent = Buffer.from(
   file.content.replace(/\s/g,""),"base64"
  ).toString("utf8");

  const newContent =
   oldContent.replace(/\s*$/,"") + "\n" + line + "\n";

  try {
   await githubRequest(API,{
    method:"PUT",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
     message:"SCP new 24-hour key",
     content:Buffer.from(newContent,"utf8").toString("base64"),
     sha:file.sha,
     branch:BRANCH
    })
   });

   return true;
  } catch(error){
   if(!error.message.includes("409") &&
      !error.message.includes("422")){
    throw error;
   }
  }
 }

 throw new Error("GitHub dosyası güncellenemedi. Tekrar dene.");
}

// İlk aşama: Sunucu tarafında bekleme başlat.
app.post("/api/start",(req,res)=>{
 const challenge = crypto.randomBytes(32).toString("hex");

 challenges.set(challenge,{
  createdAt:Date.now(),
  used:false
 });

 res.json({
  success:true,
  challenge
 });
});

// İkinci aşama: 30 saniye dolduysa key üret.
app.post("/api/generate",async(req,res)=>{
 try {
  if(!process.env.GITHUB_TOKEN){
   return res.status(500).json({
    error:"GITHUB_TOKEN .env dosyasında bulunamadı."
   });
  }

  const challenge = String(req.body.challenge || "");
  const session = challenges.get(challenge);

  if(!session){
   return res.status(403).json({
    error:"Geçersiz işlem. Yeniden başlat."
   });
  }

  if(session.used){
   return res.status(403).json({
    error:"Bu işlem daha önce kullanılmış."
   });
  }

  if(Date.now()-session.createdAt < 30000){
   return res.status(429).json({
    error:"30 saniyelik bekleme henüz tamamlanmadı."
   });
  }

  session.used = true;

  const key = "SCP-" +
   crypto.randomBytes(16).toString("hex").toUpperCase();

  const expires = Date.now() + 24*60*60*1000;

  await saveKey(`${key}|${expires}`);

  challenges.delete(challenge);

  res.json({
   success:true,
   key,
   expires
  });

 } catch(error){
  console.error("GENERATE ERROR:",error);

  res.status(500).json({
   error:error.message || "Key oluşturulamadı."
  });
 }
});

// Key doğrulama.
app.post("/api/verify",async(req,res)=>{
 try {
  const key = String(req.body.key || "");

  if(!/^SCP-[A-F0-9]{32}$/.test(key)){
   return res.json({valid:false});
  }

  const file = await githubRequest(
   `${API}?ref=${encodeURIComponent(BRANCH)}`
  );

  const content = Buffer.from(
   file.content.replace(/\s/g,""),"base64"
  ).toString("utf8");

  const record = content.split(/\r?\n/).find(row=>{
   const parts = row.split("|");
   return parts[0] === key;
  });

  if(!record){
   return res.json({valid:false});
  }

  const expiry = Number(record.split("|")[1]);

  res.json({
   valid:Number.isFinite(expiry) && expiry > Date.now(),
   expires:expiry
  });

 } catch(error){
  console.error("VERIFY ERROR:",error);
  res.status(500).json({
   valid:false,
   error:"Doğrulama yapılamadı."
  });
 }
});

// JSON cevaplı bulunamayan adres.
app.use((req,res)=>{
 res.status(404).json({
  error:"API adresi bulunamadı: " + req.path
 });
});

// Önce API rotaları, ardından HTML dosyaları.
app.use(express.static("public"));

app.listen(PORT,()=>{
 console.log("SCP KEY GENERATOR hazır.");
 console.log(`Adres: http://localhost:${PORT}`);
});
