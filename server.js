const crypto = require("crypto");

const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const PATH = "code82437";
const BRANCH = "main";
const WAIT_MS = 30000;               // bekleme suresi
const KEY_TTL_MS = 24 * 60 * 60 * 1000; // key omru: 24 saat

const GITHUB_API =
 `https://api.github.com/repos/${OWNER}/${REPO}/contents/${PATH}`;

function send(res,status,data){
 res.statusCode=status;
 res.setHeader("Content-Type","application/json; charset=utf-8");
 res.setHeader("Cache-Control","no-store");
 res.end(JSON.stringify(data));
}

function safeEqual(a,b){
 const x=Buffer.from(a);
 const y=Buffer.from(b);
 return x.length===y.length && crypto.timingSafeEqual(x,y);
}

// Vercel'e yapistirirken kalan bosluk/tirnaklari temizler
function env(name){
 return String(process.env[name]||"").trim().replace(/^["']|["']$/g,"");
}

function sign(payload){
 return crypto.createHmac("sha256",env("HMAC_SECRET"))
  .update(payload).digest("hex");
}

async function readBody(req){
 if(req.body && typeof req.body==="object" && !Buffer.isBuffer(req.body))
  return req.body;
 let raw=typeof req.body==="string" ? req.body : "";
 if(!raw && !req.readableEnded){
  raw=await new Promise(resolve=>{
   let d="";
   req.on("data",c=>d+=c);
   req.on("end",()=>resolve(d));
   req.on("error",()=>resolve(""));
  });
 }
 try{return JSON.parse(raw||"{}")}catch{return {}}
}

async function github(url,options={}){
 const response=await fetch(url,{
  ...options,
  headers:{
   Authorization:`Bearer ${env("GITHUB_TOKEN")}`,
   Accept:"application/vnd.github+json",
   "X-GitHub-Api-Version":"2022-11-28",
   "User-Agent":"SCP-Key-Generator",
   ...(options.headers||{})
  }
 });

 const raw=await response.text();
 let data;

 try{data=JSON.parse(raw)}
 catch{throw new Error("GitHub geçersiz cevap verdi.")}

 if(!response.ok){
  throw new Error("GitHub "+response.status+": "+(data.message||"Hata"));
 }

 return data;
}

async function readFile(){
 const file=await github(
  `${GITHUB_API}?ref=${encodeURIComponent(BRANCH)}`
 );

 const content=Buffer.from(
  file.content.replace(/\s/g,""),"base64"
 ).toString("utf8");

 return {file,content};
}

// Satir formati: KEY|bitisZamani|islemId
// Suresi dolan satirlar silinir, "|" icermeyen (elle yazilmis) satirlar korunur.
// Ayni islemId ikinci kez gelirse false doner (tek kullanimlik challenge).
async function saveKey(key,expires,nonceId){
 for(let i=0;i<5;i++){
  const {file,content}=await readFile();
  const now=Date.now();

  const lines=content.split(/\r?\n/).map(l=>l.trim()).filter(Boolean)
   .filter(l=>{
    const p=l.split("|");
    const exp=Number(p[1]);
    return !(p.length>1 && Number.isFinite(exp) && exp<=now);
   });

  if(lines.some(l=>l.split("|")[2]===nonceId)) return false;

  lines.push(`${key}|${expires}|${nonceId}`);
  const updated=lines.join("\n")+"\n";

  try{
   await github(GITHUB_API,{
    method:"PUT",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
     message:"SCP 24 hour key generated",
     content:Buffer.from(updated).toString("base64"),
     sha:file.sha,
     branch:BRANCH
    })
   });
   return true;
  }catch(error){
   if(!error.message.includes("409") &&
      !error.message.includes("422")) throw error;
  }
 }
 throw new Error("GitHub dosyası güncellenemedi.");
}

module.exports=async function(req,res){
 try{
  const missing=[];
  if(!env("GITHUB_TOKEN")) missing.push("GITHUB_TOKEN");
  if(env("HMAC_SECRET").length<32) missing.push("HMAC_SECRET (en az 32 karakter)");
  if(missing.length)
   return send(res,500,{error:"Vercel ortam değişkeni eksik: "+missing.join(", ")+". Ekledikten sonra Redeploy et."});

  const url=new URL(req.url,"https://vercel.app");
  const route=url.pathname;

  if(req.method==="POST" && route==="/api/start"){
   const payload=Buffer.from(JSON.stringify({
    created:Date.now(),
    nonce:crypto.randomBytes(32).toString("hex")
   })).toString("base64url");

   return send(res,200,{
    success:true,
    challenge:payload+"."+sign(payload),
    waitMs:WAIT_MS
   });
  }

  if(req.method==="POST" && route==="/api/generate"){
   const body=await readBody(req);
   const challenge=String(body.challenge||"");
   const parts=challenge.split(".");

   if(parts.length!==2)
    return send(res,403,{error:"Geçersiz işlem."});

   const [payload,signature]=parts;

   if(!safeEqual(signature,sign(payload)))
    return send(res,403,{error:"İmza doğrulanamadı."});

   let data;
   try{
    data=JSON.parse(
     Buffer.from(payload,"base64url").toString("utf8")
    );
   }catch{
    return send(res,403,{error:"Challenge okunamadı."});
   }

   if(typeof data.nonce!=="string" || !Number.isFinite(data.created))
    return send(res,403,{error:"Challenge okunamadı."});

   const age=Date.now()-data.created;

   if(age<WAIT_MS)
    return send(res,429,{error:"30 saniye henüz dolmadı."});

   if(age>600000)
    return send(res,403,{error:"İşlem süresi dolmuş. Yeniden başlat."});

   // Her istek icin yeni rastgele key
   const key="SCP-"+crypto.randomBytes(16)
    .toString("hex").toUpperCase();

   const expires=Date.now()+KEY_TTL_MS;
   const nonceId=crypto.createHash("sha256")
    .update(data.nonce).digest("hex").slice(0,16);

   const saved=await saveKey(key,expires,nonceId);

   if(!saved)
    return send(res,409,{error:"Bu işlem zaten kullanıldı. Yeni key için baştan başlat."});

   return send(res,200,{success:true,key,expires});
  }

  if(req.method==="POST" && route==="/api/verify"){
   const body=await readBody(req);
   const key=String(body.key||"");

   if(!/^SCP-[A-F0-9]{32}$/.test(key))
    return send(res,200,{valid:false});

   const {content}=await readFile();

   const row=content.split(/\r?\n/).find(
    line=>line.split("|")[0]===key
   );

   if(!row)return send(res,200,{valid:false});

   const expires=Number(row.split("|")[1]);

   return send(res,200,{
    valid:Number.isFinite(expires)&&expires>Date.now(),
    expires
   });
  }

  return send(res,404,{error:"API adresi bulunamadı."});

 }catch(error){
  console.error(error);
  return send(res,500,{error:error.message||"Sunucu hatası."});
 }
};
