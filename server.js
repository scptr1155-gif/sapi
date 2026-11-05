
const crypto = require("crypto");

const OWNER = "scptr1155-gif";
const REPO = "fly-noclip-scpstudio";
const PATH = "code82437";
const BRANCH = "main";

const GITHUB_API =
 `https://api.github.com/repos/${OWNER}/${REPO}/contents/${PATH}`;

function send(res,status,data){
 res.statusCode=status;
 res.setHeader("Content-Type","application/json; charset=utf-8");
 res.end(JSON.stringify(data));
}

function safeEqual(a,b){
 const x=Buffer.from(a);
 const y=Buffer.from(b);
 return x.length===y.length && crypto.timingSafeEqual(x,y);
}

function sign(payload){
 return crypto.createHmac("sha256",process.env.HMAC_SECRET)
  .update(payload).digest("hex");
}

async function github(url,options={}){
 const response=await fetch(url,{
  ...options,
  headers:{
   Authorization:`Bearer ${process.env.GITHUB_TOKEN}`,
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

async function saveKey(key,expires){
 for(let i=0;i<5;i++){
  const {file,content}=await readFile();

  const updated=content.replace(/\s*$/,"")+
   `\n${key}|${expires}\n`;

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
   return;
  }catch(error){
   if(!error.message.includes("409") &&
      !error.message.includes("422")) throw error;
  }
 }
 throw new Error("GitHub dosyası güncellenemedi.");
}

module.exports=async function(req,res){
 try{
  if(!process.env.GITHUB_TOKEN)
   return send(res,500,{error:"GITHUB_TOKEN eksik."});

  if(!process.env.HMAC_SECRET ||
     process.env.HMAC_SECRET.length<32)
   return send(res,500,{error:"HMAC_SECRET eksik veya kısa."});

  const url=new URL(req.url,"https://vercel.app");
  const route=url.pathname;

  if(req.method==="POST" && route==="/api/start"){
   const payload=Buffer.from(JSON.stringify({
    created:Date.now(),
    nonce:crypto.randomBytes(32).toString("hex")
   })).toString("base64url");

   return send(res,200,{
    success:true,
    challenge:payload+"."+sign(payload)
   });
  }

  if(req.method==="POST" && route==="/api/generate"){
   const challenge=String(req.body?.challenge||"");
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

   const age=Date.now()-data.created;

   if(age<30000)
    return send(res,429,{error:"30 saniye henüz dolmadı."});

   if(age>600000)
    return send(res,403,{error:"İşlem süresi dolmuş. Yeniden başlat."});

   const key="SCP-"+crypto.randomBytes(16)
    .toString("hex").toUpperCase();

   const expires=Date.now()+86400000;

   await saveKey(key,expires);

   return send(res,200,{success:true,key,expires});
  }

  if(req.method==="POST" && route==="/api/verify"){
   const key=String(req.body?.key||"");

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

