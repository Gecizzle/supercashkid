import http from 'node:http';

const port = Number(process.env.PORT || 10000);
const key = process.env.BREVO_API_KEY;
const allowed = new Set(['https://supercashkid.onrender.com','https://supercashkid.com','https://www.supercashkid.com']);
const reply = (res,code,obj,origin) => {
  res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store',...(allowed.has(origin)?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{})});
  res.end(JSON.stringify(obj));
};
http.createServer(async (req,res)=>{
  const origin = req.headers.origin || '';
  if(req.url==='/health') return reply(res,200,{ok:true},origin);
  if(req.url!=='/subscribe') return reply(res,404,{error:'Not found'},origin);
  if(!allowed.has(origin)) return reply(res,403,{error:'Origin not allowed'},origin);
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'600'});return res.end();}
  if(req.method!=='POST') return reply(res,405,{error:'Method not allowed'},origin);
  let body='';
  try{
    for await(const chunk of req){body+=chunk;if(body.length>4096)throw Error('Too large');}
    const data=JSON.parse(body);
    const email=String(data.email||'').trim().toLowerCase();
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254) return reply(res,400,{error:'Enter a valid email address.'},origin);
    if(!key) return reply(res,503,{error:'Signup is being configured. Please try again later.'},origin);
    const attributes={};
    const payload={email,updateEnabled:true};
    if(data.marketing===true){payload.listIds=process.env.BREVO_LIST_ID? [Number(process.env.BREVO_LIST_ID)] : undefined;}
    const response=await fetch('https://api.brevo.com/v3/contacts',{method:'POST',headers:{'api-key':key,'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if(!response.ok){console.error('Brevo contact API failed',response.status);return reply(res,502,{error:'Could not complete signup. Please try again.'},origin);}
    return reply(res,200,{ok:true,message:'You’re signed up! Your free kit will be available soon.'},origin);
  }catch(err){return reply(res,400,{error:'Could not process signup.'},origin);}
}).listen(port,'0.0.0.0',()=>console.log('Signup API listening'));
