import http from 'node:http';
import { createHmac, timingSafeEqual, createDecipheriv } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const port = Number(process.env.PORT || 10000);
const key = process.env.BREVO_API_KEY;
const allowed = new Set(['https://supercashkid.onrender.com','https://supercashkid.com','https://www.supercashkid.com']);
const reply = (res,code,obj,origin) => {
  res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store',...(allowed.has(origin)?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{})});
  res.end(JSON.stringify(obj));
};
const readBody = async (req,maxBytes) => {
  const chunks=[];let bytes=0;
  for await(const chunk of req){bytes+=chunk.length;if(bytes>maxBytes)throw Error('Body too large');chunks.push(chunk);}
  return Buffer.concat(chunks);
};
const verifyStripe = (raw,header,secret) => {
  if(!header||!secret)return false;
  const parts=Object.fromEntries(header.split(',').map(x=>x.trim().split('=',2)));
  const timestamp=Number(parts.t);
  if(!Number.isFinite(timestamp)||Math.abs(Date.now()/1000-timestamp)>300)return false;
  const expected=createHmac('sha256',secret).update(String(timestamp)+'.').update(raw).digest('hex');
  return header.split(',').some(x=>{
    const value=x.trim();
    if(!value.startsWith('v1='))return false;
    const candidate=value.slice(3);
    if(!/^[0-9a-f]{64}$/.test(candidate))return false;
    return timingSafeEqual(Buffer.from(candidate,'hex'),Buffer.from(expected,'hex'));
  });
};
const processed=new Set();
const deliverBlueprint=async(event,liveSignature,testSignature,res,origin)=>{
    if(event.type!=='checkout.session.completed')return reply(res,200,{received:true},origin);
    const session=event.data?.object||{};
    if(session.payment_status!=='paid')return reply(res,200,{received:true,paid:false},origin);
    if(session.mode!=='payment'||![499,2999].includes(session.amount_total)||String(session.currency).toLowerCase()!=='usd')return reply(res,200,{received:true,matchingProduct:false},origin);
    // Configure STRIPE_PAYMENT_LINK_ID to prevent unrelated $29.99 payments triggering delivery.
    const expectedLink=liveSignature?process.env.STRIPE_PAYMENT_LINK_ID:process.env.STRIPE_TEST_PAYMENT_LINK_ID;
    const newBlueprintLink='plink_1UTukDE2tA36niJtdIYxbeHk';
    const matchesNewLink=session.amount_total===499&&((liveSignature&&session.payment_link===newBlueprintLink)||(testSignature&&session.payment_link==='plink_1UTvNKE3PpUqj1X65KVRfEVy'));
    const matchesLegacyLink=!!expectedLink&&session.amount_total===2999&&session.payment_link===expectedLink;
    if(!matchesNewLink&&!matchesLegacyLink)return reply(res,200,{received:true,matchingLink:false},origin);
    if(processed.has(event.id))return reply(res,200,{received:true,duplicate:true},origin);
    const email=session.customer_details?.email||session.customer_email;
    let pdf;
    try {
      const encrypted=Buffer.from((await readFile(new URL('./blueprint.encrypted.b64',import.meta.url),'utf8')).trim(),'base64');
      const encryptionKey=Buffer.from(process.env.BLUEPRINT_DECRYPTION_KEY||'','hex');
      if(encryptionKey.length!==32||encrypted.length<29)throw Error('Missing Blueprint encryption configuration');
      const nonce=encrypted.subarray(0,12);
      const tag=encrypted.subarray(encrypted.length-16);
      const ciphertext=encrypted.subarray(12,encrypted.length-16);
      const decipher=createDecipheriv('aes-256-gcm',encryptionKey,nonce);
      decipher.setAuthTag(tag);
      pdf=Buffer.concat([decipher.update(ciphertext),decipher.final()]).toString('base64');
    }catch(err){console.error('Blueprint decryption unavailable',err?.message);return reply(res,503,{error:'Delivery unavailable'},origin);}
    const sender=process.env.BREVO_SENDER_EMAIL;
    if(!key||!pdf||!sender||!email){console.error('Blueprint delivery configuration missing');return reply(res,503,{error:'Delivery unavailable'},origin);}
    try{
      const response=await fetch('https://api.brevo.com/v3/smtp/email',{
        method:'POST',headers:{'api-key':key,'Content-Type':'application/json'},
        body:JSON.stringify({
          sender:{email:sender,name:'Super Cash Kid'},
          to:[{email}],subject:'Your Super Cash Kid Business Launch Blueprint',
          htmlContent:'<p>Thanks for your purchase!</p><p>Your Business Launch Blueprint PDF is attached to this email.</p><p>— Super Cash Kid</p>',
          attachment:[{name:'Super_Cash_Kid_Business_Launch_Blueprint.pdf',content:pdf}]
        })
      });
      if(!response.ok){console.error('Blueprint email failed',response.status);return reply(res,502,{error:'Delivery failed'},origin);}
      processed.add(event.id);
      if(processed.size>10000)processed.clear();
      return reply(res,200,{received:true},origin);
    }catch(err){console.error('Blueprint email error',err?.message);return reply(res,502,{error:'Delivery failed'},origin);}
};
http.createServer(async (req,res)=>{
  const origin = req.headers.origin || '';
  if(req.method==='OPTIONS' && req.url==='/admin/retry-blueprint'){
    if(!allowed.has(origin))return reply(res,403,{error:'Origin not allowed'},origin);
    res.writeHead(204,{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Max-Age':'600','Vary':'Origin'});
    return res.end();
  }
  if(req.url==='/health') return reply(res,200,{ok:true},origin);
  if(req.url==='/stripe/webhook'){
    if(req.method!=='POST')return reply(res,405,{error:'Method not allowed'},origin);
    let raw;
    try{raw=await readBody(req,1024*1024);}catch{return reply(res,413,{error:'Too large'},origin);}
    const liveSignature=verifyStripe(raw,req.headers['stripe-signature'],process.env.STRIPE_WEBHOOK_SECRET);
    const testSignature=verifyStripe(raw,req.headers['stripe-signature'],process.env.STRIPE_TEST_WEBHOOK_SECRET);
    if(!liveSignature&&!testSignature)return reply(res,400,{error:'Invalid signature'},origin);
    let event;
    try{event=JSON.parse(raw.toString('utf8'));}catch{return reply(res,400,{error:'Invalid JSON'},origin);}
    return deliverBlueprint(event,liveSignature,testSignature,res,origin);
  }
  if(req.url==='/admin/retry-blueprint') {
    if(req.method!=='POST')return reply(res,405,{error:'Method not allowed'},origin);
    const configured=process.env.BLUEPRINT_RETRY_ADMIN_KEY||'';
    const supplied=String(req.headers.authorization||'').replace(/^Bearer /i,'');
    if(configured.length<32||supplied.length!==configured.length||!timingSafeEqual(Buffer.from(configured),Buffer.from(supplied)))return reply(res,401,{error:'Unauthorized'},origin);
    let data;
    try{data=JSON.parse((await readBody(req,4096)).toString('utf8'));}catch{return reply(res,400,{error:'Invalid request'},origin);}
    const id=String(data.sessionId||'');
    if(!/^cs_test_[A-Za-z0-9_]+$/.test(id))return reply(res,400,{error:'Invalid sandbox session'},origin);
    const stripeKey=process.env.STRIPE_TEST_SECRET_KEY;
    if(!stripeKey)return reply(res,503,{error:'Stripe test API key not configured'},origin);
    let session;
    try{
      const response=await fetch('https://api.stripe.com/v1/checkout/sessions/'+encodeURIComponent(id),{headers:{Authorization:'Bearer '+stripeKey}});
      if(!response.ok){console.error('Retry Stripe verification failed',response.status);return reply(res,502,{error:'Could not verify purchase'},origin);}
      session=await response.json();
    }catch(err){console.error('Retry Stripe lookup error',err?.message);return reply(res,502,{error:'Could not verify purchase'},origin);}
    if(session.livemode!==false||session.payment_status!=='paid'||session.mode!=='payment'||session.amount_total!==499||session.currency!=='usd'||session.payment_link!=='plink_1UTvNKE3PpUqj1X65KVRfEVy')return reply(res,403,{error:'Not an eligible paid sandbox purchase'},origin);
    const event={id:'retry:'+session.id,type:'checkout.session.completed',data:{object:session}};
    return deliverBlueprint(event,false,true,res,origin);
  }
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
    // Contact storage is intentionally disabled. Google identity verification happens
    // on the frontend; this endpoint only acknowledges the optional signup step.
    // Do not imply that name, phone, or email was saved or subscribed.
    return reply(res,200,{ok:true,message:'Google verification complete. You can access your free Starter Kit.'},origin);
  }catch(err){return reply(res,400,{error:'Could not process signup.'},origin);}
}).listen(port,'0.0.0.0',()=>console.log('Signup API listening'));

