import http from 'node:http';
import { randomBytes, createHash, scryptSync, timingSafeEqual, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
try {
  const envFile=await readFile(path.join(ROOT,'.env'),'utf8');
  for(const line of envFile.split(/\r?\n/)){
    const match=line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if(match&&!Object.hasOwn(process.env,match[1]))process.env[match[1]]=match[2].replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/,'$1$2');
  }
} catch {}
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || (process.env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1');
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const DB_PATH = process.env.DB_PATH || path.join(ROOT, 'data', 'noir.sqlite');
const UPLOADS = process.env.UPLOAD_DIR || path.join(ROOT, 'uploads');
const SESSION_DAYS = 14;
const MAX_BODY = 7 * 1024 * 1024;
const CATEGORIES = new Set(['Верхняя одежда', 'Верх', 'Низ', 'Платья', 'Обувь', 'Аксессуары']);
const CONDITIONS = new Set(['Отличное', 'Хорошее', 'Новое с биркой']);
const loginFailures = new Map();

await mkdir(path.dirname(DB_PATH), { recursive: true });
await mkdir(UPLOADS, { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS listings (
  id INTEGER PRIMARY KEY, seller_id INTEGER NOT NULL REFERENCES users(id),
  name TEXT NOT NULL, category TEXT NOT NULL, price INTEGER NOT NULL,
  condition TEXT NOT NULL, size TEXT NOT NULL, city TEXT NOT NULL,
  image TEXT NOT NULL, description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'available', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS favorites (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, listing_id)
);
CREATE TABLE IF NOT EXISTS threads (
  id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id),
  buyer_id INTEGER NOT NULL REFERENCES users(id), seller_id INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL, UNIQUE(listing_id, buyer_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
  created_at INTEGER NOT NULL, read_at INTEGER
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id),
  buyer_id INTEGER NOT NULL REFERENCES users(id), seller_id INTEGER NOT NULL REFERENCES users(id),
  thread_id INTEGER NOT NULL REFERENCES threads(id), status TEXT NOT NULL DEFAULT 'pending',
  payment_method TEXT NOT NULL DEFAULT 'cash',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id, id);
CREATE INDEX IF NOT EXISTS idx_listings_created ON listings(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);`);

const sha = value => createHash('sha256').update(value).digest('hex');
const safeUser = row => row ? { id: row.id, name: row.name, email: row.email, createdAt: row.created_at } : null;
const getUser = id => db.prepare('SELECT id,name,email,created_at FROM users WHERE id=?').get(id);
const parseCookies = header => Object.fromEntries((header || '').split(';').map(v => v.trim().split(/=(.*)/s)).filter(p => p.length > 1).map(([k, v]) => [k, decodeURIComponent(v)]));
const secureCookie = process.env.NODE_ENV === 'production' ? '; Secure' : '';
const cookie = (token, maxAge=SESSION_DAYS*86400) => `noir_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureCookie}`;
const clientIp = req => TRUST_PROXY && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : (req.socket.remoteAddress||'unknown');

function json(res, status, body, headers={}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', ...headers });
  res.end(payload);
}
function fail(res, status, message) { json(res, status, { error: message }); }
async function body(req) {
  const chunks=[]; let size=0;
  for await (const chunk of req) { size+=chunk.length; if(size>MAX_BODY) throw Object.assign(new Error('Слишком большой запрос'),{status:413}); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw Object.assign(new Error('Некорректный JSON'),{status:400}); }
}
function authenticate(req) {
  const token=parseCookies(req.headers.cookie).noir_session;
  if(!token) return null;
  const session=db.prepare('SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>?').get(sha(token),Date.now());
  return session ? getUser(session.user_id) : null;
}
function originOkay(req) {
  const origin=req.headers.origin;
  if(!origin) return true;
  try { const u=new URL(origin),expected=process.env.SITE_ORIGIN?new URL(process.env.SITE_ORIGIN).origin:`${req.headers['x-forwarded-proto']==='https'?'https':'http'}://${req.headers.host}`; return u.origin===expected && ['http:','https:'].includes(u.protocol); }
  catch { return false; }
}
function cleanText(value, max, field) {
  const text=String(value ?? '').trim();
  if(!text || text.length>max) throw Object.assign(new Error(`${field}: укажи значение до ${max} символов`),{status:400});
  return text;
}
function listingRow(row, userId=null) {
  const result={id:row.id,name:row.name,category:row.category,price:row.price,condition:row.condition,size:row.size,city:row.city,image:row.image,description:row.description,status:row.status,createdAt:row.created_at,seller:{id:row.seller_id,name:row.seller_name}};
  if(userId) result.isFavorite=Boolean(db.prepare('SELECT 1 FROM favorites WHERE user_id=? AND listing_id=?').get(userId,row.id));
  return result;
}
function ensureThread(listing, buyerId) {
  let thread=db.prepare('SELECT * FROM threads WHERE listing_id=? AND buyer_id=?').get(listing.id,buyerId);
  if(!thread){const result=db.prepare('INSERT INTO threads(listing_id,buyer_id,seller_id,created_at) VALUES(?,?,?,?)').run(listing.id,buyerId,listing.seller_id,Date.now());thread=db.prepare('SELECT * FROM threads WHERE id=?').get(Number(result.lastInsertRowid));}
  return thread;
}
function unreadFor(userId) {
  return Number(db.prepare('SELECT count(*) n FROM messages m JOIN threads t ON t.id=m.thread_id WHERE (t.buyer_id=? OR t.seller_id=?) AND m.sender_id!=? AND m.read_at IS NULL').get(userId,userId,userId).n);
}

async function handle(req,res) {
  const url=new URL(req.url,'http://localhost');
  const method=req.method || 'GET';
  const api=url.pathname.startsWith('/api/');
  if(api && !originOkay(req)) return fail(res,403,'Источник запроса не совпадает с сайтом');
  if(method==='GET'&&url.pathname==='/healthz'){try{db.prepare('SELECT 1').get();return json(res,200,{status:'ok'})}catch{return fail(res,503,'Database unavailable')}}
  const user=authenticate(req);
  const requireAuth=()=>{ if(!user){fail(res,401,'Войди в аккаунт, чтобы продолжить');return false} return true; };
  try {
    if(method==='GET' && url.pathname==='/api/session') return json(res,200,{user:safeUser(user),unread:user?unreadFor(user.id):0});
    if(method==='POST' && ['/api/auth/register','/api/auth/login'].includes(url.pathname)){
      const data=await body(req),email=cleanText(data.email,254,'Почта').toLowerCase(),password=String(data.password||'');
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res,400,'Проверь адрес электронной почты');
      if(password.length<10 || password.length>200) return fail(res,400,'Пароль должен быть не короче 10 символов');
      let row;
      if(url.pathname.endsWith('register')){
        const name=cleanText(data.name,60,'Имя');
        if(db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return fail(res,409,'Этот email уже зарегистрирован');
        const salt=randomBytes(16).toString('hex'),hash=scryptSync(password,salt,64).toString('hex');
        try { const out=db.prepare('INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)').run(name,email,`${salt}:${hash}`,Date.now());row=getUser(Number(out.lastInsertRowid)); }
        catch { return fail(res,409,'Не удалось создать аккаунт с этим email'); }
      } else {
        const key=`${clientIp(req)}:${email}`,record=loginFailures.get(key),now=Date.now();
        if(record&&now-record.since<15*60*1000&&record.count>=10)return fail(res,429,'Слишком много попыток входа. Попробуй через 15 минут');
        row=db.prepare('SELECT id,name,email,password_hash,created_at FROM users WHERE email=?').get(email);
        if(!row){const item=record&&now-record.since<15*60*1000?record:{since:now,count:0};item.count++;loginFailures.set(key,item);if(loginFailures.size>10000)for(const [k,v] of loginFailures)if(now-v.since>15*60*1000)loginFailures.delete(k);return fail(res,401,'Неверная почта или пароль');}
        const [salt,expected]=row.password_hash.split(':'),actual=scryptSync(password,salt,64);
        if(!timingSafeEqual(actual,Buffer.from(expected,'hex'))){const item=record&&now-record.since<15*60*1000?record:{since:now,count:0};item.count++;loginFailures.set(key,item);if(loginFailures.size>10000)for(const [k,v] of loginFailures)if(now-v.since>15*60*1000)loginFailures.delete(k);return fail(res,401,'Неверная почта или пароль');}
        loginFailures.delete(key);
      }
      const token=randomBytes(32).toString('base64url'),expires=Date.now()+SESSION_DAYS*86400000;
      db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(token),row.id,expires);
      db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(Date.now());
      return json(res,200,{user:safeUser(row)},{'Set-Cookie':cookie(token)});
    }
    if(method==='POST' && url.pathname==='/api/auth/logout'){
      const token=parseCookies(req.headers.cookie).noir_session;
      if(token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(token));
      return json(res,200,{ok:true},{'Set-Cookie':cookie('',0)});
    }
    if(method==='GET' && url.pathname==='/api/listings'){
      const q=(url.searchParams.get('q')||'').slice(0,100),category=url.searchParams.get('category'),condition=url.searchParams.get('condition'),max=Number(url.searchParams.get('max'));
      const where=['l.status IN (\'available\',\'reserved\')'],args=[];
      if(q){where.push('(l.name LIKE ? OR l.description LIKE ? OR l.city LIKE ?)');args.push(`%${q}%`,`%${q}%`,`%${q}%`)}
      if(category&&CATEGORIES.has(category)){where.push('l.category=?');args.push(category)}
      if(condition&&CONDITIONS.has(condition)){where.push('l.condition=?');args.push(condition)}
      if(Number.isFinite(max)&&max>0){where.push('l.price<=?');args.push(max)}
      const order=url.searchParams.get('sort')==='low'?'l.price ASC,l.created_at DESC':url.searchParams.get('sort')==='high'?'l.price DESC,l.created_at DESC':'l.created_at DESC';
      const rows=db.prepare(`SELECT l.*,u.name seller_name FROM listings l JOIN users u ON u.id=l.seller_id WHERE ${where.join(' AND ')} ORDER BY ${order}`).all(...args);
      return json(res,200,{listings:rows.map(r=>listingRow(r,user?.id))});
    }
    if(method==='POST' && url.pathname==='/api/listings'){
      if(!requireAuth()) return;
      const d=await body(req),name=cleanText(d.name,80,'Название'),category=cleanText(d.category,40,'Категория'),condition=cleanText(d.condition,30,'Состояние'),size=cleanText(d.size,25,'Размер'),city=cleanText(d.city,60,'Город'),description=cleanText(d.description,1200,'Описание');
      const price=Number(d.price);
      if(!CATEGORIES.has(category)||!CONDITIONS.has(condition)) return fail(res,400,'Выбери допустимые категорию и состояние');
      if(!Number.isSafeInteger(price)||price<1||price>100000000) return fail(res,400,'Укажи корректную цену');
      const image=cleanText(d.image,500,'Фотография');
      if(!image.startsWith('/uploads/')&&!/^https:\/\//i.test(image)) return fail(res,400,'Фото должно быть загружено или иметь HTTPS-ссылку');
      const out=db.prepare('INSERT INTO listings(seller_id,name,category,price,condition,size,city,image,description,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(user.id,name,category,price,condition,size,city,image,description,Date.now());
      return json(res,201,{id:Number(out.lastInsertRowid)});
    }
    const deleteMatch=url.pathname.match(/^\/api\/listings\/(\d+)$/);
    if(method==='DELETE'&&deleteMatch){if(!requireAuth())return;const id=Number(deleteMatch[1]),row=db.prepare('SELECT seller_id FROM listings WHERE id=?').get(id);if(!row)return fail(res,404,'Объявление не найдено');if(row.seller_id!==user.id)return fail(res,403,'Удалить объявление может только продавец');if(db.prepare('SELECT 1 FROM orders WHERE listing_id=? UNION SELECT 1 FROM threads WHERE listing_id=? LIMIT 1').get(id,id))return fail(res,409,'У объявления уже есть заказы или переписка, поэтому его нельзя удалить');db.prepare('DELETE FROM listings WHERE id=?').run(id);return json(res,200,{ok:true})}
    const favoriteMatch=url.pathname.match(/^\/api\/favorites\/(\d+)$/);
    if(method==='GET'&&url.pathname==='/api/favorites'){if(!requireAuth())return;const rows=db.prepare('SELECT listing_id FROM favorites WHERE user_id=?').all(user.id);return json(res,200,{ids:rows.map(x=>x.listing_id)})}
    if(method==='POST'&&favoriteMatch){if(!requireAuth())return;const id=Number(favoriteMatch[1]);if(!db.prepare('SELECT 1 FROM listings WHERE id=?').get(id))return fail(res,404,'Объявление не найдено');const found=db.prepare('SELECT 1 FROM favorites WHERE user_id=? AND listing_id=?').get(user.id,id);if(found)db.prepare('DELETE FROM favorites WHERE user_id=? AND listing_id=?').run(user.id,id);else db.prepare('INSERT INTO favorites(user_id,listing_id) VALUES(?,?)').run(user.id,id);return json(res,200,{favorite:!found})}
    if(method==='POST'&&url.pathname==='/api/upload'){
      if(!requireAuth())return;const d=await body(req),match=String(d.data||'').match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/);if(!match)return fail(res,400,'Поддерживаются JPG, PNG и WebP');const bytes=Buffer.from(match[2],'base64');if(bytes.length>5*1024*1024)return fail(res,413,'Файл должен быть меньше 5 МБ');const valid=match[1]==='image/jpeg'?bytes.length>3&&bytes[0]===0xff&&bytes[1]===0xd8&&bytes[2]===0xff:match[1]==='image/png'?bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):bytes.length>12&&bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP';if(!valid)return fail(res,400,'Содержимое файла не совпадает с форматом изображения');const ext={'image/jpeg':'jpg','image/png':'png','image/webp':'webp'}[match[1]],name=`${randomUUID()}.${ext}`;await writeFile(path.join(UPLOADS,name),bytes,{flag:'wx'});return json(res,201,{url:`/uploads/${name}`});
    }
    if(method==='GET'&&url.pathname==='/api/threads'){
      if(!requireAuth())return;const rows=db.prepare(`SELECT t.id,t.listing_id,t.buyer_id,t.seller_id,t.created_at,l.name listing_name,l.image listing_image,CASE WHEN t.buyer_id=? THEN s.name ELSE b.name END other_name,CASE WHEN t.buyer_id=? THEN s.id ELSE b.id END other_id,(SELECT body FROM messages WHERE thread_id=t.id ORDER BY id DESC LIMIT 1) last_message,(SELECT created_at FROM messages WHERE thread_id=t.id ORDER BY id DESC LIMIT 1) last_at,(SELECT count(*) FROM messages WHERE thread_id=t.id AND sender_id!=? AND read_at IS NULL) unread FROM threads t JOIN listings l ON l.id=t.listing_id JOIN users s ON s.id=t.seller_id JOIN users b ON b.id=t.buyer_id WHERE t.buyer_id=? OR t.seller_id=? ORDER BY coalesce(last_at,t.created_at) DESC`).all(user?.id,user?.id,user?.id,user?.id,user?.id);return json(res,200,{threads:rows});
    }
    if(method==='POST'&&url.pathname==='/api/threads'){
      if(!requireAuth())return;const d=await body(req),listing=db.prepare('SELECT * FROM listings WHERE id=?').get(Number(d.listingId));if(!listing)return fail(res,404,'Объявление не найдено');if(listing.seller_id===user.id)return fail(res,400,'Нельзя начать переписку с самим собой');const thread=ensureThread(listing,user.id),text=String(d.text||'').trim(),hasMessages=db.prepare('SELECT 1 FROM messages WHERE thread_id=? LIMIT 1').get(thread.id);if(text&&!hasMessages){if(text.length>2000)return fail(res,400,'Сообщение слишком длинное');db.prepare('INSERT INTO messages(thread_id,sender_id,body,created_at) VALUES(?,?,?,?)').run(thread.id,user.id,text,Date.now())}return json(res,201,{threadId:thread.id});
    }
    const threadMessages=url.pathname.match(/^\/api\/threads\/(\d+)\/messages$/);
    if(threadMessages&&method==='GET'){
      if(!requireAuth())return;const id=Number(threadMessages[1]),thread=db.prepare('SELECT * FROM threads WHERE id=? AND (buyer_id=? OR seller_id=?)').get(id,user.id,user.id);if(!thread)return fail(res,404,'Переписка не найдена');db.prepare('UPDATE messages SET read_at=? WHERE thread_id=? AND sender_id!=? AND read_at IS NULL').run(Date.now(),id,user.id);const after=Number(url.searchParams.get('after')||0),messages=db.prepare('SELECT m.id,m.sender_id senderId,u.name senderName,m.body,m.created_at createdAt FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.thread_id=? AND m.id>? ORDER BY m.id').all(id,after);return json(res,200,{messages});
    }
    if(threadMessages&&method==='POST'){
      if(!requireAuth())return;const id=Number(threadMessages[1]),thread=db.prepare('SELECT * FROM threads WHERE id=? AND (buyer_id=? OR seller_id=?)').get(id,user.id,user.id);if(!thread)return fail(res,404,'Переписка не найдена');const d=await body(req),text=cleanText(d.text,2000,'Сообщение');const result=db.prepare('INSERT INTO messages(thread_id,sender_id,body,created_at) VALUES(?,?,?,?)').run(id,user.id,text,Date.now());return json(res,201,{id:Number(result.lastInsertRowid)});
    }
    if(method==='POST'&&url.pathname==='/api/orders'){
      if(!requireAuth())return;const d=await body(req),listing=db.prepare('SELECT * FROM listings WHERE id=?').get(Number(d.listingId));if(!listing)return fail(res,404,'Объявление не найдено');if(listing.seller_id===user.id)return fail(res,400,'Нельзя заказать собственное объявление');if(listing.status!=='available')return fail(res,409,'Эта вещь уже зарезервирована или продана');const paymentMethod=d.paymentMethod||'cash';if(paymentMethod==='online')return fail(res,503,'Онлайн-оплата пока не настроена: владельцу сайта нужно подключить договор и реквизиты платёжного провайдера');if(paymentMethod!=='cash')return fail(res,400,'Неизвестный способ оплаты');
      const thread=ensureThread(listing,user.id),now=Date.now();db.exec('BEGIN IMMEDIATE');try{const out=db.prepare('INSERT INTO orders(listing_id,buyer_id,seller_id,thread_id,payment_method,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run(listing.id,user.id,listing.seller_id,thread.id,paymentMethod,now,now);db.prepare("UPDATE listings SET status='reserved' WHERE id=?").run(listing.id);const note=`Покупатель хочет купить «${listing.name}» за ${listing.price} ₽ с оплатой наличными при встрече. Обсудите в чате способ передачи.`;db.prepare('INSERT INTO messages(thread_id,sender_id,body,created_at) VALUES(?,?,?,?)').run(thread.id,user.id,note,now);db.exec('COMMIT');return json(res,201,{orderId:Number(out.lastInsertRowid),threadId:thread.id});}catch(err){db.exec('ROLLBACK');throw err}
    }
    const orderMatch=url.pathname.match(/^\/api\/orders\/(\d+)$/);
    if(orderMatch&&method==='PATCH'){
      if(!requireAuth())return;const id=Number(orderMatch[1]),order=db.prepare('SELECT * FROM orders WHERE id=?').get(id);if(!order)return fail(res,404,'Заказ не найден');const d=await body(req),status=String(d.status);if(status==='accepted'||status==='declined'){if(order.seller_id!==user.id||order.status!=='pending')return fail(res,403,'Недоступное действие');db.exec('BEGIN IMMEDIATE');try{db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run(status,Date.now(),id);db.prepare("UPDATE listings SET status=? WHERE id=?").run(status==='accepted'?'sold':'available',order.listing_id);db.prepare('INSERT INTO messages(thread_id,sender_id,body,created_at) VALUES(?,?,?,?)').run(order.thread_id,user.id,status==='accepted'?'Продавец подтвердил заказ. Напишите в чате, чтобы договориться о передаче вещи и оплате.':'Продавец отклонил заказ; вещь снова доступна.',Date.now());db.exec('COMMIT');}catch(err){db.exec('ROLLBACK');throw err}}else if(status==='cancelled'){if(order.buyer_id!==user.id||order.status!=='pending')return fail(res,403,'Недоступное действие');db.exec('BEGIN IMMEDIATE');try{db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run(status,Date.now(),id);db.prepare("UPDATE listings SET status='available' WHERE id=?").run(order.listing_id);db.prepare('INSERT INTO messages(thread_id,sender_id,body,created_at) VALUES(?,?,?,?)').run(order.thread_id,user.id,'Покупатель отменил запрос на покупку. Вещь снова доступна.',Date.now());db.exec('COMMIT')}catch(err){db.exec('ROLLBACK');throw err}}else return fail(res,400,'Недопустимый статус');return json(res,200,{ok:true});
    }
    if(method==='GET'&&url.pathname==='/api/orders'){
      if(!requireAuth())return;const rows=db.prepare(`SELECT o.*,l.name listing_name,l.price,l.image,CASE WHEN o.buyer_id=? THEN s.name ELSE b.name END other_name FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users s ON s.id=o.seller_id JOIN users b ON b.id=o.buyer_id WHERE o.buyer_id=? OR o.seller_id=? ORDER BY o.created_at DESC`).all(user.id,user.id,user.id);return json(res,200,{orders:rows});
    }
    if(api) return fail(res,404,'Маршрут не найден');
    if(method==='GET'&&url.pathname.startsWith('/uploads/')){
      const name=path.basename(url.pathname),target=path.join(UPLOADS,name);if(name!==url.pathname.slice('/uploads/'.length)||!/^[-\w]+\.(?:jpg|png|webp)$/.test(name))return fail(res,404,'Файл не найден');try{const data=await readFile(target),type=name.endsWith('.png')?'image/png':name.endsWith('.webp')?'image/webp':'image/jpeg';res.writeHead(200,{'Content-Type':type,'Cache-Control':'public, max-age=31536000, immutable','X-Content-Type-Options':'nosniff'});return res.end(data)}catch{return fail(res,404,'Файл не найден')}
    }
    if(method==='GET'&&['/app.js','/styles.css'].includes(url.pathname)){
      const name=url.pathname.slice(1),content=await readFile(path.join(ROOT,name));res.writeHead(200,{'Content-Type':name.endsWith('.js')?'text/javascript; charset=utf-8':'text/css; charset=utf-8','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff'});return res.end(content);
    }
    if(method==='GET'&&['/','/noir-store.html'].includes(url.pathname)){
      const html=await readFile(path.join(ROOT,'noir-store.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; img-src 'self' https: data:; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"});return res.end(html);
    }
    return fail(res,404,'Страница не найдена');
  } catch(error) { console.error(error);return fail(res,error.status||500,error.status?error.message:'Внутренняя ошибка сервера'); }
}

const server=http.createServer((req,res)=>{handle(req,res).catch(err=>{console.error(err);if(!res.headersSent)fail(res,500,'Внутренняя ошибка сервера');else res.destroy()})});
server.headersTimeout=10000;
server.requestTimeout=30000;
server.listen(PORT,HOST,()=>console.log(`NOIR Market: http://${HOST}:${PORT}`));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{server.close(()=>{db.close();process.exit(0)})});
