"""NEURO local web interface. Uses TG BOTE's identity and indicator engine."""
import asyncio, hashlib, json, math, os, secrets, sqlite3, sys, time
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from aiohttp import web

ROOT = Path(__file__).resolve().parent
BOT = Path(os.environ.get('NEURO_BOT_DIR', 'D:/TG BOTE'))
DB = Path(os.environ.get('NEURO_BOT_DB', str(BOT / 'data/bot.sqlite3')))
LOCAL = Path(os.environ.get('NEURO_WEB_DB', str(ROOT / 'data/web.sqlite3')))
PORT = int(os.environ.get('NEURO_PORT','8765'))
# Only the exact configured HTTPS origin may enter through a local reverse proxy.
def parse_public_origin(value):
    value=value.strip().rstrip('/')
    if not value:return '', ''
    parsed=urlsplit(value)
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or parsed.port not in (None,443)
            or any(c.isspace() for c in value) or '*' in value):
        raise ValueError('NEURO_PUBLIC_ORIGIN must be an exact HTTPS origin without a path')
    return value,parsed.netloc
PUBLIC_ORIGIN,PUBLIC_HOST=parse_public_origin(os.environ.get('NEURO_PUBLIC_ORIGIN',''))
LOCAL_HOSTS=(f'127.0.0.1:{PORT}',f'localhost:{PORT}')
sys.path.insert(0, str(BOT))
from bot.security import hash_password, verify_password, valid_login, actor_id
from bot.models import ChatSettings, EXCHANGES, TIMEFRAMES
from bot.storage import SettingsStore
from bot.services.market import MarketGateway
from bot.services.indicators import enrich_indicators, decide_signals, required_history
from bot.services.timeframes import select_candles
import pandas as pd

@contextmanager
def database(path=DB):
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        with conn: yield conn
    finally: conn.close()

def fail(message, status=400):
    raise ApiError(message,status)

class ApiError(Exception):
    def __init__(self,message,status=400): self.message,self.status=message,status

def rows(query,args=()):
    with database() as db: return [dict(r) for r in db.execute(query,args)]

def user_for_token(token):
    if not token: return None
    with database(LOCAL) as db:
        session=db.execute('SELECT * FROM sessions WHERE token=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
    if not session: return None
    user=rows('SELECT user_id,login,display_name,role,blocked,locked,login_chosen,password_hash,updated FROM users WHERE user_id=?',(session['user_id'],))
    if not user: return None
    user=user[0]
    if user['blocked'] or user['locked'] or not user['login_chosen'] or hashlib.sha256(user['password_hash'].encode()).hexdigest()!=session['fingerprint']: return None
    user.pop('password_hash');return user

attempts=defaultdict(deque)
def throttle(key,limit=10):
    now=time.time(); q=attempts[key]
    while q and q[0]<now-300:q.popleft()
    if len(q)>=limit: fail('Слишком много попыток. Повторите через 5 минут.',429)
    q.append(now)
    if len(attempts)>5000:
        for old in list(attempts):
            if not attempts[old] or attempts[old][-1]<now-300: attempts.pop(old,None)

@web.middleware
async def security(request,handler):
    try:
        public=bool(PUBLIC_HOST and request.host==PUBLIC_HOST)
        if request.host not in LOCAL_HOSTS and not public:fail('Недопустимый адрес сервера',403)
        if public and (request.remote not in ('127.0.0.1','::1') or request.headers.get('X-Forwarded-Proto')!='https'):
            fail('Требуется защищённое HTTPS-подключение',403)
        expected_origin=PUBLIC_ORIGIN if public else 'http://'+request.host
        if request.method not in ('GET','HEAD','OPTIONS'):
            if request.headers.get('Origin')!=expected_origin:fail('Недопустимый источник запроса',403)
            if request.content_type!='application/json':fail('Ожидается JSON',415)
        if request.path.startswith('/api/') and request.path not in ('/api/login','/api/register','/api/health'):
            user=await asyncio.to_thread(user_for_token,request.cookies.get('neuro_session'))
            if not user:fail('Войдите в аккаунт',401)
            request['user']=user
        response=await handler(request)
    except ApiError as error:response=web.json_response({'error':error.message},status=error.status)
    except (ValueError,TypeError,KeyError,json.JSONDecodeError):response=web.json_response({'error':'Проверьте введённые значения.'},status=400)
    except web.HTTPException:raise
    except Exception as error:
        print('Request failed:',type(error).__name__,flush=True)
        response=web.json_response({'error':'Сервис временно недоступен. Попробуйте ещё раз.'},status=503)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
    if PUBLIC_HOST and request.host==PUBLIC_HOST:
        response.headers['Strict-Transport-Security']='max-age=86400'
    return response

def public_user(user):return {k:user[k] for k in ('user_id','login','display_name','role')}

def session_response(user):
    token=secrets.token_urlsafe(48)
    with database(LOCAL) as db:
        db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['user_id'],time.time()+43200,hashlib.sha256(user['password_hash'].encode()).hexdigest()))
    response=web.json_response(public_user(user))
    response.set_cookie('neuro_session',token,max_age=43200,httponly=True,secure=bool(PUBLIC_ORIGIN),samesite='Strict',path='/')
    return response

async def login(request):
    throttle(('ip',request.remote)); data=await request.json(); login=str(data.get('login','')).strip();password=str(data.get('password',''))
    throttle(('login',login.lower()))
    found=await asyncio.to_thread(rows,'SELECT * FROM users WHERE login=? COLLATE NOCASE',(login,))
    user=found[0] if found else None
    encoded=user['password_hash'] if user else 'scrypt$16384$8$1$'+'00'*16+'$'+'00'*32
    ok=await asyncio.to_thread(verify_password,password,encoded)
    if not ok or not user or user['blocked'] or user['locked'] or not user['login_chosen'] or user['retry_after']>time.time():fail('Неверный логин или пароль, либо аккаунт заблокирован.',401)
    return session_response(user)

async def register(request):
    throttle(('register',request.remote),5);data=await request.json();login=str(data.get('login','')).strip();password=str(data.get('password',''))
    if not valid_login(login) or login.lower().startswith('tg_'):fail('Логин: 3–32 латинских символа, цифры или _. Префикс tg_ зарезервирован.')
    if not 10<=len(password)<=128:fail('Пароль должен содержать от 10 до 128 символов.')
    encoded=await asyncio.to_thread(hash_password,password)
    def create():
        with database() as db:
            db.execute('BEGIN IMMEDIATE')
            uid=-(secrets.randbelow(2**50)+1000000);now=time.time()
            try:db.execute('INSERT INTO users(user_id,login,display_name,password_hash,role,login_chosen,created,updated) VALUES(?,?,?,?,?,?,?,?)',(uid,login,login,encoded,'user',1,now,now))
            except sqlite3.IntegrityError:fail('Этот логин уже занят.',409)
            db.execute('INSERT INTO audit(actor,target,action,detail,created) VALUES(?,?,?,?,?)',(uid,uid,'web.register','{}',now))
        return rows('SELECT * FROM users WHERE user_id=?',(uid,))[0]
    return session_response(await asyncio.to_thread(create))

async def logout(request):
    token=request.cookies.get('neuro_session','')
    with database(LOCAL) as db:db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(token.encode()).hexdigest(),))
    r=web.json_response({'ok':True});r.del_cookie('neuro_session');return r

async def health(request):
    count=await asyncio.to_thread(rows,'SELECT count(*) AS count, max(updated) AS updated FROM markets')
    return web.json_response({'ok':True,'markets':count[0]['count'],'catalog_updated':count[0]['updated']})

async def me(request):return web.json_response(public_user(request['user']))

async def catalog(request):
    exchange=request.query.get('exchange','bybit');query=request.query.get('q','')[:64];category=request.query.get('category','');kind=request.query.get('type','swap')
    if exchange not in EXCHANGES:fail('Неизвестная биржа')
    sql=' FROM markets WHERE exchange=? AND symbol LIKE ?';args=[exchange,'%'+query+'%']
    if category:sql+=' AND category=?';args.append(category)
    if kind:sql+=" AND json_extract(payload,'$.type')=?";args.append(kind)
    result=rows('SELECT payload,updated'+sql+' ORDER BY CASE WHEN symbol LIKE \'BTC/%\' THEN 0 WHEN symbol LIKE \'ETH/%\' THEN 1 WHEN symbol LIKE \'SOL/%\' THEN 2 ELSE 3 END,symbol LIMIT 250',args)
    return web.json_response({'items':[{**json.loads(r['payload']),'updated':r['updated']} for r in result],'total':rows('SELECT COUNT(*) AS n'+sql,args)[0]['n']})

def market_from(data):
    found=rows('SELECT payload FROM markets WHERE exchange=? AND symbol=?',(data.get('exchange'),data.get('symbol')))
    if not found:fail('Инструмент не найден')
    return json.loads(found[0]['payload'])

async def settings(request):
    uid=request['user']['user_id'];store=request.app['store']
    if request.method=='GET':return web.json_response((await store.get(uid)).to_dict())
    data=await request.json(); previous=await store.get(uid)
    allowed={'exchanges','categories','market_types','quotes','timeframes','indicators','rsi_periods','rsi_low','rsi_high','ema_periods','kdj_period','kdj_smooth','combination','direction','candle_mode','active','watchlist_only','charts_enabled','delivery_mode'}
    if set(data)-allowed:fail('Неизвестная настройка')
    for name in ('active','watchlist_only','charts_enabled'):
        if name in data and type(data[name]) is not bool:fail('Неверное значение переключателя')
    if uid<0 and data.get('active'):fail('Для фоновой отправки сначала войдите этим аккаунтом в Telegram-бота.')
    new=ChatSettings.from_dict({**previous.to_dict(),**data})
    if required_history(new)>1000:fail('Для веб-скринера период индикатора должен быть не больше 998.')
    token=actor_id.set(uid)
    try:await store.save(uid,new)
    finally:actor_id.reset(token)
    return web.json_response(new.to_dict())

async def watchlist(request):
    uid=request['user']['user_id'];store=request.app['store']
    if request.method=='POST':await store.add_watch(uid,market_from(await request.json()))
    if request.method=='DELETE':await store.remove_watch(uid,int(request.match_info['id']))
    return web.json_response([{'id':key,**m} for key,m in await store.watch_items(uid)])

async def alerts(request):
    uid=request['user']['user_id'];store=request.app['store']
    if request.method=='POST':
        if uid<0:fail('Для доставки алертов войдите этим аккаунтом в Telegram-бота.')
        d=await request.json();price=float(d['price'])
        if not math.isfinite(price) or price<=0:fail('Цена должна быть положительным числом')
        try:await store.add_alert(uid,market_from(d),d['comparator'],price,False,str(d.get('note',''))[:1000])
        except ValueError as e:fail('Достигнут лимит активных алертов.' if str(e)=='alert_limit' else 'Проверьте параметры алерта')
    if request.method=='DELETE':await store.delete_alert(uid,int(request.match_info['id']))
    return web.json_response(await store.alerts(uid))

async def history(request):
    uid=request['user']['user_id']
    # Explicit allowlists prevent credentials, account identifiers and encrypted payloads leaking.
    signals=[]
    key=DB.parent/'private/credentials.key'
    if key.exists():
        from cryptography.fernet import Fernet, InvalidToken
        cipher=Fernet(key.read_bytes())
        for row in rows('SELECT payload,created FROM signal_details WHERE chat_id=? ORDER BY created DESC LIMIT 80',(uid,)):
            try:
                p=json.loads(cipher.decrypt(row['payload'].encode()).decode())
                signals.append({k:p.get(k) for k in ('market','timeframe','direction','reason')}|{'created':row['created']})
            except (InvalidToken,ValueError):continue
    return web.json_response({'signals':signals,'runs':rows('SELECT started,finished,summary FROM scan_runs WHERE chat_id=? ORDER BY id DESC LIMIT 10',(uid,)), 'orders':rows('SELECT exchange,state,created FROM trading_jobs WHERE chat_id=? ORDER BY created DESC LIMIT 30',(uid,)), 'tracking':rows('SELECT exchange,state,updated FROM position_tracking WHERE chat_id=? ORDER BY updated DESC LIMIT 30',(uid,)), 'accounts':rows('SELECT exchange,enabled FROM trading_accounts WHERE chat_id=?',(uid,))})

async def candles(request):
    m=market_from(request.query);tf=request.query.get('timeframe','1h')
    if tf not in TIMEFRAMES:fail('Неизвестный таймфрейм')
    throttle(('chart',request['user']['user_id']),100)
    settings_=await request.app['store'].get(request['user']['user_id'])
    needed=max(160,required_history(settings_)+20)
    if needed>1020:fail('Периоды индикаторов слишком велики для веб-графика')
    gateway=request.app['gateway'];key=(m['exchange'],m['symbol'],tf,needed)
    async with request.app['locks'].setdefault(key,asyncio.Lock()):
        cached=request.app['cache'].get(key)
        if cached and time.time()-cached[0]<30:frame=cached[1].copy();fetched=cached[0]
        else:
            try:
                async with request.app['semaphore']:
                    await asyncio.wait_for(gateway.catalogue(m['exchange']),35)
                    frame=await asyncio.wait_for(gateway.candles(m['exchange'],m['symbol'],tf,needed,live=True),45)
                fetched=time.time()
                if len(request.app['cache'])>200:request.app['cache'].clear()
                request.app['cache'][key]=(fetched,frame.copy())
            except Exception:fail('Биржа не вернула свечи. Повторите запрос или выберите другую биржу.',502)
    now=pd.Timestamp.now(tz='UTC');frame=enrich_indicators(frame,settings_)
    selected=select_candles(frame,settings_.candle_mode,now)
    decisions=decide_signals(selected,settings_) if len(selected)>1 else []
    columns=['timestamp','open','high','low','close','volume']+[c for c in frame.columns if c.startswith(('rsi_','ema_')) or c in ('k','d','j')]
    records=json.loads(frame[columns].tail(160).to_json(orient='records'))
    rsi_column='rsi_'+str(settings_.rsi_periods[0])
    rsi_value=float(selected.iloc[-1][rsi_column]) if len(selected) and rsi_column in selected else None
    if rsi_value is not None and not math.isfinite(rsi_value):rsi_value=None
    return web.json_response({'market':m,'candles':records,'rsi':rsi_value,'signals':[{'direction':s.direction,'reason':s.reason} for s in decisions],'fetched':fetched,'mode':settings_.candle_mode})

async def index(request):return web.FileResponse(ROOT/'static/index.html')

async def cleanup(app):await app['gateway'].close()

def create_app():
    if not DB.is_file():raise RuntimeError('Bot database not found: set NEURO_BOT_DB')
    LOCAL.parent.mkdir(parents=True,exist_ok=True)
    with database(LOCAL) as db:db.execute('CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires REAL NOT NULL,fingerprint TEXT NOT NULL)')
    # Reuse existing store methods, without running migrations or initializing its credential vault.
    store=SettingsStore.__new__(SettingsStore);store.path=DB;store._lock=asyncio.Lock()
    app=web.Application(middlewares=[security],client_max_size=32768)
    app.update(store=store,gateway=MarketGateway(),cache={},locks={},semaphore=asyncio.Semaphore(3))
    app.add_routes([web.get('/',index),web.get('/api/health',health),web.post('/api/login',login),web.post('/api/register',register),web.post('/api/logout',logout),web.get('/api/me',me),web.get('/api/catalog',catalog),web.get('/api/settings',settings),web.post('/api/settings',settings),web.get('/api/watchlist',watchlist),web.post('/api/watchlist',watchlist),web.delete('/api/watchlist/{id}',watchlist),web.get('/api/alerts',alerts),web.post('/api/alerts',alerts),web.delete('/api/alerts/{id}',alerts),web.get('/api/history',history),web.get('/api/candles',candles),web.static('/static/',ROOT/'static')])
    app.on_cleanup.append(cleanup)
    return app

if __name__=='__main__':web.run_app(create_app(),host='127.0.0.1',port=PORT,access_log=None)
