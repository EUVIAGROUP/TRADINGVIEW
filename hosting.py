"""NEURO personal-PC HTTPS launcher. Secrets stay local, protected by Windows DPAPI."""
import ctypes, getpass, json, msvcrt, os, signal, socket, subprocess, sys, time
from ctypes import wintypes
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen, Request

ROOT=Path(__file__).resolve().parent
CONFIG=ROOT/'hosting.json'
STATE=ROOT/'data/hosting'
SECRET=Path(os.environ['LOCALAPPDATA'])/'NEURO/ngrok-token.bin'
AGENT=ROOT/'runtime/ngrok/ngrok.exe'
PORT=8766
HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)

class Blob(ctypes.Structure):
    _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]

def protect(data,encrypt=True):
    buffer=ctypes.create_string_buffer(data)
    source=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)))
    result=Blob();api=ctypes.windll.crypt32
    api.CryptProtectData.argtypes=[ctypes.POINTER(Blob),wintypes.LPCWSTR,ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    api.CryptProtectData.restype=wintypes.BOOL
    api.CryptUnprotectData.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    api.CryptUnprotectData.restype=wintypes.BOOL
    ctypes.windll.kernel32.LocalFree.argtypes=[ctypes.c_void_p]
    ctypes.windll.kernel32.LocalFree.restype=ctypes.c_void_p
    if encrypt:ok=api.CryptProtectData(ctypes.byref(source),'NEURO ngrok',None,None,None,1,ctypes.byref(result))
    else:ok=api.CryptUnprotectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(result))
    if not ok:raise ctypes.WinError()
    try:return ctypes.string_at(result.pbData,result.cbData)
    finally:ctypes.windll.kernel32.LocalFree(result.pbData)

def origin(value):
    value=value.strip().rstrip('/')
    if '://' not in value:value='https://'+value
    p=urlsplit(value)
    if (p.scheme!='https' or not p.hostname or p.username or p.password or p.path or p.query or p.fragment
        or p.port not in (None,443) or '*' in value or any(c.isspace() for c in value)):
        raise ValueError('Введите только HTTPS-адрес из раздела Domains в ngrok, без пути.')
    if not p.hostname.endswith(('.ngrok-free.app','.ngrok-free.dev','.ngrok.app','.ngrok.dev','.ngrok.io')):
        raise ValueError('Нужен адрес, выданный ngrok вашему аккаунту.')
    return value

def setup():
    print('NEURO: постоянная HTTPS-ссылка\n')
    print('1. Войдите на https://dashboard.ngrok.com\n2. Скопируйте ваш адрес из Domains: https://dashboard.ngrok.com/domains')
    address=origin(input('\nАдрес ngrok: '))
    print('\nТокен: https://dashboard.ngrok.com/get-started/your-authtoken')
    token=getpass.getpass('Вставьте только токен (символы скрыты): ').strip()
    if len(token)<15 or any(c.isspace() for c in token):raise ValueError('Токен должен быть одной строкой, без команды ngrok.')
    SECRET.parent.mkdir(parents=True,exist_ok=True)
    SECRET.write_bytes(protect(token.encode('utf-8')))
    CONFIG.write_text(json.dumps({'public_origin':address},indent=2),encoding='utf-8')
    (ROOT/'PUBLIC_SITE.url').write_text('[InternetShortcut]\nURL='+address+'\n',encoding='utf-8')
    print('\nНастройки сохранены. Токен зашифрован для текущего пользователя Windows.')
    print('Запустите START_HTTPS.cmd. Ваш постоянный адрес: '+address)

def status(value,**extra):
    STATE.mkdir(parents=True,exist_ok=True)
    temp=STATE/'status.tmp'
    temp.write_text(json.dumps({'state':value,'updated':time.time(),**extra},ensure_ascii=False),encoding='utf-8')
    temp.replace(STATE/'status.json')

def busy(port):
    with socket.socket() as s:return s.connect_ex(('127.0.0.1',port))==0

def run():
    STATE.mkdir(parents=True,exist_ok=True)
    lock=(STATE/'run.lock').open('a+b');lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:raise RuntimeError('HTTPS-сервер уже запущен. Используйте STOP_HTTPS.cmd для остановки.')
    processes=[];logs=[];stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGINT,stop)
    signal.signal(signal.SIGTERM,stop)
    try:
        if not CONFIG.is_file() or not SECRET.is_file():raise RuntimeError('Сначала запустите SETUP_HTTPS.cmd и укажите аккаунт ngrok.')
        if not AGENT.is_file():raise RuntimeError('Не найден runtime/ngrok/ngrok.exe.')
        address=origin(json.loads(CONFIG.read_text(encoding='utf-8'))['public_origin'])
        if busy(PORT) or busy(4047):raise RuntimeError('Порт 8766 или 4047 уже занят. Другие процессы не были остановлены.')
        stopfile=STATE/'stop.request'
        if stopfile.exists():stopfile.unlink()
        agent_config=STATE/'ngrok.yml'
        agent_config.write_text('version: "3"\nagent:\n  web_addr: 127.0.0.1:4047\n',encoding='utf-8')
        token=protect(SECRET.read_bytes(),False).decode('utf-8')
        env=os.environ.copy();env.update(NEURO_PORT=str(PORT),NEURO_PUBLIC_ORIGIN=address,NEURO_WEB_DB=str(ROOT/'data/web-public.sqlite3'),PYTHONUNBUFFERED='1')
        status('starting',url=address)
        serverlog=(STATE/'server.log').open('w',encoding='utf-8');logs.append(serverlog)
        server=subprocess.Popen([sys.executable,str(ROOT/'server.py')],cwd=ROOT,env=env,stdout=serverlog,stderr=subprocess.STDOUT,creationflags=HIDDEN);processes.append(server)
        ready=False
        for _ in range(90):
            if stopping or stopfile.exists():return
            if server.poll() is not None:raise RuntimeError('Сервер завершился. Подробности: data/hosting/server.log')
            try:
                with urlopen(f'http://127.0.0.1:{PORT}/api/health',timeout=1) as response:ready=response.status==200
            except OSError:pass
            if ready:break
            time.sleep(1)
        if not ready:raise RuntimeError('Сервер не успел запуститься.')
        tunnel_env=os.environ.copy();tunnel_env['NGROK_AUTHTOKEN']=token;token=''
        tunnel_log=(STATE/'ngrok.log').open('w',encoding='utf-8');logs.append(tunnel_log)
        tunnel=subprocess.Popen([str(AGENT),'http',f'http://127.0.0.1:{PORT}','--url',address,'--config',str(agent_config),'--inspect=false','--log=stdout','--log-format=json'],cwd=ROOT,env=tunnel_env,stdout=tunnel_log,stderr=subprocess.STDOUT,creationflags=HIDDEN);processes.append(tunnel);tunnel_env.pop('NGROK_AUTHTOKEN',None)
        ready=False
        for _ in range(90):
            if stopping or stopfile.exists():return
            if tunnel.poll() is not None:raise RuntimeError('ngrok не подключился. Проверьте data/hosting/ngrok.log и настройки аккаунта.')
            try:
                req=Request(address+'/api/health',headers={'ngrok-skip-browser-warning':'neuro-check'})
                with urlopen(req,timeout=3) as response:
                    ready=response.status==200 and json.load(response).get('ok') is True
            except (OSError,ValueError):pass
            if ready:break
            time.sleep(1)
        if not ready:raise RuntimeError('HTTPS-ссылка не прошла проверку доступности. Проверьте интернет и data/hosting/ngrok.log.')
        status('online',url=address)
        (ROOT/'SHARE_URL.txt').write_text(address+'\n',encoding='utf-8')
        print('\nСайт доступен по HTTPS: '+address,flush=True)
        print('Отправьте другу эту ссылку. Для остановки: STOP_HTTPS.cmd или Ctrl+C.',flush=True)
        while not stopping and not stopfile.exists():
            if any(p.poll() is not None for p in processes):raise RuntimeError('Сервер или ngrok завершился. Запустите START_HTTPS.cmd ещё раз.')
            time.sleep(1)
    except Exception as error:
        status('error',message=str(error));raise
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        for f in logs:f.close()
        try:
            old=json.loads((STATE/'status.json').read_text(encoding='utf-8'))
            if old.get('state')!='error':status('stopped')
        except (OSError,ValueError):pass
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()

def autostart(enabled):
    import winreg
    keypath=r'Software\Microsoft\Windows\CurrentVersion\Run'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,keypath) as key:
        if enabled:
            if not CONFIG.is_file() or not SECRET.is_file():raise RuntimeError('Сначала выполните SETUP_HTTPS.cmd и проверьте START_HTTPS.cmd.')
            pythonw=Path(sys.executable).with_name('pythonw.exe')
            if not pythonw.is_file():raise RuntimeError('Не найден pythonw.exe.')
            command=subprocess.list2cmdline([str(pythonw),str(ROOT/'hosting.py'),'run'])
            winreg.SetValueEx(key,'NEURO_HTTPS',0,winreg.REG_SZ,command)
            print('Автозапуск включён: HTTPS-сервер запустится после вашего входа в Windows.')
        else:
            try:winreg.DeleteValue(key,'NEURO_HTTPS')
            except FileNotFoundError:pass
            print('Автозапуск выключен. Текущую публикацию можно остановить через STOP_HTTPS.cmd.')

if __name__=='__main__':
    try:
        action=sys.argv[1] if len(sys.argv)>1 else 'run'
        if action=='setup':setup()
        elif action=='stop':STATE.mkdir(parents=True,exist_ok=True);(STATE/'stop.request').touch();print('Остановка HTTPS-сервера запрошена. Локальный сайт продолжит работать.')
        elif action=='status':print((STATE/'status.json').read_text(encoding='utf-8') if (STATE/'status.json').exists() else 'HTTPS-сервер ещё не запускался.')
        elif action=='autostart-on':autostart(True)
        elif action=='autostart-off':autostart(False)
        elif action=='run':run()
        else:raise ValueError('Неизвестная команда')
    except Exception as error:
        if sys.stdout:print(str(error),flush=True)
        sys.exit(1)
