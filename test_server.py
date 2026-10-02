"""Integration checks with schema-only fixtures; never modify the bot's live DB."""
import os, sqlite3, tempfile, unittest
from contextlib import closing
from pathlib import Path
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer

fixture=tempfile.TemporaryDirectory()
folder=Path(fixture.name)
source=Path(os.environ.get('NEURO_BOT_DIR','D:/TG BOTE'))/'data/bot.sqlite3'
with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original:
    schema=[r[0] for r in original.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")]
os.environ['NEURO_BOT_DB']=str(folder/'bot.sqlite3')
os.environ['NEURO_WEB_DB']=str(folder/'web.sqlite3')
with closing(sqlite3.connect(os.environ['NEURO_BOT_DB'])) as db, db:
    for sql in schema:db.execute(sql)
    db.execute("INSERT INTO markets VALUES('bybit','BTC/USDT:USDT','crypto',?,0)",('{"exchange":"bybit","symbol":"BTC/USDT:USDT","category":"crypto","type":"swap","quote":"USDT"}',))

import server

class WebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        server.attempts.clear()
        with server.database() as db:
            for table in ('users','chats','watchlist','price_alerts','audit'):db.execute('DELETE FROM '+table)
        self.client=TestClient(TestServer(server.create_app()),cookie_jar=CookieJar(unsafe=True))
        await self.client.start_server()

    async def asyncTearDown(self):await self.client.close()

    async def req(self,path,method='GET',data=None,origin='http://127.0.0.1:8765'):
        return await self.client.request(method,'/api/'+path,json=data,headers={'Host':'127.0.0.1:8765','Origin':origin})

    async def register(self,name='test_user'):
        r=await self.req('register','POST',{'login':name,'password':'test-only-pass-3941'})
        self.assertEqual(r.status,200,await r.text());return await r.json()

    async def test_public_https_boundaries(self):
        old=server.PUBLIC_ORIGIN,server.PUBLIC_HOST
        server.PUBLIC_ORIGIN,server.PUBLIC_HOST=server.parse_public_origin('https://neuro-test.example')
        try:
            headers={'Host':'neuro-test.example','Origin':'https://neuro-test.example','X-Forwarded-Proto':'https'}
            response=await self.client.post('/api/register',json={'login':'public_test','password':'test-only-pass-3941'},headers=headers)
            self.assertEqual(response.status,200,await response.text())
            self.assertTrue(response.cookies['neuro_session']['secure'])
            self.assertIn('max-age=',response.headers['Strict-Transport-Security'])
            token=response.cookies['neuro_session'].value
            response=await self.client.get('/api/me',headers={**headers,'Cookie':'neuro_session='+token})
            self.assertEqual(response.status,200)
            for changed in ({'Origin':'https://attacker.example'},{'Origin':'http://127.0.0.1:8765'},{'Host':'another.ngrok-free.app'},{'X-Forwarded-Proto':'http'}):
                response=await self.client.post('/api/login',json={},headers={**headers,**changed})
                self.assertEqual(response.status,403)
            response=await self.client.get('/api/me',headers=headers)
            self.assertEqual(response.status,401)
            response=await self.client.get('/api/health',headers={'Host':'127.0.0.1:8765'})
            self.assertEqual(response.status,200)
        finally:server.PUBLIC_ORIGIN,server.PUBLIC_HOST=old

    def test_public_origin_configuration(self):
        for origin in ('http://neuro.example','https://*.example','https://name:secret@example.com','https://example.com/path','https://example.com?x=1','https://example.com:8765'):
            with self.assertRaises(ValueError):server.parse_public_origin(origin)
        self.assertEqual(server.parse_public_origin('https://neuro.example/'),('https://neuro.example','neuro.example'))

    async def test_auth_and_unique_login(self):
        self.assertEqual((await self.req('catalog')).status,401)
        await self.register()
        r=await self.req('register','POST',{'login':'TEST_USER','password':'another-test-pass'})
        self.assertEqual(r.status,409)
        self.assertEqual((await self.req('me')).status,200)
        await self.req('logout','POST',{})
        self.assertEqual((await self.req('me')).status,401)
        r=await self.req('login','POST',{'login':'TEST_USER','password':'test-only-pass-3941'})
        self.assertEqual(r.status,200)
        self.assertIn('HttpOnly',r.headers['Set-Cookie']);self.assertIn('SameSite=Strict',r.headers['Set-Cookie'])

    async def test_password_and_origin(self):
        self.assertEqual((await self.req('register','POST',{'login':'a_test','password':'123'})).status,400)
        self.assertEqual((await self.req('register','POST',{'login':'a_test','password':'long-test-password'},origin='https://attacker.invalid')).status,403)
        await self.register();await self.req('logout','POST',{})
        self.assertEqual((await self.req('login','POST',{'login':'test_user','password':'incorrect'})).status,401)

    async def test_watchlist_isolation(self):
        first=await self.register('first_user')
        r=await self.req('watchlist','POST',{'exchange':'bybit','symbol':'BTC/USDT:USDT'})
        item=(await r.json())[0]
        await self.req('logout','POST',{});await self.register('second_user')
        self.assertEqual(await (await self.req('watchlist')).json(),[])
        await self.req('watchlist/'+str(item['id']),'DELETE',{})
        with server.database() as db:self.assertEqual(db.execute('SELECT count(*) FROM watchlist WHERE chat_id=?',(first['user_id'],)).fetchone()[0],1)

    async def test_settings_validation_and_persistence(self):
        await self.register()
        self.assertEqual((await self.req('settings','POST',{'rsi_low':80,'rsi_high':20})).status,400)
        self.assertEqual((await self.req('settings','POST',{'active':True})).status,400)
        r=await self.req('settings','POST',{'rsi_periods':[14],'rsi_low':25,'rsi_high':75})
        self.assertEqual(r.status,200)
        self.assertEqual((await (await self.req('settings')).json())['rsi_periods'],[14])

    async def test_block_revokes_session(self):
        u=await self.register()
        with server.database() as db:db.execute('UPDATE users SET blocked=1 WHERE user_id=?',(u['user_id'],))
        self.assertEqual((await self.req('me')).status,401)

    async def test_password_change_revokes_session(self):
        u=await self.register()
        with server.database() as db:db.execute('UPDATE users SET password_hash=? WHERE user_id=?',(server.hash_password('replacement-test-only'),u['user_id']))
        self.assertEqual((await self.req('me')).status,401)

    async def test_catalog_and_private_history(self):
        await self.register()
        r=await self.req('catalog?exchange=bybit&q=BTC&type=swap')
        self.assertEqual((await r.json())['total'],1)
        d=await (await self.req('history')).json()
        self.assertEqual(d['orders'],[]);self.assertNotIn('password',str(d));self.assertNotIn('credentials',str(d))

    async def test_telegram_alert_limits(self):
        u=await self.register()
        self.assertEqual((await self.req('alerts','POST',{'exchange':'bybit','symbol':'BTC/USDT:USDT','price':50000,'comparator':'gte'})).status,400)
        # Positive ID models a linked Telegram account. Login again to get its session.
        with server.database() as db:db.execute('UPDATE users SET user_id=123456 WHERE user_id=?',(u['user_id'],))
        await self.req('login','POST',{'login':'test_user','password':'test-only-pass-3941'})
        for i in range(3):self.assertEqual((await self.req('alerts','POST',{'exchange':'bybit','symbol':'BTC/USDT:USDT','price':50000+i,'comparator':'gte'})).status,200)
        self.assertEqual((await self.req('alerts','POST',{'exchange':'bybit','symbol':'BTC/USDT:USDT','price':60000,'comparator':'gte'})).status,400)

    async def test_login_throttle(self):
        for _ in range(10):await self.req('login','POST',{'login':'nobody','password':'incorrect'})
        self.assertEqual((await self.req('login','POST',{'login':'nobody','password':'incorrect'})).status,429)

    async def test_chart_uses_closed_candle_for_rsi(self):
        await self.register()
        import pandas as pd
        from bot.services.timeframes import normalize
        from bot.services.indicators import enrich_indicators
        now=pd.Timestamp.now(tz='UTC').floor('h')
        values=[]
        for i in range(162):
            price=100+i*.2
            values.append([int((now-pd.Timedelta(hours=161-i)).timestamp()*1000),price,price+2,price-2,price+1,10])
        values[-1][4]=80;values[-1][3]=79
        frame=normalize(values,'1h')
        class FakeGateway:
            async def catalogue(self,exchange):return []
            async def candles(self,*args,**kwargs):return frame.copy()
            async def close(self):pass
        self.client.server.app['gateway']=FakeGateway()
        r=await self.req('candles?exchange=bybit&symbol=BTC%2FUSDT%3AUSDT&timeframe=1h')
        self.assertEqual(r.status,200,await r.text())
        payload=await r.json()
        expected=enrich_indicators(frame,server.ChatSettings()).iloc[-2]['rsi_7']
        self.assertAlmostEqual(payload['rsi'],expected)
        self.assertEqual(payload['mode'],'closed')

if __name__=='__main__':unittest.main(verbosity=2)
