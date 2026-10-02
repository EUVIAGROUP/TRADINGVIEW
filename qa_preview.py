"""Temporary isolated UI fixture. No access to real user records."""
import os
os.environ['NEURO_PORT']='8766'
import test_server
from test_server import server
with server.database() as db:
    db.execute("INSERT INTO users(user_id,login,display_name,password_hash,login_chosen,created,updated) VALUES(123456,'visual_test','Visual Test',?,1,0,0)",(server.hash_password('temporary-preview-3941'),))
server.web.run_app(server.create_app(),host='127.0.0.1',port=8766,access_log=None)
