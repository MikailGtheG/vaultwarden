#!/usr/bin/env python3
"""Isolated live-server security regression tests; synthetic data only.

Requires an already-built Vaultwarden binary and openssl. Starts a fresh
Vaultwarden service with a temporary SQLite database and generated RSA key.
No production database, accounts, tokens or external services are used.
"""
import base64
import concurrent.futures
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

PORT = 18192
HOST = "127.0.0.1"
BINARY = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath("target/ci/vaultwarden")
ADMIN_SECRET = "ci-only-synthetic-admin-token"
NOW = lambda: dt.datetime.now(dt.timezone.utc)
def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def jwt(priv, origin, kind, sub, **extra):
    now = int(time.time())
    header = {"alg":"RS256","typ":"JWT"}
    claims = {"nbf":now-5,"exp":now+1200,"iss":origin+"|"+kind,"sub":sub,**extra}
    prefix = ".".join(b64(json.dumps(x, separators=(",",":")).encode()) for x in (header,claims))
    sig = subprocess.run(["openssl","dgst","-sha256","-sign",str(priv)],input=prefix.encode(),capture_output=True,check=True).stdout
    return prefix+"."+b64(sig)

def request(method, path, body=None, headers=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=8)
    try:
        c.request(method,path,body=body,headers=headers or {})
        r=c.getresponse()
        return r.status,dict(r.getheaders()),r.read()
    finally:
        c.close()

def insert(db, table, values):
    cols=",".join(values)
    marks=",".join("?" for _ in values)
    db.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(values.values()))
    db.commit()

def expect(ok,msg):
    if not ok: raise AssertionError(msg)
    print("PASS:",msg,flush=True)

def socket_upgrade(path):
    key=b64(os.urandom(16))
    req=(f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
         f"Connection: Upgrade\r\nUpgrade: websocket\r\n"
         f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n")
    with socket.create_connection((HOST,PORT),timeout=8) as s:
        s.settimeout(8)
        s.sendall(req.encode())
        first=s.recv(1024).split(b"\r\n",1)[0].decode()
        return int(first.split(" ")[1])

def run_case(scheme, trusted_proxy=False):
    origin=f"{scheme}://vault.test"
    with tempfile.TemporaryDirectory(prefix="vw-security-ci-") as d:
        data=Path(d); logs=data/"server.log"
        env=dict(os.environ,
            DATA_FOLDER=d, DATABASE_URL="sqlite://"+str(data/"db.sqlite3"),
            WEB_VAULT_ENABLED="false",DOMAIN=origin,ADMIN_TOKEN=ADMIN_SECRET,
            ROCKET_ADDRESS=HOST,ROCKET_PORT=str(PORT),LOG_LEVEL="warn",
            JOB_POLL_INTERVAL_MS="0",SIGNUPS_ALLOWED="false",
            IP_HEADER_TRUSTED_PROXIES="127.0.0.1/32" if trusted_proxy else "203.0.113.0/24")
        with logs.open("wb") as log:
            proc=subprocess.Popen([BINARY],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                for _ in range(120):
                    if proc.poll() is not None:
                        raise RuntimeError(f"server exited with {proc.returncode}: {logs.read_text()[-4000:]}")
                    try:
                        status,_,_=request("GET","/api/alive")
                        if status==200:break
                    except (OSError,http.client.HTTPException):
                        pass
                    time.sleep(1)
                else:raise RuntimeError(f"server not ready: {logs.read_text()[-4000:]}")
                cookie_test(scheme, trusted_proxy)
                db=sqlite3.connect(str(data/"db.sqlite3"),timeout=10)
                try:
                    security_tests(db,data,origin)
                finally:db.close()
            except Exception:
                print("SERVICE LOG TAIL:\n"+logs.read_text()[-6000:],file=sys.stderr)
                raise
            finally:
                proc.terminate()
                try:proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait()

def cookie_test(scheme,trusted_proxy):
    headers={"Content-Type":"application/x-www-form-urlencoded","X-Forwarded-Proto":"http"}
    status,res,_=request("POST","/admin/",urllib.parse.urlencode({"token":ADMIN_SECRET}),headers)
    cookie=next((value for name,value in res.items() if name.lower()=="set-cookie"),"")
    expect(status in (200,302,303) and cookie,f"admin login creates a session cookie (status={status}, response_headers={list(res)})")
    expect(("Secure" in cookie)==(scheme=="https"),"public HTTPS origin determines cookie Secure attribute")
    # Explicitly test a forged HTTPS header from an untrusted client.
    headers["X-Forwarded-Proto"]="https"
    status,res,_=request("POST","/admin/",urllib.parse.urlencode({"token":ADMIN_SECRET}),headers)
    cookie=next((value for name,value in res.items() if name.lower()=="set-cookie"),"")
    expect(("Secure" in cookie)==(scheme=="https" or trusted_proxy),"forwarded HTTPS trusted only from configured peer")

def security_tests(db,data,origin):
    uid=str(uuid.uuid4()); did=str(uuid.uuid4()); stamp=str(uuid.uuid4())
    clock=NOW().strftime("%Y-%m-%d %H:%M:%S")
    insert(db,"users",dict(uuid=uid,enabled=1,created_at=clock,updated_at=clock,
        login_verify_count=0,email="synthetic@example.invalid",name="Test",
        password_hash=b"ci-only",salt=b"ci-only",password_iterations=1,
        akey="synthetic",security_stamp=stamp,equivalent_domains="[]",
        excluded_globals="[]",client_kdf_type=0,client_kdf_iter=100000))
    insert(db,"devices",dict(uuid=did,created_at=clock,updated_at=clock,user_uuid=uid,
        name="synthetic-test-device",atype=14,refresh_token="ci-only-refresh"))
    private=data/"rsa_key.pem"
    login=jwt(private,origin,"login",uid,device=did,sstamp=stamp,
        premium=True,name="Test",email="synthetic@example.invalid",email_verified=True,
        devicetype="14",client_id="web",scope=["api","offline_access"],amr=["Application"])
    ws_path="/notifications/hub?access_token="+urllib.parse.quote(login,safe="")
    expect(socket_upgrade(ws_path)==101,"valid synthetic login JWT opens WebSocket")
    db.execute("DELETE FROM devices WHERE uuid=?",(did,));db.commit()
    expect(socket_upgrade(ws_path)!=101,"removed device cannot reconnect to WebSocket")
    insert(db,"devices",dict(uuid=did,created_at=clock,updated_at=clock,user_uuid=uid,
        name="synthetic-test-device",atype=14,refresh_token="ci-only-refresh"))
    db.execute("UPDATE users SET security_stamp=? WHERE uuid=?",("new-stamp",uid));db.commit()
    expect(socket_upgrade(ws_path)!=101,"stale user security stamp prevents WebSocket reconnect")

    sid=str(uuid.uuid4());fid="ci-file-"+str(uuid.uuid4())
    sd={"id":fid,"size":4,"fileName":"test.txt"}
    expiry=(NOW()+dt.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    insert(db,"sends",dict(uuid=sid,user_uuid=uid,name="CI Test File",atype=1,
        data=json.dumps(sd),akey="synthetic-key",access_count=0,
        creation_date=clock,revision_date=clock,deletion_date=expiry,disabled=0))
    folder=data/"sends"/sid;folder.mkdir(parents=True,exist_ok=True)
    (folder/fid).write_bytes(b"test")
    file_token=jwt(private,origin,"send",sid+"/"+fid)
    url=f"/api/sends/{sid}/{fid}?t="+urllib.parse.quote(file_token,safe="")
    status,_,payload=request("GET",url)
    expect(status==200 and payload==b"test","valid signed Send file URL retrieves synthetic data")
    db.execute("UPDATE sends SET disabled=1 WHERE uuid=?",(sid,));db.commit()
    expect(request("GET",url)[0]!=200,"disabled Send rejects previously issued signed URL")
    db.execute("UPDATE sends SET disabled=0, expiration_date=? WHERE uuid=?",(clock,sid));db.commit()
    expect(request("GET",url)[0]!=200,"expired Send rejects previously issued signed URL")
    db.execute("UPDATE sends SET expiration_date=NULL WHERE uuid=?",(sid,));db.commit()
    expect(request("GET",url.replace(fid,"not-the-file",1))[0]!=200,"incorrect file id rejected")

    bearer=jwt(private,origin,"send",sid)
    base=f"/api/sends/access/file/{fid}"
    for value,accepted in [
        ("Bearer "+bearer,True),("Bearer   "+bearer,True),
        ("Basic "+bearer,False),("Basic Bearer "+bearer,False),
        (bearer,False),("Bearer "+bearer+" trailing",False)]:
        db.execute("UPDATE sends SET access_count=0,max_access_count=NULL WHERE uuid=?",(sid,));db.commit()
        status,_,_=request("POST",base,headers={"Authorization":value})
        expect((status==200)==accepted,"Bearer parsing "+("accepts" if accepted else "rejects")+" "+value.split(" ")[0])
    db.execute("UPDATE sends SET access_count=0,max_access_count=1 WHERE uuid=?",(sid,));db.commit()
    def access(_):return request("POST",base,headers={"Authorization":"Bearer "+bearer})[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses=list(pool.map(access,range(8)))
    count=db.execute("SELECT access_count FROM sends WHERE uuid=?",(sid,)).fetchone()[0]
    expect(statuses.count(200)==1 and count==1,
        "concurrent Send accesses atomically respect max_access_count=1")

if __name__=="__main__":
    expect(Path(BINARY).is_file(),"combined Vaultwarden test executable exists")
    run_case("http",False)
    run_case("https",False)
    run_case("http",True)
    print("ALL isolated HTTP/SQLite/WS smoke tests passed",flush=True)
