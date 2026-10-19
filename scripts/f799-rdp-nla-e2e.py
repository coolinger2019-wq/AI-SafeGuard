#!/usr/bin/env python3
# F799 E2E：python 模拟真客户端 NLA 全流程（X.224 → TLS → TSRequest type1/2/3）
import socket, ssl, struct, time, sqlite3, datetime

HOST, PORT = "127.0.0.1", 3389

def x224_cr():
    cookie = b"Cookie: mstshash=e2e-f799\r\n"
    neg = struct.pack("<BBHI", 1, 0, 8, 2)  # TYPE_NEG_REQ, flags, len=8, PROTOCOL_NLA
    pdu = b"\xe0\x00\x00\x00\x00" + cookie + neg
    return b"\x03\x00" + struct.pack(">H", len(pdu) + 5) + bytes([len(pdu)]) + pdu

def der_len(n):
    if n < 0x80: return bytes([n])
    if n <= 0xFF: return b"\x81" + bytes([n])
    return b"\x82" + struct.pack(">H", n)

def tsrequest(blob):
    inner = b"\x04" + der_len(len(blob)) + blob
    seq = b"\x30" + der_len(len(inner)) + inner
    a1 = b"\xa1" + der_len(len(seq)) + seq
    body = b"\xa0\x03\x02\x01\x02" + a1
    return b"\x30" + der_len(len(body)) + body

def read_tsrequest(sock):
    head = sock.recv(2)
    if head[0] != 0x30: raise RuntimeError(f"非 DER: {head.hex()}")
    n = head[1]
    if n < 0x80: content = sock.recv(n)
    elif n == 0x81: content = sock.recv(sock.recv(1)[0])
    else:
        l = struct.unpack(">H", sock.recv(2))[0]
        content = sock.recv(l)
    return head + content

def find_nego(frame):
    i = frame.find(b"\xa1")
    if i < 0: raise RuntimeError("无 a1")
    j = frame.find(b"\x30", i)
    k = frame.find(b"\x04", j)
    ln = frame[k+1]
    return frame[k+2:k+2+ln]

def ntlm_type(blob):
    assert blob[:8] == b"NTLMSSP\x00", blob[:16]
    return struct.unpack("<I", blob[8:12])[0]

def type3(user="admin"):
    u16 = user.encode("utf-16-le")
    blob = b"NTLMSSP\x00" + struct.pack("<I", 3)
    blob += struct.pack("<HHI", 0, 0, 0)                 # lm
    blob += struct.pack("<HHI", 0, 0, 0)                 # ntlm
    blob += struct.pack("<HHI", 0, 0, 0)                 # domain
    blob += struct.pack("<HHI", len(u16), len(u16), 56)  # user offset=56
    blob += struct.pack("<HHI", 0, 0, 0)                 # ws
    blob += b"\x00" * 4                                  # flags
    blob += u16
    return blob

s = socket.create_connection((HOST, PORT), timeout=10)
s.sendall(x224_cr())
cc = s.recv(64)
assert cc[:4] == b"\x03\x00\x00\x13", cc.hex()
sel = struct.unpack("<I", cc[15:19])[0]
print("X.224 CC selectedProtocol =", sel)
assert sel == 2, "应选 NLA"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
tls = ctx.wrap_socket(s)
print("TLS 建立:", tls.version())

tls.sendall(tsrequest(b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 24))
r1 = find_nego(read_tsrequest(tls))
print("收到 NTLM type =", ntlm_type(r1))
assert ntlm_type(r1) == 2, "应回 type2 挑战"

tls.sendall(tsrequest(type3("admin")))
r2 = read_tsrequest(tls)
ok = b"\x80\x09\x03\x0c" in r2
print("LOGON_DENIED 返回:", ok)
assert ok

time.sleep(3)
c = sqlite3.connect("file:/var/lib/aisafeguard/aisafeguard.db?mode=ro", uri=True)
rows = c.execute("SELECT ts, listener, summary FROM events WHERE kind='credential_observed' AND remote_ip='127.0.0.1' ORDER BY id DESC LIMIT 3").fetchall()
for ts, l, sm in rows:
    print("credential_observed:", datetime.datetime.fromtimestamp(int(ts), datetime.UTC).strftime("%H:%M:%S"), l, "|", sm[:50])
assert any(r[1] == "rdp" and "admin" in r[2] for r in rows), "rdp 凭证未落库（admin 不在事件里）"
print("E2E-PASS")
