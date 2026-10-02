#!/usr/bin/env python3
"""solve_cmd_key.py -- determine which key/IV actually decrypts 8899.

Instead of assuming key=authKey, this tries every candidate key against every
candidate IV, in both chaining modes, and reports which pair validates by the
zero-padding oracle. Also reports the negotiated aesKeyType/aesIvType so the
expected branch of genAesKey/genAesIv is known.

Usage: solve_cmd_key.py <pcap> <logcat>
"""
import re, struct, subprocess, sys, itertools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b'\x00\x07\x01\xe0'

def parse_encrypted(body):
    if len(body) < 9 or body[:4] != MAGIC: return None
    flags = body[3]; pad = body[4] if flags & 0x40 else 0
    return pad, body[9:]

def frames_from(buf):
    out=[]; i=0
    while i+9 <= len(buf):
        if buf[i] != 0x24: i+=1; continue
        blen = struct.unpack('>I', buf[i+5:i+9])[0]
        if i+9+blen > len(buf) or blen > (1<<22): i+=1; continue
        out.append((buf[i+2], struct.unpack('>H', buf[i+3:i+5])[0], bytes(buf[i+9:i+9+blen])))
        i += 9+blen
    return out

def keys_from_log(text):
    """Return list of (timestamp, role, value16) using toJson + uuid binding."""
    uuids = re.findall(r'uuid:([0-9a-f]{32})', text)
    tails = re.findall(r'toJson:authKey:(\w{4})\s*,streamKey:(\w{4})\s*,streamIV:(\w{4})', text)
    out=[]
    if tails:
        a,s,v = tails[-1]
        pools=list(uuids)
        for role,want in (('authKey',a),('streamKey',s),('streamIV',v)):
            for u in pools:
                if u[:16].endswith(want):
                    out.append((role,u[:16])); pools.remove(u); break
    return out

def main():
    pcap, log = sys.argv[1], sys.argv[2]
    text = open(log, errors='replace').read()
    kf = keys_from_log(text)
    print('# keys from logcat: %s' % kf)
    negotiated = re.findall(r'"?(aesKeyType|aesIvType|authKeyType|authAlgorithmType)"?\s*[:=]\s*"?(\d+)', text)
    if negotiated: print('# negotiated: %s' % negotiated[-6:])

    out = subprocess.run(['tshark','-r',pcap,'-Y','tcp.port==8899','-T','fields','-e','tcp.srcport','-e','tcp.payload'],
                         capture_output=True, text=True)
    st={}
    for line in out.stdout.splitlines():
        p=line.split('\t')
        if len(p)<2 or not p[1].strip(): continue
        try: raw=bytes.fromhex(p[1].replace(':',''))
        except ValueError: continue
        st.setdefault(p[0], bytearray()).extend(raw)

    cands = [v.encode() for _,v in kf] + [bytes.fromhex(v) for _,v in kf]
    cands = [c for c in cands if len(c)==16]
    cands.append(bytes(16))
    labels = [f'{r}:{v}' for r,v in kf] + [f'{r}:hex' for r,_ in kf] + ['zero']

    for sp, buf in sorted(st.items()):
        fr = frames_from(buf)
        enc = [(c,s,p) for c,s,b in fr if (p:=parse_encrypted(b))]
        if not enc: continue
        print('\n=== dir %s : %d encrypted frames' % (sp, len(enc)))
        for (kn,k),(vn,v) in itertools.product(zip(labels,cands), zip(labels,cands)):
            for mode in ('chain','reset'):
                cur=v; ok=tot=0; first=None
                for c,s,p in enc:
                    pad, ct = p
                    if ct and len(ct)%16==0:
                        pt=Cipher(algorithms.AES(k),modes.CBC(cur)).decryptor().update(ct)
                        tot+=1
                        good=pt.endswith(b'\x00'*pad)
                        if good and first is None: first=(c,s,pt[:len(pt)-pad])
                        ok+=good
                        if mode=='chain': cur=ct[-16:]
                if ok:
                    print('  *** key=%s iv=%s %s -> padok %d/%d  first=%r'
                          % (kn,vn,mode,ok,tot,(first[2][:80] if first else b'')))

if __name__=='__main__': main()
