import sys, json, random, base64, collections
src = sys.argv[1]; out = sys.argv[2]
def fnv(bs, basis):
    h = basis
    for b in bs:
        h ^= b
        h = (h * 0x01000193) & 0xffffffff
    return h
def key(host):
    bs = host.encode('ascii')
    return (fnv(bs, 0x9747b28c) & 0xff) * 4294967296 + fnv(bs, 0x811c9dc5)
domains = set()
for line in open(src, encoding='utf-8', errors='ignore'):
    d = line.strip().lower().rstrip('.')
    if not d or '.' not in d or ' ' in d or '/' in d or ':' in d: continue
    try:
        d.encode('ascii')
    except UnicodeEncodeError:
        try: d2 = d.encode('idna').decode('ascii')
        except Exception: continue
        if 'xn--' not in d2: continue
        d = d2
    domains.add(d)
domains = sorted(domains)
keys = sorted(set(key(d) for d in domains))
buf = bytearray(); prev = 0
for k in keys:
    v = k - prev; prev = k
    while v >= 128:
        buf.append((v & 127) | 128); v >>= 7
    buf.append(v)
b64 = base64.b64encode(bytes(buf)).decode()
MULTI = {'co','com','org','net','gov','edu','ac','or','ne','go'}
def reg(d):
    p = d.split('.')
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in MULTI: return '.'.join(p[-3:])
    return '.'.join(p[-2:])
tlds = collections.Counter(d.rsplit('.',1)[1] for d in domains)
parents = collections.Counter(reg(d) for d in domains if d.count('.') >= 2)
random.seed(20261104)
pool = [d for d in domains if len(d) <= 48 and not d.startswith('xn--') and d.count('.') <= 3]
sample = sorted(random.sample(pool, 240))
# shared hosts present as exact entries?
chk = ['google.com','github.io','weebly.com','blogspot.com','000webhostapp.com','netlify.app','pages.dev','wixsite.com','web.app','firebaseapp.com','paypal.com','amazon.com','microsoft.com']
present = [c for c in chk if c in set(domains)]
json.dump({'count': len(domains), 'tlds': tlds.most_common(8), 'parents': parents.most_common(8), 'sample': sample, 'present': present, 'b64len': len(b64)}, open(out + '.json', 'w'))
open(out + '.b64', 'w').write(b64)
print(len(domains), len(keys), len(b64), present)
print(tlds.most_common(8)); print(parents.most_common(8))
