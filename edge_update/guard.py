"""Local signed-update state machine, with trusted local state and single-writer locking."""
import argparse, base64, fcntl, hashlib, json, os, re, tempfile, urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
LIMIT = 262144

class Rejected(ValueError):
    pass

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def reset(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / 'slots').mkdir(exist_ok=True)
    data = b'factory image'
    digest = hashlib.sha256(data).hexdigest()
    atomic(root / 'slots' / digest, data)
    atomic(root / 'state.json', canonical({'version': 1, 'digest': digest}))

def recover(root):
    state = json.loads((root / 'state.json').read_bytes())
    digest = state['digest']
    if not re.fullmatch('[a-f0-9]{64}', digest):
        raise Rejected('invalid committed digest')
    if hashlib.sha256((root / 'slots' / digest).read_bytes()).hexdigest() != digest:
        raise Rejected('committed image corruption')
    return state

def download(url):
    with urllib.request.urlopen(url, timeout=1) as r:
        expected = r.headers.get('Content-Length')
        if expected is not None and (not expected.isdecimal() or int(expected) > LIMIT):
            raise Rejected('invalid transport length')
        data = r.read(LIMIT + 1)
        if expected is not None and len(data) != int(expected):
            raise Rejected('interrupted download')
    if len(data) > LIMIT:
        raise Rejected('download size limit')
    return data

def install(root, package, key, now, crash=''):
    with open(root / 'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = recover(root)
        try:
            env = json.loads(package)
            meta = env['metadata']
            if set(meta) != {'version', 'sha256', 'size', 'expires', 'target'}:
                raise Rejected('metadata fields')
            key.verify(base64.b64decode(env['signature'], validate=True), canonical(meta))
            if type(meta['version']) is not int or meta['version'] <= state['version']:
                raise Rejected('rollback/replay')
            if type(meta['expires']) is not int or now >= meta['expires']:
                raise Rejected('expired metadata')
            if meta['target'] != 'application.bin':
                raise Rejected('unexpected target')
            payload = base64.b64decode(env['payload'], validate=True)
            if type(meta['size']) is not int or not 0 < meta['size'] <= LIMIT:
                raise Rejected('size limit')
            if len(payload) != meta['size'] or hashlib.sha256(payload).hexdigest() != meta['sha256']:
                raise Rejected('payload integrity')
        except Rejected:
            raise
        except Exception as e:
            raise Rejected(type(e).__name__) from e
        slots = root / 'slots'
        if crash == 'during_write':
            with open(slots / '.interrupted', 'wb') as f:
                f.write(payload[:len(payload) // 2])
                f.flush()
                os.fsync(f.fileno())
                os._exit(91)
        atomic(slots / meta['sha256'], payload)
        if crash == 'after_stage':
            os._exit(92)
        atomic(root / 'state.json', canonical({'version': meta['version'], 'digest': meta['sha256']}))
        if crash == 'after_commit':
            os._exit(93)
        return recover(root)
if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('root', type=Path)
    ap.add_argument('package', type=Path)
    ap.add_argument('key', type=Path)
    ap.add_argument('--now', type=int, required=True)
    ap.add_argument('--crash', default='')
    a = ap.parse_args()
    print(json.dumps(install(a.root, a.package.read_bytes(), Ed25519PublicKey.from_public_bytes(a.key.read_bytes()), a.now, a.crash)))
