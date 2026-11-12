import base64, hashlib, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from edge_update.guard import canonical, reset, recover, install, download, Rejected, LIMIT

class UpdateTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'device'
        reset(self.root)
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key()

    def package(self, version=2, payload=b'new application' * 100, expires=2000, target='application.bin'):
        m = {'version': version, 'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload), 'expires': expires, 'target': target}
        return {'metadata': m, 'signature': base64.b64encode(self.key.sign(canonical(m))).decode(), 'payload': base64.b64encode(payload).decode()}

    def apply(self, p=None, now=1000):
        return install(self.root, canonical(p or self.package()), self.pub, now)

    def rejected(self, p, now=1000):
        before = recover(self.root)
        with self.assertRaises(Rejected):
            self.apply(p, now)
        self.assertEqual(before, recover(self.root))

    def test_valid_update(self):
        self.assertEqual(self.apply()['version'], 2)

    def test_payload_tampering(self):
        p = self.package()
        p['payload'] = base64.b64encode(b'evil').decode()
        self.rejected(p)

    def test_metadata_tampering(self):
        p = self.package()
        p['metadata']['version'] = 99
        self.rejected(p)

    def test_wrong_signing_key(self):
        p = self.package()
        p['signature'] = base64.b64encode(Ed25519PrivateKey.generate().sign(canonical(p['metadata']))).decode()
        self.rejected(p)

    def test_rollback(self):
        self.apply()
        self.rejected(self.package(version=1))

    def test_same_version_replay(self):
        self.apply()
        self.rejected(self.package())

    def test_expired_metadata(self):
        self.rejected(self.package(expires=999))

    def test_expiry_boundary(self):
        self.rejected(self.package(expires=1000))

    def test_forward_clock_drift(self):
        self.rejected(self.package(), now=3000)

    def test_backward_clock_drift_limit(self):
        self.assertEqual(self.apply(self.package(expires=900), now=800)['version'], 2)

    def test_target_traversal(self):
        self.rejected(self.package(target='../state.json'))

    def test_oversized_payload(self):
        self.rejected(self.package(payload=b'x' * (LIMIT + 1)))

    def test_boolean_version(self):
        self.rejected(self.package(version=True))

    def test_truncated_envelope(self):
        with self.assertRaises(Rejected):
            install(self.root, b'{', self.pub, 1000)
        self.assertEqual(recover(self.root)['version'], 1)

    def crash(self, stage, expected):
        p = self.root.parent / 'package.json'
        p.write_bytes(canonical(self.package()))
        k = self.root.parent / 'key'
        k.write_bytes(self.pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        r = subprocess.run([sys.executable, '-m', 'edge_update.guard', str(self.root), str(p), str(k), '--now', '1000', '--crash', stage], capture_output=True, timeout=10)
        self.assertIn(r.returncode, [91, 92, 93])
        self.assertEqual(recover(self.root)['version'], expected)
        if expected == 1:
            self.assertEqual(self.apply()['version'], 2)
        else:
            self.rejected(self.package(version=1))

    def test_process_crash_during_write(self):
        self.crash('during_write', 1)

    def test_process_crash_after_stage(self):
        self.crash('after_stage', 1)

    def test_process_crash_after_commit(self):
        self.crash('after_commit', 2)

    def test_committed_corruption_detected(self):
        s = self.apply()
        (self.root / 'slots' / s['digest']).write_bytes(b'broken')
        with self.assertRaises(Rejected):
            recover(self.root)

    def test_provisioning_reset(self):
        self.apply()
        reset(self.root)
        self.assertEqual(recover(self.root)['version'], 1)

    def test_concurrent_writers(self):
        p = canonical(self.package())
        out = []

        def run():
            try:
                out.append(install(self.root, p, self.pub, 1000)['version'])
            except Rejected:
                out.append('rejected')
        ts = [threading.Thread(target=run) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(out.count(2), 1)
        self.assertEqual(out.count('rejected'), 3)

    def network(self, mode):
        body = canonical(self.package())
        count = [0]

        class Handler(BaseHTTPRequestHandler):

            def log_message(self, *args):
                pass

            def do_GET(h):
                count[0] += 1
                if mode == 'intermittent' and count[0] == 1:
                    h.send_error(503)
                    return
                h.send_response(200)
                h.send_header('Content-Length', str(len(body)))
                h.end_headers()
                if mode == 'disconnect':
                    h.wfile.write(body[:100])
                    h.wfile.flush()
                    h.close_connection = True
                elif mode == 'slow':
                    for i in range(0, len(body), 100):
                        h.wfile.write(body[i:i + 100])
                        h.wfile.flush()
                        time.sleep(0.002)
                else:
                    h.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/package'
            if mode == 'disconnect':
                with self.assertRaises(Exception):
                    download(url)
                self.assertEqual(recover(self.root)['version'], 1)
            elif mode == 'intermittent':
                with self.assertRaises(Exception):
                    download(url)
                self.assertEqual(install(self.root, download(url), self.pub, 1000)['version'], 2)
                self.assertEqual(count[0], 2)
            else:
                self.assertEqual(install(self.root, download(url), self.pub, 1000)['version'], 2)
        finally:
            server.shutdown()
            server.server_close()
            t.join()

    def test_http_disconnect(self):
        self.network('disconnect')

    def test_http_intermittent_retry(self):
        self.network('intermittent')

    def test_http_throttled_transfer(self):
        self.network('slow')

    def test_offline_committed_image(self):
        self.apply()
        self.assertEqual(recover(self.root)['version'], 2)
