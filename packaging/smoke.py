"""Real non-root installed process, unit validation, upgrade and WAL recovery."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import ssl
import h2.config
import h2.connection
import h2.events
import threading
import subprocess
import time
import urllib.error
import urllib.request

bundle = Path('/bundle')
spec = importlib.util.spec_from_file_location('install', bundle / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
initial_release = installer.install(bundle, Path('/'))
account = pwd.getpwnam('rustwalld-dns')
assert 0 < account.pw_uid < 1000
subprocess.run(['systemd-analyze', 'verify', '/usr/lib/systemd/system/rustwalld-dns.service'], check=True)
config = Path('/etc/rustwalld-dns/config.toml')
config.write_text(config.read_text().replace('lists = []', 'lists = [{name="installed",action="block",rules="installed.test"}]'))
original_config = config.read_bytes()
secret = Path('/etc/rustwalld-dns/service.env').read_bytes()
token = secret.decode().strip().split('=', 1)[1]
binary = '/opt/rustwalld-dns/current/bin/rustwalld-dns'
subprocess.run([binary, '--config', str(config), '--check-config'], user=account.pw_uid, group=account.pw_gid, extra_groups=[], check=True)
checked = json.loads(subprocess.check_output(
    [binary, 'policy', 'test', '--config', str(config), '--format', 'json'],
    user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert checked['valid'] and checked['basis'] == 'permanent_policy'


def api(path, method='GET', body=None, etag=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if etag is not None:
        headers['If-Match'] = etag
    request = urllib.request.Request('http://127.0.0.1:8080' + path, method=method, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        content = response.read()
        return json.loads(content) if response.headers.get('Content-Type', '').startswith('application/json') else content


def configuration_tag():
    request = urllib.request.Request('http://127.0.0.1:8080/api/v1/config', headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, timeout=3) as response:
        response.read()
        return response.headers['ETag']


def start():
    child = subprocess.Popen([binary, '--config', str(config)], cwd='/var/lib/rustwalld-dns',
                             env={**os.environ, 'RUSTWALLD_API_TOKEN': token}, user=account.pw_uid,
                             group=account.pw_gid, extra_groups=[], stdout=subprocess.DEVNULL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert child.poll() is None
        try:
            api('/healthz')
            break
        except (OSError, urllib.error.URLError):
            time.sleep(.02)
    else:
        raise AssertionError('installed service did not become ready')
    assert Path(f'/proc/{child.pid}').stat().st_uid == account.pw_uid
    assert b'rustwall' in api('/').lower()
    return child


def stop(child):
    child.terminate()
    assert child.wait(timeout=10) == 0


def dns(domain, tcp=False, answer=False):
    labels = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.'))
    packet = bytes.fromhex('123401000001000000000000') + labels + bytes.fromhex('0000010001')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
        connection.settimeout(2)
        connection.connect(('127.0.0.1', 5353))
        if tcp:
            connection.sendall(len(packet).to_bytes(2, 'big') + packet)
            def exact(length):
                result = b''
                while len(result) < length:
                    chunk = connection.recv(length - len(result))
                    if not chunk:
                        raise ConnectionError('DNS TCP stream ended early')
                    result += chunk
                return result
            response = exact(int.from_bytes(exact(2), 'big'))
        else:
            connection.send(packet)
            response = connection.recv(1232)
    assert response[:2] == packet[:2]
    if answer:
        assert int.from_bytes(response[6:8], 'big') == 1 and response[-4:] == bytes([192, 0, 2, 1])
    return response[3] & 15


# Local strict TLS fixture; the container has no external network access.
fixture = Path('/tmp/tls-fixture')
fixture.mkdir(mode=0o700)
def openssl(*arguments):
    subprocess.run(['openssl', *arguments], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', str(fixture / 'ca-key.pem'), '-out', str(fixture / 'ca.pem'),
        '-subj', '/CN=Local fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-days', '1')
openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', str(fixture / 'key.pem'), '-out', str(fixture / 'request.pem'),
        '-subj', '/CN=resolver.test')
(fixture / 'extensions').write_text('subjectAltName=DNS:resolver.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
openssl('x509', '-req', '-in', str(fixture / 'request.pem'), '-CA', str(fixture / 'ca.pem'),
        '-CAkey', str(fixture / 'ca-key.pem'), '-CAcreateserial', '-out', str(fixture / 'cert.pem'),
        '-days', '1', '-extfile', str(fixture / 'extensions'))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(fixture / 'cert.pem', fixture / 'key.pem')
context.set_alpn_protocols(['h2'])
tls_listener = socket.socket()
tls_listener.bind(('127.0.0.1', 0))
tls_listener.listen(8)
tls_counts = {'connections': 0, 'queries': 0}


def wire_answer(query):
    assert 12 <= len(query) <= 4096
    end = 12
    while query[end] != 0:
        assert query[end] <= 63
        end += 1 + query[end]
    end += 5 # root label + qtype + qclass; exclude request EDNS
    response = query[:2] + bytes.fromhex('81800001000100000000') + query[12:end]
    return response + bytes.fromhex('c00c000100010000003c0004c0000201')


def https_mock(stream):
    connection = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding='ascii'))
    connection.initiate_connection()
    stream.sendall(connection.data_to_send())
    requests = {}
    while data := stream.recv(16384):
        for event in connection.receive_data(data):
            if isinstance(event, h2.events.RequestReceived):
                headers = dict(event.headers)
                assert headers[':method'] == 'POST' and headers[':path'] == '/dns-query'
                assert headers[':authority'].startswith('resolver.test:')
                assert headers['content-type'] == 'application/dns-message'
                requests[event.stream_id] = bytearray()
            elif isinstance(event, h2.events.DataReceived):
                requests[event.stream_id].extend(event.data)
                assert len(requests[event.stream_id]) <= 4096
                connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                query = bytes(requests.pop(event.stream_id))
                assert query[:2] == b'\0\0'
                response = wire_answer(query)
                tls_counts['queries'] += 1
                connection.send_headers(event.stream_id, [(':status', '200'), ('content-type', 'application/dns-message'), ('content-length', str(len(response)))])
                connection.send_data(event.stream_id, response, end_stream=True)
        stream.sendall(connection.data_to_send())


def tls_mock():
    def exact(connection, size):
        result = b''
        while len(result) < size:
            part = connection.recv(size - len(result))
            if not part:
                raise ConnectionError('fixture peer closed')
            result += part
        return result
    while True:
        connection, _ = tls_listener.accept()
        tls_counts['connections'] += 1
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                if stream.selected_alpn_protocol() == 'h2':
                    https_mock(stream)
                else:
                    while True:
                        size = int.from_bytes(exact(stream, 2), 'big')
                        response = wire_answer(exact(stream, size))
                        tls_counts['queries'] += 1
                        stream.sendall(len(response).to_bytes(2, 'big') + response)
        except (OSError, ConnectionError):
            connection.close()


threading.Thread(target=tls_mock, daemon=True).start()

# A separate publisher: pinned IP, private HTTPS trust, no bootstrap DNS query.
list_listener = socket.socket()
list_listener.bind(('127.0.0.1', 0))
list_listener.listen(1)
list_listener.settimeout(.2)
list_port = list_listener.getsockname()[1]
list_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
list_context.load_cert_chain(fixture / 'cert.pem', fixture / 'key.pem')
list_context.set_alpn_protocols(['http/1.1'])
list_stop = threading.Event()
list_requests = []
list_text = b'installed.test\nupgrade.test\n=downloaded.test\n'


def list_mock():
    while not list_stop.is_set():
        try:
            connection, _ = list_listener.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        connection.settimeout(3)
        with list_context.wrap_socket(connection, server_side=True) as stream:
            request = bytearray()
            while not request.endswith(b'\r\n\r\n'):
                request.extend(stream.recv(1))
                assert len(request) <= 4096
            assert request.startswith(b'GET /domains.txt HTTP/1.1\r\n')
            assert b'authorization:' not in request.lower()
            list_requests.append(bytes(request))
            tag = '"' + hashlib.sha256(list_text).hexdigest() + '"'
            conditional = b'if-none-match: ' + tag.encode() in request.lower()
            code = '304 Not Modified' if conditional else '200 OK'
            stream.sendall(f'HTTP/1.1 {code}\r\nETag: {tag}\r\nContent-Type: text/plain\r\nContent-Length: {len(list_text)}\r\nConnection: close\r\n\r\n'.encode() + (b'' if conditional else list_text))


list_thread = threading.Thread(target=list_mock, daemon=True)
list_thread.start()

process = start()
try:
    assert dns('installed.test') == 3
    assert dns('installed.test', tcp=True) == 3
    policy = api('/api/v1/config')
    policy['policies'][0]['lists'][0]['rules'] += '\nupgrade.test'
    policy['upstreams'][0]['addresses'] = [f'127.0.0.1:{tls_listener.getsockname()[1]}']
    policy['upstreams'][0]['transport'] = {'kind': 'tls', 'server_name': 'resolver.test',
                                         'ca_pem': (fixture / 'ca.pem').read_text(), 'max_connections': 2}
    assert api('/api/v1/config', 'PUT', policy)['generation'] == 2
    assert api('/api/v1/upstreams')[0]['transport'] == 'tls'
    assert dns('tls-one.test', answer=True) == 0 and dns('tls-two.test', tcp=True, answer=True) == 0
    assert tls_counts == {'connections': 1, 'queries': 2}
    policy['upstreams'][0]['transport']['kind'] = 'https'
    policy['upstreams'][0]['transport']['path'] = '/dns-query'
    assert api('/api/v1/config', 'PUT', policy)['generation'] == 3
    assert api('/api/v1/upstreams')[0]['transport'] == 'https'
    assert dns('https-one.test', answer=True) == 0 and dns('https-two.test', tcp=True, answer=True) == 0
    assert tls_counts == {'connections': 2, 'queries': 4}
    policy['filter_sources'] = [{'policy': 'default', 'list': 'installed',
                                'url': f'https://resolver.test:{list_port}/domains.txt',
                                'bootstrap_ips': ['127.0.0.1'], 'ca_pem': (fixture / 'ca.pem').read_text()}]
    downloaded = api('/api/v1/filter-sources/preview', 'POST', {'config': policy, 'source': 0}, etag=configuration_tag())
    policy = downloaded['config']
    assert downloaded['report']['valid'] and downloaded['changed']
    fingerprint = hashlib.sha256(list_text).hexdigest()
    assert policy['filter_sources'][0]['download']['sha256'] == fingerprint
    assert api('/api/v1/status')['generation'] == 3
    assert dns('downloaded.test', answer=True) == 0
    annotations = {'group': 'Work', 'owner': 'Operator', 'vlan': 20,
                   'tags': ['managed', 'laptop'], 'note': 'Fixed DHCP reservation'}
    policy['bindings'] = [{'name': 'Work laptop', 'network': '127.0.0.1/32',
                           'policy': 'default', 'metadata': annotations}]
    expiry = int(time.time()) + 3
    policy['policies'][0]['temporary_exceptions'] = [
        {'name': 'installed repair', 'domain': 'installed.test', 'expires_at': expiry}]
    policy['assertions'] = [{'client': '127.0.0.1', 'domain': 'installed.test', 'expected': 'block'}]
    assert api('/api/v1/policy/test', 'POST', policy)['basis'] == 'permanent_policy'
    assert api('/api/v1/config', 'PUT', policy)['generation'] == 4
    assert dns('downloaded.test') == 3
    assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == fingerprint
    assert api('/api/v1/clients')['bindings'][0]['metadata'] == annotations
    assert api('/api/v1/explain?client=127.0.0.1&domain=downloaded.test')['binding_metadata'] == annotations
    assert api('/api/v1/temporary-exceptions')['exceptions'][0]['active']
    assert dns('installed.test', answer=True) == 0
    assert dns('installed.test', tcp=True, answer=True) == 0
    # A changed scheduled retrieval is durable review work, never live promotion.
    policy['filter_sources'][0]['refresh_interval_secs'] = 300
    assert api('/api/v1/config', 'PUT', policy)['generation'] == 5
    def unchanged_check(expected_http):
        before = len(list_requests)
        api('/api/v1/filter-refreshes/check', 'POST', {'source': 0}, etag=configuration_tag())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = api('/api/v1/filter-refreshes')
            if len(list_requests) > before and status['running'] is None and status['entries'][0]['outcome'] == 'unchanged':
                break
            time.sleep(.02)
        else:
            raise AssertionError('unchanged conditional check did not complete')
        assert status['entries'][0]['last_http_status'] == expected_http
        assert status['entries'][0]['last_download_bytes'] == (0 if expected_http == 304 else len(list_text))
        assert api('/api/v1/status')['generation'] == 5
        assert api('/api/v1/shadow')['generation'] is None
        assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == fingerprint
    unchanged_check(200)
    unchanged_check(304)
    # Validator hints are runtime-only: process restart requires one full re-learning GET.
    stop(process)
    process = start()
    unchanged_check(200)
    unchanged_check(304)
    list_text += b'=scheduled.test\n'
    api('/api/v1/filter-refreshes/check', 'POST', {'source': 0}, etag=configuration_tag())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if api('/api/v1/shadow')['generation'] == 6:
            break
        time.sleep(.02)
    else:
        raise AssertionError('scheduled check did not stage a shadow')
    assert api('/api/v1/status')['generation'] == 5
    assert api('/api/v1/filter-refreshes')['paused'] == 'shadow_review'
    candidate_fingerprint = hashlib.sha256(list_text).hexdigest()
    assert api('/api/v1/shadow')['config']['filter_sources'][0]['download']['sha256'] == candidate_fingerprint
    assert dns('scheduled.test', answer=True) == 0
    backup = '/var/lib/rustwalld-dns/snapshot.sqlite'
    result = subprocess.check_output([binary, 'backup', '--database', '/var/lib/rustwalld-dns/rustwalld.sqlite', '--output', backup], user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    assert json.loads(result)['active_generation'] == 5
    assert json.loads(result)['shadow_generation'] == 6
    assert json.loads(result)['schema'] == 2
finally:
    stop(process)
list_stop.set()
list_listener.close()
list_thread.join(timeout=3)
assert not list_thread.is_alive() and len(list_requests) == 6
while time.time() <= expiry:
    time.sleep(.05)
# Simulate a release with different bundle content, leaving the binary schema intact.
upgrade = Path('/tmp/upgrade')
shutil.copytree(bundle, upgrade)
readme = upgrade / 'README.md'
readme.write_bytes(readme.read_bytes() + b'\nUpgrade verification fixture.\n')
manifest = json.loads((upgrade / 'manifest.json').read_text())
manifest['files']['README.md'] = hashlib.sha256(readme.read_bytes()).hexdigest()
manifest['release_id'] = manifest['release_id'].rsplit('-', 1)[0] + '-' + hashlib.sha256(readme.read_bytes()).hexdigest()[:16]
(upgrade / 'manifest.json').write_text(json.dumps(manifest))
final_release = installer.install(upgrade, Path('/'))
assert final_release != initial_release and initial_release.is_dir()
assert config.read_bytes() == original_config
assert Path('/etc/rustwalld-dns/service.env').read_bytes() == secret
process = start()
try:
    assert api('/api/v1/status')['generation'] == 5
    assert api('/api/v1/shadow')['generation'] == 6
    assert api('/api/v1/filter-refreshes')['paused'] == 'shadow_review'
    assert api('/api/v1/filter-sources')['sources'][0]['refresh_interval_secs'] == 300
    assert dns('scheduled.test', answer=True) == 0
    assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == fingerprint
    assert api('/api/v1/clients')['bindings'][0]['metadata'] == annotations
    assert api('/api/v1/explain?client=127.0.0.1&domain=downloaded.test')['binding_metadata'] == annotations
    assert dns('downloaded.test') == 3
    exception = api('/api/v1/temporary-exceptions')['exceptions'][0]
    assert exception['expires_at'] == expiry and not exception['active']
    restored_upstream = api('/api/v1/upstreams')[0]
    assert restored_upstream['transport'] == 'https' and restored_upstream['path'] == '/dns-query'
    assert dns('upgrade.test') == 3
    assert dns('installed.test') == 3
    assert dns('https-after-upgrade.test', answer=True) == 0
finally:
    stop(process)
# Restore only after removing the original DB and all associated sidecars as a set.
recovery = Path('/var/lib/rustwalld-dns/recovery')
recovery.mkdir(mode=0o700)
for suffix in ('', '-wal', '-shm', '-journal'):
    path = Path('/var/lib/rustwalld-dns/rustwalld.sqlite' + suffix)
    if path.exists():
        path.rename(recovery / path.name)
subprocess.run([binary, 'restore', '--backup', backup, '--database', '/var/lib/rustwalld-dns/rustwalld.sqlite'], user=account.pw_uid, group=account.pw_gid, extra_groups=[], check=True)
process = start()
try:
    assert api('/api/v1/status')['generation'] == 5
    assert api('/api/v1/shadow')['generation'] == 6
    assert api('/api/v1/filter-refreshes')['paused'] == 'shadow_review'
    assert api('/api/v1/filter-sources')['sources'][0]['refresh_interval_secs'] == 300
    assert dns('scheduled.test', answer=True) == 0
    assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == fingerprint
    assert api('/api/v1/clients')['bindings'][0]['metadata'] == annotations
    assert api('/api/v1/explain?client=127.0.0.1&domain=downloaded.test')['binding_metadata'] == annotations
    assert dns('downloaded.test') == 3
    exception = api('/api/v1/temporary-exceptions')['exceptions'][0]
    assert exception['expires_at'] == expiry and not exception['active']
    restored_upstream = api('/api/v1/upstreams')[0]
    assert restored_upstream['transport'] == 'https' and restored_upstream['path'] == '/dns-query'
    assert dns('installed.test') == 3 and dns('upgrade.test') == 3
    assert dns('https-after-restore.test', answer=True) == 0
    assert api('/api/v1/shadow/promote', 'POST', {}, etag=configuration_tag())['generation'] == 7
    assert dns('scheduled.test') == 3
    assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == candidate_fingerprint
finally:
    stop(process)
print('PASS: clean non-root installation, UDP/TCP clients, authenticated warm DoT/HTTP2 DoH, reviewed HTTPS lists with offline-publisher recovery, conditional 200/304/restart retrieval, scheduled shadow backup/upgrade/recovery with offline publisher and explicit promotion, binding annotations, temporary allows and permanent assertions, unit validation, upgrade preservation, schema-2 WAL snapshot and expired-exception recovery; native sandbox activation not exercised')
