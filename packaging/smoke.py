"""Real non-root installed process, unit validation, upgrade and WAL recovery."""
import hashlib
import zipfile
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import socket
import struct
import ssl
import h2.config
import h2.connection
import h2.events
import threading
import subprocess
import time
import tomllib
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
assert tomllib.loads(config.read_text())['serve_stale_max_staleness_secs'] == 0
# Enable only this isolated smoke appliance; shipped defaults stay disabled.
config.write_text(config.read_text()
                  .replace('serve_stale_max_staleness_secs = 0', 'serve_stale_max_staleness_secs = 120')
                  .replace('lists = []', 'lists = [{name="installed",action="block",rules="installed.test"}]'))
original_config = config.read_bytes()
secret = Path('/etc/rustwalld-dns/service.env').read_bytes()
token = secret.decode().strip().split('=', 1)[1]
binary = '/opt/rustwalld-dns/current/bin/rustwalld-dns'
subprocess.run([binary, '--config', str(config), '--check-config'], user=account.pw_uid, group=account.pw_gid, extra_groups=[], check=True)
checked = json.loads(subprocess.check_output(
    [binary, 'policy', 'test', '--config', str(config), '--format', 'json'],
    user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert checked['valid'] and checked['basis'] == 'permanent_policy'

# Offline client migration on the installed non-root release, without resolver I/O.
client_source = Path('/tmp/adguard-client-fixture.yaml')
client_source.write_text("dns: {upstream_dns: ['127.0.0.1:15401', '[/child.test/]127.0.0.1:15402']}\nclients: {persistent: [{name: Work, ids: [127.0.0.2], tags: [user_child], use_global_settings: true, upstreams: ['127.0.0.1:15402']}, {name: Shared, ids: [127.0.0.3], upstreams: ['127.0.0.1:15402']}]}\nfiltering: {rewrites: [{domain: cli-active.home.arpa, answer: 192.0.2.10, enabled: true}, {domain: cli-disabled.home.arpa, answer: 192.0.2.11, enabled: false}, {domain: cli-pass.test, answer: A}]}\nuser_rules: [installed.test, cli-pass.test, '||cancelled.test^', '||cancelled.test^$badfilter', '||scoped.test^$denyallow=safe.scoped.test|work.scoped.test', '||typed.fixture^$dnstype=AAAA,denyallow=safe.typed.fixture', '||client.fixture^$client=Work|127.0.0.1,dnstype=AAAA']\n")
client_source.chmod(0o644)
client_report = json.loads(subprocess.check_output([binary, 'migrate', '--source', 'adguard', '--input', str(client_source), '--base-config', str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert client_report['ready']
assert all(policy['ds_routing']=='parent' for policy in client_report['config']['policies'])
assert client_report['config']['policies'][0]['lists'][0]['syntax']=='adguard_v6'
assert client_report['config']['bindings'][0]['filter_tags']==['user_child']
assert all([record['domain'] for record in policy['dns_records']]==['cli-active.home.arpa','cli-pass.test'] for policy in client_report['config']['policies'])
assert client_report['validation']['list_stats'][0]['lists'][0]['disabled']==1
client_draft = client_report['config']
assert client_draft['policies'][1]['upstream'] == client_draft['policies'][2]['upstream'] != client_draft['policies'][0]['upstream']
assert len(client_draft['upstreams']) == 3
assert client_draft['bindings'][0]['network'] == '127.0.0.2/32'
assert config.read_bytes() == original_config
rewrite_source = Path('/tmp/adguard-rewrite-layout.yaml')
rewrite_source.write_text("schema_version: 34\nfiltering: {rewrites_enabled: false, rewrites: [{domain: cli-globally-off.home.arpa, answer: 192.0.2.12, enabled: true}]}\nuser_rules: [installed.test]\n")
rewrite_source.chmod(0o644)
off_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert off_report['ready']
assert all(not policy.get('dns_records',[]) for policy in off_report['config']['policies'])
assert any(issue['field']=='filtering.rewrites_enabled' and issue['severity']=='info' for issue in off_report['issues'])
rewrite_source.write_text("schema_version: 25\ndns: {rewrites: [{domain: cli-old-pass.test, answer: A}]}\nuser_rules: [installed.test, cli-old-pass.test]\n")
old_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert old_report['ready']
assert old_report['config']['policies'][0]['dns_records'][0]['data']=={'type':'PASSTHROUGH','family':'A'}
old_draft=old_report['config']
for schema,container,entry in [(34,'dns','{domain: cli-incompatible.test, answer: 192.0.2.13}'),(30,'filtering','{domain: cli-incompatible.test, answer: 192.0.2.13, enabled: false}')]:
    rewrite_source.write_text(f"schema_version: {schema}\n{container}: {{rewrites: [{entry}]}}\nuser_rules: [installed.test]\n")
    conflict=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    assert conflict.returncode==1
    conflict_report=json.loads(conflict.stdout)
    assert not conflict_report['ready'] and all(not policy.get('dns_records',[]) for policy in conflict_report['config']['policies'])
    assert any(issue['severity']=='blocker' for issue in conflict_report['issues'])
for schema,container in [(25,'dns'),(34,'filtering')]:
    rewrite_source.write_text(f"schema_version: {schema}\n{container}: {{rewrites: [{{domain: '*.wild.home.arpa', answer: 192.0.2.40}}, {{domain: '*.wild.home.arpa', answer: '2001:db8::40'}}]}}\n")
    wildcard_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
    assert wildcard_report['ready']
    assert [record['domain'] for record in wildcard_report['config']['policies'][0]['dns_records']]==['*.wild.home.arpa','*.wild.home.arpa']
rewrite_source.write_text("filtering: {rewrites: [{domain: '*.wild.home.arpa', answer: A}]}\n")
wildcard_blocked=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
assert wildcard_blocked.returncode==1 and not json.loads(wildcard_blocked.stdout)['ready']
rewrite_source.write_text("schema_version: 34\nfiltering: {protection_enabled: false, blocked_response_ttl: 17, rewrites_enabled: false}\nuser_rules: ['||pattern.home.arpa^$dnsrewrite=192.0.2.50', '||pattern.home.arpa^$dnsrewrite=NOERROR;AAAA;2001:db8::50']\nclients: {persistent: [{name: Off, ids: [127.0.0.2], use_global_settings: false, filtering_enabled: false}]}\n")
pattern_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert pattern_report['ready'] and len(pattern_report['config']['policies'][0]['dns_records'])==4
assert all(record['ttl']==17 for record in pattern_report['config']['policies'][0]['dns_records'])
assert not pattern_report['config']['policies'][1].get('dns_records',[])
with zipfile.ZipFile(rewrite_source,"w",compression=zipfile.ZIP_STORED) as backup:
    backup.writestr("AdGuardHome.yaml", "filtering: {blocked_response_ttl: 17}\nfilters: [{id: 7, enabled: true}]\nuser_rules: ['|pool.home.arpa^$dnsrewrite=192.0.2.10', '|sets-cancelled.test^$dnsrewrite=192.0.2.10']\n")
    backup.writestr("data/filters/7.txt", "|pool.home.arpa^$dnsrewrite=192.0.2.20\n|pool.home.arpa^$dnsrewrite=192.0.2.30\n|pool.home.arpa^$dnsrewrite=2001:db8::20\n@@|pool.home.arpa|$dnsrewrite=192.0.2.10\n@@|sets-cancelled.test|$dnsrewrite\n")
sets_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert sets_report['ready'] and len(sets_report['config']['policies'][0]['dns_records'])==3
assert [record['data']['address'] for record in sets_report['config']['policies'][0]['dns_records']]==['192.0.2.20','192.0.2.30','2001:db8::20']
pattern_report['config']['policies'][0]['dns_records'].extend(sets_report['config']['policies'][0]['dns_records'])
with zipfile.ZipFile(rewrite_source,"w",compression=zipfile.ZIP_STORED) as backup:
    backup.writestr("AdGuardHome.yaml", "filtering: {blocked_response_ttl: 17}\nfilters: [{id: 8, enabled: true}]\nuser_rules: ['||typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed']\n")
    backup.writestr("data/filters/8.txt", "||typed.home.arpa^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture\n||typed.home.arpa^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.\n||typed.home.arpa^$dnsrewrite=NOERROR;MX;10 MAIL.home.arpa\n||typed.home.arpa^$dnsrewrite=NOERROR;SRV;1 2 8443 SERVICE.home.arpa\n@@||typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed\n")
typed_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert typed_report['ready'] and len(typed_report['config']['policies'][0]['dns_records'])==8
assert {record['data']['type'] for record in typed_report['config']['policies'][0]['dns_records']}=={'TXT','PTR','MX','SRV'}
assert all(record['ttl']==17 for record in typed_report['config']['policies'][0]['dns_records'])
pattern_report['config']['policies'][0]['dns_records'].extend(typed_report['config']['policies'][0]['dns_records'])
with zipfile.ZipFile(rewrite_source,"w",compression=zipfile.ZIP_STORED) as backup:
    backup.writestr("AdGuardHome.yaml", "filtering: {blocked_response_ttl: 17}\nfilters: [{id: 9, enabled: true}]\nuser_rules: ['||cancelled-binding.test^$dnsrewrite=NOERROR;HTTPS;1 .']\n")
    backup.writestr("data/filters/9.txt", "||binding.home.arpa^$dnsrewrite=NOERROR;HTTPS;1 . port=8443\n||binding.home.arpa^$dnsrewrite=NOERROR;SVCB;0 ENDPOINT.home.arpa\n@@||cancelled-binding.test^$dnsrewrite\n")
binding_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert binding_report['ready'] and len(binding_report['config']['policies'][0]['dns_records'])==4
assert {record['data']['type'] for record in binding_report['config']['policies'][0]['dns_records']}=={'HTTPS','SVCB'}
assert all(record['ttl']==17 for record in binding_report['config']['policies'][0]['dns_records'])
pattern_report['config']['policies'][0]['dns_records'].extend(binding_report['config']['policies'][0]['dns_records'])
rewrite_source.write_text("user_rules: ['||pool.home.arpa^$dnsrewrite=192.0.2.10', '@@|pool.home.arpa^$dnsrewrite']\n")
sets_blocked=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
assert sets_blocked.returncode==1 and not json.loads(sets_blocked.stdout)['ready']
rewrite_source.write_text("filtering: {filtering_enabled: false, rewrites: [{domain: legacy-off.home.arpa, answer: 192.0.2.20}]}\nuser_rules: ['||pattern.home.arpa^$dnsrewrite=192.0.2.50']\n")
filtering_off_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)], user=account.pw_uid, group=account.pw_gid, extra_groups=[]))
assert filtering_off_report['ready'] and not filtering_off_report['config']['policies'][0].get('dns_records',[])
rewrite_source.write_text("user_rules: ['||pattern.home.arpa^$dnsrewrite=192.0.2.50', '||deep.pattern.home.arpa^$dnsrewrite=192.0.2.51']\n")
pattern_blocked=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
assert pattern_blocked.returncode==1 and not json.loads(pattern_blocked.stdout)['ready']
rewrite_source.unlink()
client_source.unlink()


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


def dns_name(message, offset):
    labels = []
    end = None
    for _ in range(128):
        length = message[offset]
        if length & 0xc0 == 0xc0:
            if end is None:
                end = offset + 2
            offset = int.from_bytes(message[offset:offset + 2], 'big') & 0x3fff
        elif length == 0:
            return '.'.join(labels), end if end is not None else offset + 1
        else:
            assert length <= 63
            labels.append(message[offset + 1:offset + 1 + length].decode('ascii'))
            offset += length + 1
    raise AssertionError('fixture DNS name loop')


def dns(domain, tcp=False, answer=False, ttl=None, cname=None, ttl_max=None, qtype=1, wildcard_address=None, expected_ttl=60, rrset_addresses=None, expected_data=None):
    labels = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.'))
    packet = bytes.fromhex('123401000001000000000000') + labels + b'\0' + (5 if cname else qtype).to_bytes(2, 'big') + b'\0\1'
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
    if expected_data is not None:
        assert response[3]&15==0 and int.from_bytes(response[6:8],'big')==1
        owner,offset=dns_name(response,len(packet))
        assert owner==domain
        kind,rrclass,lifetime,length=struct.unpack_from('!HHIH',response,offset)
        assert kind==qtype and rrclass==1 and 0<lifetime<=expected_ttl
        start=offset+10;end=start+length
        if kind==16:
            text=expected_data[0].encode('ascii')
            assert response[start:end]==bytes([len(text)])+text
        elif kind==12:
            target,consumed=dns_name(response,start)
            assert (target,)==expected_data and consumed==end
        elif kind==15:
            target,consumed=dns_name(response,start+2)
            assert (struct.unpack_from('!H',response,start)[0],target)==expected_data and consumed==end
        elif kind==33:
            target,consumed=dns_name(response,start+6)
            assert (*struct.unpack_from('!HHH',response,start),target)==expected_data and consumed==end
        elif kind in [64,65]:
            target,consumed=dns_name(response,start+2)
            assert (struct.unpack_from('!H',response,start)[0],target or '.')==expected_data[:2]
            if len(expected_data)==3:
                assert struct.unpack_from('!HHH',response,consumed)==(3,2,expected_data[2]) and consumed+6==end
            else:
                assert consumed==end
        else:
            raise AssertionError('unsupported typed recovery fixture')
    if rrset_addresses:
        assert response[3]&15==0 and int.from_bytes(response[6:8],'big')==len(rrset_addresses)
        offset=len(packet);found=[]
        for _ in rrset_addresses:
            owner,offset=dns_name(response,offset)
            assert owner==domain
            kind,rrclass,lifetime,length=struct.unpack_from('!HHIH',response,offset)
            assert kind==qtype and rrclass==1 and 0<lifetime<=expected_ttl
            found.append(socket.inet_ntop(socket.AF_INET if qtype==1 else socket.AF_INET6,response[offset+10:offset+10+length]))
            offset+=10+length
        assert sorted(found)==sorted(rrset_addresses)
    if wildcard_address:
        assert response[3] & 15 == 0 and int.from_bytes(response[6:8], 'big') == 1
        owner, offset = dns_name(response, len(packet))
        assert owner == domain
        kind, rrclass, lifetime, length = struct.unpack_from('!HHIH', response, offset)
        assert kind == qtype and rrclass == 1 and 0 < lifetime <= expected_ttl
        assert response[offset+10:offset+10+length] == socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, wildcard_address)
    if answer:
        assert int.from_bytes(response[6:8], 'big') == 1 and response[-4:] == bytes([192, 0, 2, 1])
        if ttl is not None or ttl_max is not None:
            assert response[8:12] == b'\0\0\0\0' # no other records after the A answer
            actual_ttl = int.from_bytes(response[-10:-6], 'big')
            if ttl is not None:
                assert actual_ttl == ttl
            if ttl_max is not None:
                assert 0 <= actual_ttl <= ttl_max
    if cname:
        assert response[3] & 15 == 0 and int.from_bytes(response[6:8], 'big') == 1
        _, offset = dns_name(response, len(packet))
        assert int.from_bytes(response[offset:offset + 2], 'big') == 5
        assert dns_name(response, offset + 10)[0] == cname
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
tls_reply = {'ttl': 60, 'servfail': False}


def wire_answer(query):
    assert 12 <= len(query) <= 4096
    end = 12
    while query[end] != 0:
        assert query[end] <= 63
        end += 1 + query[end]
    end += 5 # root label + qtype + qclass; exclude request EDNS
    if tls_reply['servfail']:
        return query[:2] + bytes.fromhex('81820001000000000000') + query[12:end]
    response = query[:2] + bytes.fromhex('81800001000100000000') + query[12:end]
    return response + bytes.fromhex('c00c00010001') + tls_reply['ttl'].to_bytes(4, 'big') + bytes.fromhex('0004c0000201')


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
    # Exercise a real schema-four-to-six boot with retained legacy rows.
    stop(process)
    with sqlite3.connect('/var/lib/rustwalld-dns/rustwalld.sqlite') as legacy:
        assert legacy.execute('PRAGMA user_version').fetchone()[0] == 6
        assert legacy.execute('SELECT COUNT(*) FROM queries').fetchone()[0] >= 2
        legacy.execute('ALTER TABLE queries DROP COLUMN service_schedule')
        legacy.execute('ALTER TABLE queries DROP COLUMN matched_type')
        legacy.execute('PRAGMA user_version=4')
    process = start()
    with sqlite3.connect('/var/lib/rustwalld-dns/rustwalld.sqlite') as migrated:
        assert migrated.execute('PRAGMA user_version').fetchone()[0] == 6
        assert migrated.execute('SELECT COUNT(*) FROM queries WHERE service_schedule IS NULL').fetchone()[0] >= 2
    policy = api('/api/v1/config')
    policy['policies'][0].setdefault('dns_records', []).extend(client_draft['policies'][0]['dns_records'])
    policy['policies'][0]['dns_records'].extend(old_draft['policies'][0]['dns_records'])
    policy['policies'][0]['dns_records'].extend(wildcard_report['config']['policies'][0]['dns_records'])
    policy['policies'][0]['dns_records'].extend(pattern_report['config']['policies'][0]['dns_records'])
    policy['policies'][0]['lists'][0]['rules'] += '\nupgrade.test'
    cancellation_list = {'name': 'cancellations', 'action': 'block', 'syntax': 'adguard_v3', 'rules': '||cancelled.test^\n||cancelled.test^$badfilter\n||scoped.test^$denyallow=safe.scoped.test|work.scoped.test\n||cli-pass.test^\n||cli-old-pass.test^'}
    policy['policies'][0]['lists'].append(cancellation_list)
    policy['policies'][0]['lists'].append({'name':'types','syntax':'adguard_v4','action':'block','rules':'||typed.fixture^$dnstype=AAAA,denyallow=safe.typed.fixture'})
    policy['assertions'].append({'client':'127.0.0.1','domain':'typed.fixture','qtype':28,'expected':'block'})
    policy['policies'][0]['lists'].append({'name':'tags','syntax':'adguard_v6','action':'block','rules':'||tag.fixture^$ctag=user_child,dnstype=A|AAAA'})
    policy['policies'][0]['lists'].append({'name':'clients','syntax':'adguard_v5','action':'block','rules':"||client.fixture^$client='Work laptop'|127.0.0.1,dnstype=A|AAAA"})
    safe_search = {'catalog_version': 1, 'google': True, 'bing': False,
                   'duckduckgo': False, 'youtube': 'strict'}
    policy['policies'][0]['safe_search'] = safe_search
    weekly = {'time_zone': 'UTC', 'mode': 'block', 'windows': [{'days': ['mon','tue','wed','thu','fri','sat','sun'], 'start': '00:00', 'end': '24:00'}]}
    blocked_services = {'catalog_version': 2, 'ids': ['discord', 'tiktok', 'netflix', 'whatsapp'], 'schedule': weekly}
    policy['policies'][0]['blocked_services'] = blocked_services
    policy['upstreams'][0]['addresses'] = [f'127.0.0.1:{tls_listener.getsockname()[1]}']
    policy['upstreams'][0]['transport'] = {'kind': 'tls', 'server_name': 'resolver.test',
                                         'ca_pem': (fixture / 'ca.pem').read_text(), 'max_connections': 2}
    assert api('/api/v1/config', 'PUT', policy, etag=configuration_tag())['generation'] == 2
    assert api('/api/v1/upstreams')[0]['transport'] == 'tls'
    assert dns('www.tiktok.com') == 3
    assert dns('www.netflix.com') == 3
    assert dns('web.whatsapp.com', tcp=True) == 3
    assert dns('discord.gg', tcp=True) == 3
    assert api('/api/v1/config')['policies'][0]['blocked_services'] == blocked_services
    assert api('/api/v1/policies')[0]['service_schedule']['state'] == 'active'
    assert dns('www.google.com', cname='forcesafesearch.google.com') == 0
    assert dns('www.youtube.com', tcp=True, cname='restrict.youtube.com') == 0
    assert dns('tls-one.test', answer=True) == 0 and dns('tls-two.test', tcp=True, answer=True) == 0
    assert tls_counts == {'connections': 1, 'queries': 2}
    policy['upstreams'][0]['transport']['kind'] = 'https'
    policy['upstreams'][0]['transport']['path'] = '/dns-query'
    assert api('/api/v1/config', 'PUT', policy, etag=configuration_tag())['generation'] == 3
    assert api('/api/v1/upstreams')[0]['transport'] == 'https'
    assert dns('https-one.test', answer=True) == 0 and dns('https-two.test', tcp=True, answer=True) == 0
    assert tls_counts == {'connections': 2, 'queries': 4}
    # Verify opt-in serve-stale and both ingress transports. The weekly policy
    # may shorten private TTLs at a minute boundary, including the warm reply.
    tls_reply['ttl'] = 1
    assert dns('stale.test', answer=True, ttl_max=1) == 0
    time.sleep(1.2)
    tls_reply['servfail'] = True
    before = tls_counts['queries']
    try:
        assert dns('stale.test', answer=True, ttl_max=30) == 0
        assert dns('stale.test', tcp=True, answer=True, ttl_max=30) == 0
        assert dns('uncached-outage.test') == 2
        assert tls_counts['queries'] == before + 3 # every lookup attempted the failing upstream
        metrics = api('/metrics').decode()
        assert 'rustwalld_stale_answers_total 2' in metrics.splitlines()
    finally:
        tls_reply.update(ttl=60, servfail=False)
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
                           'policy': 'default', 'filter_tags':['user_child'], 'metadata': annotations}]
    expiry = int(time.time()) + 3
    policy['policies'][0]['temporary_exceptions'] = [
        {'name': 'installed repair', 'domain': 'installed.test', 'expires_at': expiry}]
    policy['policies'][0]['ds_routing'] = 'parent'
    policy['assertions'] = [{'client': '127.0.0.1', 'domain': 'installed.test', 'expected': 'block'}, {'client':'127.0.0.1','domain':'typed.fixture','qtype':28,'expected':'block'}, {'client':'127.0.0.1','domain':'client.fixture','qtype':1,'expected':'block'}, {'client':'127.0.0.1','domain':'tag.fixture','qtype':1,'expected':'block'}]
    assert api('/api/v1/policy/test', 'POST', policy)['basis'] == 'permanent_policy'
    assert api('/api/v1/config', 'PUT', policy, etag=configuration_tag())['generation'] == 4
    assert dns('downloaded.test') == 3
    assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == fingerprint
    assert api('/api/v1/clients')['bindings'][0]['metadata'] == annotations
    assert api('/api/v1/explain?client=127.0.0.1&domain=downloaded.test')['binding_metadata'] == annotations
    assert api('/api/v1/temporary-exceptions')['exceptions'][0]['active']
    assert dns('installed.test', answer=True) == 0
    assert dns('installed.test', tcp=True, answer=True) == 0
    # A changed scheduled retrieval is durable review work, never live promotion.
    policy['filter_sources'][0]['refresh_interval_secs'] = 300
    assert api('/api/v1/config', 'PUT', policy, etag=configuration_tag())['generation'] == 5
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
    assert json.loads(result)['schema'] == 6
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
    assert api('/api/v1/config')['policies'][0]['safe_search'] == safe_search
    assert api('/api/v1/shadow')['config']['policies'][0]['safe_search'] == safe_search
    assert api('/api/v1/config')['policies'][0]['ds_routing'] == 'parent'
    assert api('/api/v1/shadow')['config']['policies'][0]['ds_routing'] == 'parent'
    assert dns('www.tiktok.com') == 3
    assert dns('www.netflix.com') == 3
    assert dns('web.whatsapp.com', tcp=True) == 3
    assert dns('discord.gg', tcp=True) == 3
    assert api('/api/v1/config')['policies'][0]['blocked_services'] == blocked_services
    assert api('/api/v1/policies')[0]['service_schedule']['state'] == 'active'
    assert dns('www.google.com', cname='forcesafesearch.google.com') == 0
    assert dns('www.youtube.com', tcp=True, cname='restrict.youtube.com') == 0
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
    assert api('/api/v1/explain?client=127.0.0.1&domain=safe.scoped.test')['decision']['action']=='allow'
    assert dns('typed.fixture',qtype=28)==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-active.home.arpa')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=cli-disabled.home.arpa')['rewrite']
    passthrough=api('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=1')
    assert not passthrough['rewrite'] and passthrough['decision']['action']=='block'
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=28')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=cli-globally-off.home.arpa')['rewrite']
    old_pass=api('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=1')
    assert not old_pass['rewrite'] and old_pass['decision']['action']=='block'
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=28')['rewrite']
    assert api('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=1')['rewrite']
    assert api('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=28')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=wild.home.arpa')['rewrite']
    for transport in [False,True]:
        assert dns('pool.home.arpa',tcp=transport,rrset_addresses=['192.0.2.20','192.0.2.30'],expected_ttl=17)==0
        assert dns('pool.home.arpa',tcp=transport,qtype=28,rrset_addresses=['2001:db8::20'],expected_ttl=17)==0
    for transport in [False,True]:
        for kind,data in [(16,('v=spf1 -all;fixture',)),(12,('nas.home.arpa',)),(15,(10,'mail.home.arpa')),(33,(1,2,8443,'service.home.arpa'))]:
            for typed_domain in ['typed.home.arpa','child.typed.home.arpa','a.b.typed.home.arpa']:
                assert dns(typed_domain,tcp=transport,qtype=kind,expected_data=data,expected_ttl=17)==0
        for binding_domain in ['binding.home.arpa','child.binding.home.arpa','a.b.binding.home.arpa']:
            for binding_kind,binding_data in [(65,(1,'.',8443)),(64,(0,'endpoint.home.arpa'))]:
                assert dns(binding_domain,tcp=transport,qtype=binding_kind,expected_data=binding_data,expected_ttl=17)==0
    for domain in ['pattern.home.arpa','nas.pattern.home.arpa']:
        for transport in [False,True]:
            for kind,address in [(1,'192.0.2.50'),(28,'2001:db8::50')]:
                assert dns(domain,tcp=transport,qtype=kind,wildcard_address=address,expected_ttl=17)==0
    for transport in [False, True]:
        for kind, address in [(1,'192.0.2.40'),(28,'2001:db8::40')]:
            assert dns('nas.deep.wild.home.arpa',tcp=transport,qtype=kind,wildcard_address=address)==0
    assert dns('tag.fixture')==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')['rule']['ctag']['include']==['user_child']
    assert api('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')['filter_tags']==['user_child']
    assert dns('client.fixture')==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=client.fixture')['rule']['client']['include']==['127.0.0.1/32','Work laptop']
    assert api('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=28')['rule']['dnstype']['include']==[28]
    assert api('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=1')['decision']['action']=='allow'
    assert api('/api/v1/explain?client=127.0.0.1&domain=tracking.scoped.test')['rule']['denyallow']==['safe.scoped.test','work.scoped.test']
    restored_upstream = api('/api/v1/upstreams')[0]
    assert restored_upstream['transport'] == 'https' and restored_upstream['path'] == '/dns-query'
    assert dns('upgrade.test') == 3
    assert dns('installed.test') == 3
    assert dns('https-after-upgrade.test', answer=True) == 0
    assert api('/api/v1/config')['policies'][0]['lists'][1] == cancellation_list
    assert api('/api/v1/shadow')['config']['policies'][0]['lists'][1] == cancellation_list
    assert api('/api/v1/explain?client=127.0.0.1&domain=safe.scoped.test')['decision']['action']=='allow'
    assert dns('typed.fixture',qtype=28)==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-active.home.arpa')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=cli-disabled.home.arpa')['rewrite']
    passthrough=api('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=1')
    assert not passthrough['rewrite'] and passthrough['decision']['action']=='block'
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=28')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=cli-globally-off.home.arpa')['rewrite']
    old_pass=api('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=1')
    assert not old_pass['rewrite'] and old_pass['decision']['action']=='block'
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=28')['rewrite']
    assert api('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=1')['rewrite']
    assert api('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=28')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=wild.home.arpa')['rewrite']
    for transport in [False,True]:
        assert dns('pool.home.arpa',tcp=transport,rrset_addresses=['192.0.2.20','192.0.2.30'],expected_ttl=17)==0
        assert dns('pool.home.arpa',tcp=transport,qtype=28,rrset_addresses=['2001:db8::20'],expected_ttl=17)==0
    for transport in [False,True]:
        for kind,data in [(16,('v=spf1 -all;fixture',)),(12,('nas.home.arpa',)),(15,(10,'mail.home.arpa')),(33,(1,2,8443,'service.home.arpa'))]:
            for typed_domain in ['typed.home.arpa','child.typed.home.arpa','a.b.typed.home.arpa']:
                assert dns(typed_domain,tcp=transport,qtype=kind,expected_data=data,expected_ttl=17)==0
        for binding_domain in ['binding.home.arpa','child.binding.home.arpa','a.b.binding.home.arpa']:
            for binding_kind,binding_data in [(65,(1,'.',8443)),(64,(0,'endpoint.home.arpa'))]:
                assert dns(binding_domain,tcp=transport,qtype=binding_kind,expected_data=binding_data,expected_ttl=17)==0
    for domain in ['pattern.home.arpa','nas.pattern.home.arpa']:
        for transport in [False,True]:
            for kind,address in [(1,'192.0.2.50'),(28,'2001:db8::50')]:
                assert dns(domain,tcp=transport,qtype=kind,wildcard_address=address,expected_ttl=17)==0
    for transport in [False, True]:
        for kind, address in [(1,'192.0.2.40'),(28,'2001:db8::40')]:
            assert dns('nas.deep.wild.home.arpa',tcp=transport,qtype=kind,wildcard_address=address)==0
    assert dns('tag.fixture')==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')['rule']['ctag']['include']==['user_child']
    assert api('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')['filter_tags']==['user_child']
    assert dns('client.fixture')==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=client.fixture')['rule']['client']['include']==['127.0.0.1/32','Work laptop']
    assert api('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=28')['rule']['dnstype']['include']==[28]
    assert api('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=1')['decision']['action']=='allow'
    assert api('/api/v1/explain?client=127.0.0.1&domain=tracking.scoped.test')['rule']['denyallow']==['safe.scoped.test','work.scoped.test']
    assert api('/api/v1/filter-lists')[0]['cancellations'][0]['disabled'] == 1
    assert dns('cancelled.test', answer=True) == 0
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
    assert api('/api/v1/config')['policies'][0]['safe_search'] == safe_search
    assert api('/api/v1/shadow')['config']['policies'][0]['safe_search'] == safe_search
    assert api('/api/v1/config')['policies'][0]['ds_routing'] == 'parent'
    assert api('/api/v1/shadow')['config']['policies'][0]['ds_routing'] == 'parent'
    assert dns('www.tiktok.com') == 3
    assert dns('www.netflix.com') == 3
    assert dns('web.whatsapp.com', tcp=True) == 3
    assert dns('discord.gg', tcp=True) == 3
    assert api('/api/v1/config')['policies'][0]['blocked_services'] == blocked_services
    assert api('/api/v1/policies')[0]['service_schedule']['state'] == 'active'
    assert dns('www.google.com', cname='forcesafesearch.google.com') == 0
    assert dns('www.youtube.com', tcp=True, cname='restrict.youtube.com') == 0
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
    assert api('/api/v1/explain?client=127.0.0.1&domain=safe.scoped.test')['decision']['action']=='allow'
    assert dns('typed.fixture',qtype=28)==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-active.home.arpa')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=cli-disabled.home.arpa')['rewrite']
    passthrough=api('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=1')
    assert not passthrough['rewrite'] and passthrough['decision']['action']=='block'
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=28')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=cli-globally-off.home.arpa')['rewrite']
    old_pass=api('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=1')
    assert not old_pass['rewrite'] and old_pass['decision']['action']=='block'
    assert api('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=28')['rewrite']
    assert api('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=1')['rewrite']
    assert api('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=28')['rewrite']
    assert not api('/api/v1/explain?client=127.0.0.1&domain=wild.home.arpa')['rewrite']
    for transport in [False,True]:
        assert dns('pool.home.arpa',tcp=transport,rrset_addresses=['192.0.2.20','192.0.2.30'],expected_ttl=17)==0
        assert dns('pool.home.arpa',tcp=transport,qtype=28,rrset_addresses=['2001:db8::20'],expected_ttl=17)==0
    for transport in [False,True]:
        for kind,data in [(16,('v=spf1 -all;fixture',)),(12,('nas.home.arpa',)),(15,(10,'mail.home.arpa')),(33,(1,2,8443,'service.home.arpa'))]:
            for typed_domain in ['typed.home.arpa','child.typed.home.arpa','a.b.typed.home.arpa']:
                assert dns(typed_domain,tcp=transport,qtype=kind,expected_data=data,expected_ttl=17)==0
        for binding_domain in ['binding.home.arpa','child.binding.home.arpa','a.b.binding.home.arpa']:
            for binding_kind,binding_data in [(65,(1,'.',8443)),(64,(0,'endpoint.home.arpa'))]:
                assert dns(binding_domain,tcp=transport,qtype=binding_kind,expected_data=binding_data,expected_ttl=17)==0
    for domain in ['pattern.home.arpa','nas.pattern.home.arpa']:
        for transport in [False,True]:
            for kind,address in [(1,'192.0.2.50'),(28,'2001:db8::50')]:
                assert dns(domain,tcp=transport,qtype=kind,wildcard_address=address,expected_ttl=17)==0
    for transport in [False, True]:
        for kind, address in [(1,'192.0.2.40'),(28,'2001:db8::40')]:
            assert dns('nas.deep.wild.home.arpa',tcp=transport,qtype=kind,wildcard_address=address)==0
    assert dns('tag.fixture')==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')['rule']['ctag']['include']==['user_child']
    assert api('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')['filter_tags']==['user_child']
    assert dns('client.fixture')==3
    assert api('/api/v1/explain?client=127.0.0.1&domain=client.fixture')['rule']['client']['include']==['127.0.0.1/32','Work laptop']
    assert api('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=28')['rule']['dnstype']['include']==[28]
    assert api('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=1')['decision']['action']=='allow'
    assert api('/api/v1/explain?client=127.0.0.1&domain=tracking.scoped.test')['rule']['denyallow']==['safe.scoped.test','work.scoped.test']
    restored_upstream = api('/api/v1/upstreams')[0]
    assert restored_upstream['transport'] == 'https' and restored_upstream['path'] == '/dns-query'
    assert dns('installed.test') == 3 and dns('upgrade.test') == 3
    assert dns('https-after-restore.test', answer=True) == 0
    assert api('/api/v1/shadow/promote', 'POST', {}, etag=configuration_tag())['generation'] == 7
    assert dns('scheduled.test') == 3
    assert api('/api/v1/filter-sources')['sources'][0]['download']['sha256'] == candidate_fingerprint
finally:
    stop(process)
print('PASS: service binding and typed suffix pattern record import/recovery, bundled rewrite feed import/recovery, exact address set/exception import/recovery, literal pattern address import/recovery and filtering-disabled rewrite state, wildcard address import/recovery, global rewrite switch and historical DNS-container recovery, exact family passthrough and rewrite activation import/recovery, V6 tag scope and V5 client scope and typed assertions recovery, V4 typed assertions and active/shadow restart/upgrade/backup recovery, V3 per-rule exclusions and badfilter CLI and active/shadow restart/upgrade/backup recovery, installed non-root per-client migration CLI with DS parent routing, identical-profile sharing and preserved config, clean non-root installation, UDP/TCP clients, authenticated warm DoT/HTTP2 DoH, opt-in stale outage fallback with TTL at most 30 under the weekly minute cap over UDP/TCP with metric reconciliation and uncached SERVFAIL, reviewed HTTPS lists with offline-publisher recovery, conditional 200/304/restart retrieval, scheduled shadow backup/upgrade/recovery with offline publisher and explicit promotion, binding annotations, temporary allows and permanent assertions, unit validation, upgrade preservation, schema-4 migration with retained null states, schema-6 WAL snapshot, catalog-v2 weekly service-domain and SafeSearch active/shadow recovery over UDP/TCP and DS parent mode plus expired-exception recovery; native sandbox activation not exercised')
