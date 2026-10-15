#!/usr/bin/env python3
"""Run the production image binary as UID 10001, capability-free, without network."""
import zipfile
import base64,hashlib,hmac,http.client,json,os,signal,socket,ssl,struct,subprocess,tempfile,time,urllib.parse
from pathlib import Path
assert os.getuid()==10001
assert int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')),16)==0
binary='/usr/local/bin/rustwalld-dns';token='container-public-master-fixture-16'
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory);cert=root/'cert.pem';key=root/'key.pem'
    cert.write_bytes(Path('/fixture/cert.pem').read_bytes());key.write_bytes(Path('/fixture/key.pem').read_bytes());key.chmod(0o600)
    master=root/'master.token';master.write_text(token+'\n');master.chmod(0o600)
    auth=root/'auth.json'
    enrolled=json.loads(subprocess.check_output([binary,'auth','init','--output',str(auth),'--username','admin','--password-stdin'],input=b'fixture-password-at-least16\n'))
    # Fixture enrollment is deliberately never logged.
    uri=enrolled['totp_provisioning_uri']
    secret=urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)['secret'][0]
    config=root/'config.toml'
    config.write_text(f'dns_listen="127.0.0.1:5353"\napi_listen="127.0.0.1:8443"\ndatabase="{root}/state.sqlite"\nweb_root="/usr/share/rustwalld-dns/web"\nauth_file="{auth}"\n[api_tls]\ncert_file="{cert}"\nkey_file="{key}"\nhostnames=["lists.test"]\n[policy]\ndefault_policy="default"\nallowed_clients=["127.0.0.1/32"]\n[[policy.bindings]]\nname="Tagged"\nnetwork="127.0.0.1/32"\npolicy="default"\nfilter_tags=["user_child"]\n[[policy.upstreams]]\nname="fixture"\naddresses=["127.0.0.1:5555"]\ntimeout_ms=100\n[[policy.policies]]\nname="default"\nupstream="fixture"\nds_routing="parent"\nlists=[{{name="fixture",action="block",syntax="adguard_v4",rules="ads.fixture\\ncli-pass.test\\ncli-old-pass.test\\n||cancelled.test^\\n||cancelled.test^$badfilter\\n||scoped.test^$denyallow=safe.scoped.test|work.scoped.test\\n||typed.fixture^$dnstype=AAAA,denyallow=safe.typed.fixture"}},{{name="clients",action="block",syntax="adguard_v5",rules="||client.fixture^$client=127.0.0.1,dnstype=A|AAAA"}},{{name="tags",action="block",syntax="adguard_v6",rules="||tag.fixture^$ctag=user_child,dnstype=A|AAAA"}}]\nrewrites=[{{domain="nas.home.arpa",addresses=["192.0.2.10"],ttl=60}}]\nsafe_search={{catalog_version=1,google=true,youtube="strict"}}\nblocked_services={{catalog_version=2,ids=["tiktok","netflix"],schedule={{time_zone="UTC",mode="block",windows=[{{days=["mon","tue","wed","thu","fri","sat","sun"],start="00:00",end="24:00"}}]}}}}\n')
    client_source=root/'AdGuardHome.yaml'
    client_source.write_text("dns: {upstream_dns: ['127.0.0.1:15401', '[/child.test/]127.0.0.1:15402']}\nclients: {persistent: [{name: Work, ids: [127.0.0.2], tags: [user_child], use_global_settings: true, upstreams: ['127.0.0.1:15402']}, {name: Shared, ids: [127.0.0.3], upstreams: ['127.0.0.1:15402']}]}\nfiltering: {rewrites: [{domain: cli-active.home.arpa, answer: 192.0.2.10, enabled: true}, {domain: cli-disabled.home.arpa, answer: 192.0.2.11, enabled: false}, {domain: cli-pass.test, answer: A}]}\nuser_rules: [ads.fixture, cli-pass.test, '||cancelled.test^', '||cancelled.test^$badfilter', '||scoped.test^$denyallow=safe.scoped.test|work.scoped.test', '||typed.fixture^$dnstype=AAAA,denyallow=safe.typed.fixture', '||client.fixture^$client=Work|127.0.0.1,dnstype=AAAA']\n")
    client_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(client_source),'--base-config',str(config)]))
    assert client_report['ready']
    assert all(policy['ds_routing']=='parent' for policy in client_report['config']['policies'])
    assert client_report['config']['policies'][0]['lists'][0]['syntax']=='adguard_v6'
    assert client_report['config']['bindings'][0]['filter_tags']==['user_child']
    assert all([record['domain'] for record in policy['dns_records']]==['cli-active.home.arpa','cli-pass.test'] for policy in client_report['config']['policies'])
    assert client_report['validation']['list_stats'][0]['lists'][0]['disabled']==1
    client_draft=client_report['config']
    assert client_draft['policies'][1]['upstream']==client_draft['policies'][2]['upstream']!=client_draft['policies'][0]['upstream']
    assert len(client_draft['upstreams'])==3 and client_draft['bindings'][0]['network']=='127.0.0.2/32'
    config.write_text(config.read_text() + '\n[[policy.policies.dns_records]]\ndomain="cli-active.home.arpa"\nttl=60\ndata={type="A",address="192.0.2.10"}\n')
    config.write_text(config.read_text() + '\n[[policy.policies.dns_records]]\ndomain="cli-pass.test"\nttl=60\ndata={type="PASSTHROUGH",family="A"}\n')
    config.write_text(config.read_text() + '\n[[policy.policies.dns_records]]\ndomain="cli-old-pass.test"\nttl=60\ndata={type="PASSTHROUGH",family="A"}\n')
    config.write_text(config.read_text() + '\n[[policy.policies.dns_records]]\ndomain="*.wild.home.arpa"\nttl=60\ndata={type="A",address="192.0.2.40"}\n[[policy.policies.dns_records]]\ndomain="*.wild.home.arpa"\nttl=60\ndata={type="AAAA",address="2001:db8::40"}\n')
    rewrite_source = root/'rewrite-layout.yaml'
    rewrite_source.write_text("schema_version: 34\nfiltering: {rewrites_enabled: false, rewrites: [{domain: cli-globally-off.home.arpa, answer: 192.0.2.12, enabled: true}]}\nuser_rules: [ads.fixture]\n")
    off_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert off_report['ready']
    assert all(not policy.get('dns_records',[]) for policy in off_report['config']['policies'])
    assert any(issue['field']=='filtering.rewrites_enabled' and issue['severity']=='info' for issue in off_report['issues'])
    rewrite_source.write_text("schema_version: 25\ndns: {rewrites: [{domain: cli-old-pass.test, answer: A}]}\nuser_rules: [ads.fixture, cli-old-pass.test]\n")
    old_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert old_report['ready']
    assert old_report['config']['policies'][0]['dns_records'][0]['data']=={'type':'PASSTHROUGH','family':'A'}
    old_draft=old_report['config']
    for schema,container,entry in [(34,'dns','{domain: cli-incompatible.test, answer: 192.0.2.13}'),(30,'filtering','{domain: cli-incompatible.test, answer: 192.0.2.13, enabled: false}')]:
        rewrite_source.write_text(f"schema_version: {schema}\n{container}: {{rewrites: [{entry}]}}\nuser_rules: [ads.fixture]\n")
        conflict=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True)
        assert conflict.returncode==1
        conflict_report=json.loads(conflict.stdout)
        assert not conflict_report['ready'] and all(not policy.get('dns_records',[]) for policy in conflict_report['config']['policies'])
        assert any(issue['severity']=='blocker' for issue in conflict_report['issues'])
    for schema,container in [(25,'dns'),(34,'filtering')]:
        rewrite_source.write_text(f"schema_version: {schema}\n{container}: {{rewrites: [{{domain: '*.wild.home.arpa', answer: 192.0.2.40}}, {{domain: '*.wild.home.arpa', answer: '2001:db8::40'}}]}}\n")
        wildcard_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
        assert wildcard_report['ready']
        assert [record['domain'] for record in wildcard_report['config']['policies'][0]['dns_records']]==['*.wild.home.arpa','*.wild.home.arpa']
    rewrite_source.write_text("filtering: {rewrites: [{domain: '*.wild.home.arpa', answer: A}]}\n")
    wildcard_blocked=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True)
    assert wildcard_blocked.returncode==1 and not json.loads(wildcard_blocked.stdout)['ready']
    rewrite_source.write_text("schema_version: 34\nfiltering: {protection_enabled: false, blocked_response_ttl: 17, rewrites_enabled: false}\nuser_rules: ['||pattern.home.arpa^$dnsrewrite=192.0.2.50', '||pattern.home.arpa^$dnsrewrite=NOERROR;AAAA;2001:db8::50']\nclients: {persistent: [{name: Off, ids: [127.0.0.2], use_global_settings: false, filtering_enabled: false}]}\n")
    pattern_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert pattern_report['ready'] and len(pattern_report['config']['policies'][0]['dns_records'])==4
    assert all(record['ttl']==17 for record in pattern_report['config']['policies'][0]['dns_records'])
    assert not pattern_report['config']['policies'][1].get('dns_records',[])
    with zipfile.ZipFile(rewrite_source,"w",compression=zipfile.ZIP_STORED) as backup:
        backup.writestr("AdGuardHome.yaml", "filtering: {blocked_response_ttl: 17}\nfilters: [{id: 7, enabled: true}]\nuser_rules: ['|pool.home.arpa^$dnsrewrite=192.0.2.10', '|sets-cancelled.test^$dnsrewrite=192.0.2.10']\n")
        backup.writestr("data/filters/7.txt", "|pool.home.arpa^$dnsrewrite=192.0.2.20\n|pool.home.arpa^$dnsrewrite=192.0.2.30\n|pool.home.arpa^$dnsrewrite=2001:db8::20\n@@|pool.home.arpa|$dnsrewrite=192.0.2.10\n@@|sets-cancelled.test|$dnsrewrite\n")
    sets_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert sets_report['ready'] and len(sets_report['config']['policies'][0]['dns_records'])==3
    assert [record['data']['address'] for record in sets_report['config']['policies'][0]['dns_records']]==['192.0.2.20','192.0.2.30','2001:db8::20']
    pattern_report['config']['policies'][0]['dns_records'].extend(sets_report['config']['policies'][0]['dns_records'])
    with zipfile.ZipFile(rewrite_source,"w",compression=zipfile.ZIP_STORED) as backup:
        backup.writestr("AdGuardHome.yaml", "filtering: {blocked_response_ttl: 17}\nfilters: [{id: 8, enabled: true}]\nuser_rules: ['||typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed']\n")
        backup.writestr("data/filters/8.txt", "||typed.home.arpa^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture\n||typed.home.arpa^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.\n||typed.home.arpa^$dnsrewrite=NOERROR;MX;10 MAIL.home.arpa\n||typed.home.arpa^$dnsrewrite=NOERROR;SRV;1 2 8443 SERVICE.home.arpa\n@@||typed.home.arpa^$dnsrewrite=NOERROR;TXT;removed\n")
    typed_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert typed_report['ready'] and len(typed_report['config']['policies'][0]['dns_records'])==8
    assert {record['data']['type'] for record in typed_report['config']['policies'][0]['dns_records']}=={'TXT','PTR','MX','SRV'}
    assert all(record['ttl']==17 for record in typed_report['config']['policies'][0]['dns_records'])
    pattern_report['config']['policies'][0]['dns_records'].extend(typed_report['config']['policies'][0]['dns_records'])
    with zipfile.ZipFile(rewrite_source,"w",compression=zipfile.ZIP_STORED) as backup:
        backup.writestr("AdGuardHome.yaml", "filtering: {blocked_response_ttl: 17}\nfilters: [{id: 9, enabled: true}]\nuser_rules: ['||cancelled-binding.test^$dnsrewrite=NOERROR;HTTPS;1 .']\n")
        backup.writestr("data/filters/9.txt", "||binding.home.arpa^$dnsrewrite=NOERROR;HTTPS;1 . port=8443\n||binding.home.arpa^$dnsrewrite=NOERROR;SVCB;0 ENDPOINT.home.arpa\n@@||cancelled-binding.test^$dnsrewrite\n")
    binding_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert binding_report['ready'] and len(binding_report['config']['policies'][0]['dns_records'])==4
    assert {record['data']['type'] for record in binding_report['config']['policies'][0]['dns_records']}=={'HTTPS','SVCB'}
    assert all(record['ttl']==17 for record in binding_report['config']['policies'][0]['dns_records'])
    pattern_report['config']['policies'][0]['dns_records'].extend(binding_report['config']['policies'][0]['dns_records'])
    rewrite_source.write_text("user_rules: ['||pool.home.arpa^$dnsrewrite=192.0.2.10', '@@|pool.home.arpa^$dnsrewrite']\n")
    sets_blocked=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True)
    assert sets_blocked.returncode==1 and not json.loads(sets_blocked.stdout)['ready']
    rewrite_source.write_text("filtering: {filtering_enabled: false, rewrites: [{domain: legacy-off.home.arpa, answer: 192.0.2.20}]}\nuser_rules: ['||pattern.home.arpa^$dnsrewrite=192.0.2.50']\n")
    filtering_off_report=json.loads(subprocess.check_output([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)]))
    assert filtering_off_report['ready'] and not filtering_off_report['config']['policies'][0].get('dns_records',[])
    rewrite_source.write_text("user_rules: ['||pattern.home.arpa^$dnsrewrite=192.0.2.50', '||deep.pattern.home.arpa^$dnsrewrite=192.0.2.51']\n")
    pattern_blocked=subprocess.run([binary,'migrate','--source','adguard','--input',str(rewrite_source),'--base-config',str(config)],capture_output=True,text=True)
    assert pattern_blocked.returncode==1 and not json.loads(pattern_blocked.stdout)['ready']
    for record in pattern_report['config']['policies'][0]['dns_records']:
        payload=", ".join(f"{field}=" + ("{port="+str(value["port"])+"}" if field=="params" else json.dumps(value)) for field,value in record['data'].items())
        config.write_text(config.read_text() + f'\n[[policy.policies.dns_records]]\ndomain="{record["domain"]}"\nttl=17\ndata={{{payload}}}\n')
    rewrite_source.unlink()
    client_source.unlink()
    env={**os.environ,'RUSTWALLD_API_TOKEN_FILE':str(master)}
    env.pop('RUSTWALLD_API_TOKEN',None)
    context=ssl.create_default_context(cafile=str(cert))
    def request(path,method='GET',body=None,bearer=True,cookie=None,csrf=None):
        connection=http.client.HTTPConnection('127.0.0.1',8443,timeout=3);connection.connect()
        connection.sock=context.wrap_socket(connection.sock,server_hostname='lists.test')
        headers={'Host':'lists.test:8443','Content-Type':'application/json'}
        if bearer:headers['Authorization']='Bearer '+token
        if cookie:headers['Cookie']=cookie
        if csrf:headers['X-CSRF-Token']=csrf;headers['Origin']='https://lists.test:8443'
        connection.request(method,path,body=json.dumps(body) if body is not None else None,headers=headers)
        response=connection.getresponse();status=response.status;headers=dict(response.getheaders());data=response.read();connection.close()
        return status,headers,json.loads(data) if data and headers.get('content-type','').startswith('application/json') else data
    def start():
        process=subprocess.Popen([binary,'--config',str(config)],env=env,stdout=subprocess.DEVNULL)
        for _ in range(250):
            assert process.poll() is None
            try:
                if request('/healthz',bearer=False)[0]==200:return process
            except (OSError,ssl.SSLError):pass
            time.sleep(.02)
        raise AssertionError('container HTTPS not ready')
    def stop(process):process.send_signal(signal.SIGTERM);assert process.wait(timeout=10)==0
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


    def dns(domain, cname=None, qtype=1, wildcard_address=None, expected_ttl=60, rrset_addresses=None, expected_data=None):
        query=struct.pack('!6H',123,0x100,1,0,0,0)+b''.join(bytes([len(label)])+label.encode() for label in domain.split('.'))+b'\0'+struct.pack('!HH',5 if cname else qtype,1)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(2);client.sendto(query,('127.0.0.1',5353));response=client.recv(4096)
        assert struct.unpack_from('!H',response)[0]==123
        if expected_data is not None:
            assert response[3]&15==0 and int.from_bytes(response[6:8],'big')==1
            owner,offset=dns_name(response,len(query))
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
            assert response[3]&15==0 and struct.unpack_from('!H',response,6)[0]==len(rrset_addresses)
            offset=len(query);found=[]
            for _ in rrset_addresses:
                owner,offset=dns_name(response,offset)
                assert owner==domain
                kind,rrclass,lifetime,length=struct.unpack_from('!HHIH',response,offset)
                assert kind==qtype and rrclass==1 and 0<lifetime<=expected_ttl
                found.append(socket.inet_ntop(socket.AF_INET if qtype==1 else socket.AF_INET6,response[offset+10:offset+10+length]))
                offset+=10+length
            assert sorted(found)==sorted(rrset_addresses)
        if wildcard_address:
            assert response[3]&15==0 and struct.unpack_from('!H',response,6)[0]==1
            offset=len(query)
            assert response[offset:offset+2]==b'\xc0\x0c' # concrete original question owner
            kind,rrclass,lifetime,length=struct.unpack_from('!HHIH',response,offset+2)
            assert kind==qtype and rrclass==1 and 0<lifetime<=expected_ttl
            assert response[offset+12:offset+12+length]==socket.inet_pton(socket.AF_INET if qtype==1 else socket.AF_INET6,wildcard_address)
        if cname:
            assert response[3]&15==0 and struct.unpack_from('!H',response,6)[0]==1
            offset=len(query)
            assert response[offset:offset+2]==b'\xc0\x0c' and response[offset+2:offset+4]==b'\0\5'
            # No shared labels with the original question in this fixture.
            encoded=b''.join(bytes([len(label)])+label.encode() for label in cname.split('.'))+b'\0'
            assert response[offset+12:]==encoded
        return struct.unpack_from('!H',response,2)[0]&15
    subprocess.run([binary,'--config',str(config),'--check-config'],env=env,check=True,stdout=subprocess.DEVNULL)
    process=start()
    try:
        assert request('/setup')[0]==200
        assert request('/api/v1/config',bearer=False)[0]==401
        assert dns('ads.fixture')==3 and dns('nas.home.arpa')==0
        assert dns('www.tiktok.com')==3
        assert dns('www.netflix.com')==3
        assert request('/api/v1/config')[2]['policies'][0]['blocked_services']['catalog_version']==2
        assert request('/api/v1/config')[2]['policies'][0]['blocked_services']['ids']==['tiktok','netflix']
        assert request('/api/v1/policies')[2][0]['service_schedule']['state']=='active'
        assert dns('www.google.no',cname='forcesafesearch.google.com')==0
        assert request('/api/v1/config')[2]['policies'][0]['safe_search']['youtube']=='strict'
        assert request('/api/v1/config')[2]['policies'][0]['ds_routing']=='parent'
        assert request('/api/v1/config')[2]['policies'][0]['lists'][0]['syntax']=='adguard_v4'
        assert request('/api/v1/filter-lists')[2][0]['cancellations'][0]['disabled']==1
        assert request('/api/v1/explain?client=127.0.0.1&domain=cancelled.test')[2]['decision']['action']=='allow'
        assert request('/api/v1/explain?client=127.0.0.1&domain=safe.scoped.test')[2]['decision']['action']=='allow'
        assert dns('typed.fixture',qtype=28)==3
        assert request('/api/v1/explain?client=127.0.0.1&domain=cli-active.home.arpa')[2]['rewrite']
        assert not request('/api/v1/explain?client=127.0.0.1&domain=cli-disabled.home.arpa')[2]['rewrite']
        passthrough=request('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=1')[2]
        assert not passthrough['rewrite'] and passthrough['decision']['action']=='block'
        assert request('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=28')[2]['rewrite']
        assert not request('/api/v1/explain?client=127.0.0.1&domain=cli-globally-off.home.arpa')[2]['rewrite']
        old_pass=request('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=1')[2]
        assert not old_pass['rewrite'] and old_pass['decision']['action']=='block'
        assert request('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=28')[2]['rewrite']
        assert request('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=1')[2]['rewrite']
        assert request('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=28')[2]['rewrite']
        assert not request('/api/v1/explain?client=127.0.0.1&domain=wild.home.arpa')[2]['rewrite']
        assert dns('pool.home.arpa',rrset_addresses=['192.0.2.20','192.0.2.30'],expected_ttl=17)==0
        assert dns('pool.home.arpa',qtype=28,rrset_addresses=['2001:db8::20'],expected_ttl=17)==0
        for kind,data in [(16,('v=spf1 -all;fixture',)),(12,('nas.home.arpa',)),(15,(10,'mail.home.arpa')),(33,(1,2,8443,'service.home.arpa'))]:
            for typed_domain in ['typed.home.arpa','child.typed.home.arpa','a.b.typed.home.arpa']:
                assert dns(typed_domain,qtype=kind,expected_data=data,expected_ttl=17)==0
        for binding_domain in ['binding.home.arpa','child.binding.home.arpa','a.b.binding.home.arpa']:
            for binding_kind,binding_data in [(65,(1,'.',8443)),(64,(0,'endpoint.home.arpa'))]:
                assert dns(binding_domain,qtype=binding_kind,expected_data=binding_data,expected_ttl=17)==0
        for domain in ['pattern.home.arpa','nas.pattern.home.arpa']:
            for kind,address in [(1,'192.0.2.50'),(28,'2001:db8::50')]:
                assert dns(domain,qtype=kind,wildcard_address=address,expected_ttl=17)==0
        for kind,address in [(1,'192.0.2.40'),(28,'2001:db8::40')]:
            assert dns('nas.deep.wild.home.arpa',qtype=kind,wildcard_address=address)==0
        assert dns('tag.fixture')==3
        assert request('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')[2]['rule']['ctag']['include']==['user_child']
        assert dns('client.fixture')==3
        assert request('/api/v1/explain?client=127.0.0.1&domain=client.fixture')[2]['rule']['client']['include']==['127.0.0.1/32']
        assert request('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=28')[2]['rule']['dnstype']['include']==[28]
        assert request('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=1')[2]['decision']['action']=='allow'
        assert request('/api/v1/explain?client=127.0.0.1&domain=tracking.scoped.test')[2]['rule']['denyallow']==['safe.scoped.test','work.scoped.test']
        counter=int(time.time())//30
        digest=hmac.new(base64.b32decode(secret+'='*((-len(secret))%8)),struct.pack('!Q',counter),hashlib.sha1).digest();offset=digest[-1]&15
        code=f'{(struct.unpack_from("!I",digest,offset)[0]&0x7fffffff)%1000000:06d}'
        status,headers,session=request('/api/v1/auth/login','POST',{'username':'admin','password':'fixture-password-at-least16','totp':code},bearer=False)
        assert status==200
        cookie_header=headers.get('set-cookie','');assert 'HttpOnly' in cookie_header and 'Secure' in cookie_header and 'SameSite=Strict' in cookie_header
        cookie=cookie_header.split(';',1)[0]
        assert request('/api/v1/auth/session',bearer=False,cookie=cookie)[0]==200
        status,headers,privacy=request('/api/v1/privacy');assert status==200
        # Revision-checked preferences remain separate from policy generations.
        connection=http.client.HTTPConnection('127.0.0.1',8443,timeout=3);connection.connect();connection.sock=context.wrap_socket(connection.sock,server_hostname='lists.test')
        connection.request('PUT','/api/v1/privacy',json.dumps({'mode':'disabled','retention_rows':100,'clear_history':True}),{'Host':'lists.test:8443','Content-Type':'application/json','Authorization':'Bearer '+token,'If-Match':headers['etag']})
        response=connection.getresponse();assert response.status==200;response.read();connection.close()
        for _ in range(20):assert dns('ads.fixture')==3
        time.sleep(.05);assert request('/api/v1/queries')[2]==[]
        backup=root/'backup.sqlite';subprocess.run([binary,'backup','--database',str(root/'state.sqlite'),'--output',str(backup)],check=True,stdout=subprocess.DEVNULL)
        subprocess.run([binary,'verify-backup','--database',str(backup)],check=True,stdout=subprocess.DEVNULL)
        assert auth.stat().st_mode&0o777==0o600 and backup.stat().st_mode&0o777==0o600
        stop(process)
        # Stored policy, not the bootstrap file, owns subsequent starts.
        config.write_text(config.read_text().replace('google=true,youtube="strict"','google=false,youtube="off"').replace('ids=["tiktok","netflix"]','ids=["reddit"]').replace('ds_routing="parent"','ds_routing="question"'))
        process=start()
        assert request('/api/v1/privacy')[2]['mode']=='disabled'
        assert request('/api/v1/auth/session',bearer=False,cookie=cookie)[0]==401
        assert dns('ads.fixture')==3 and request('/api/v1/queries')[2]==[]
        assert request('/api/v1/config')[2]['policies'][0]['safe_search']['youtube']=='strict'
        assert request('/api/v1/config')[2]['policies'][0]['ds_routing']=='parent'
        assert request('/api/v1/config')[2]['policies'][0]['lists'][0]['syntax']=='adguard_v4'
        assert request('/api/v1/filter-lists')[2][0]['cancellations'][0]['disabled']==1
        assert request('/api/v1/explain?client=127.0.0.1&domain=cancelled.test')[2]['decision']['action']=='allow'
        assert request('/api/v1/explain?client=127.0.0.1&domain=safe.scoped.test')[2]['decision']['action']=='allow'
        assert dns('typed.fixture',qtype=28)==3
        assert request('/api/v1/explain?client=127.0.0.1&domain=cli-active.home.arpa')[2]['rewrite']
        assert not request('/api/v1/explain?client=127.0.0.1&domain=cli-disabled.home.arpa')[2]['rewrite']
        passthrough=request('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=1')[2]
        assert not passthrough['rewrite'] and passthrough['decision']['action']=='block'
        assert request('/api/v1/explain?client=127.0.0.1&domain=cli-pass.test&qtype=28')[2]['rewrite']
        assert not request('/api/v1/explain?client=127.0.0.1&domain=cli-globally-off.home.arpa')[2]['rewrite']
        old_pass=request('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=1')[2]
        assert not old_pass['rewrite'] and old_pass['decision']['action']=='block'
        assert request('/api/v1/explain?client=127.0.0.1&domain=cli-old-pass.test&qtype=28')[2]['rewrite']
        assert request('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=1')[2]['rewrite']
        assert request('/api/v1/explain?client=127.0.0.1&domain=nas.deep.wild.home.arpa&qtype=28')[2]['rewrite']
        assert not request('/api/v1/explain?client=127.0.0.1&domain=wild.home.arpa')[2]['rewrite']
        assert dns('pool.home.arpa',rrset_addresses=['192.0.2.20','192.0.2.30'],expected_ttl=17)==0
        assert dns('pool.home.arpa',qtype=28,rrset_addresses=['2001:db8::20'],expected_ttl=17)==0
        for kind,data in [(16,('v=spf1 -all;fixture',)),(12,('nas.home.arpa',)),(15,(10,'mail.home.arpa')),(33,(1,2,8443,'service.home.arpa'))]:
            for typed_domain in ['typed.home.arpa','child.typed.home.arpa','a.b.typed.home.arpa']:
                assert dns(typed_domain,qtype=kind,expected_data=data,expected_ttl=17)==0
        for binding_domain in ['binding.home.arpa','child.binding.home.arpa','a.b.binding.home.arpa']:
            for binding_kind,binding_data in [(65,(1,'.',8443)),(64,(0,'endpoint.home.arpa'))]:
                assert dns(binding_domain,qtype=binding_kind,expected_data=binding_data,expected_ttl=17)==0
        for domain in ['pattern.home.arpa','nas.pattern.home.arpa']:
            for kind,address in [(1,'192.0.2.50'),(28,'2001:db8::50')]:
                assert dns(domain,qtype=kind,wildcard_address=address,expected_ttl=17)==0
        for kind,address in [(1,'192.0.2.40'),(28,'2001:db8::40')]:
            assert dns('nas.deep.wild.home.arpa',qtype=kind,wildcard_address=address)==0
        assert dns('tag.fixture')==3
        assert request('/api/v1/explain?client=127.0.0.1&domain=tag.fixture')[2]['rule']['ctag']['include']==['user_child']
        assert dns('client.fixture')==3
        assert request('/api/v1/explain?client=127.0.0.1&domain=client.fixture')[2]['rule']['client']['include']==['127.0.0.1/32']
        assert request('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=28')[2]['rule']['dnstype']['include']==[28]
        assert request('/api/v1/explain?client=127.0.0.1&domain=typed.fixture&qtype=1')[2]['decision']['action']=='allow'
        assert request('/api/v1/explain?client=127.0.0.1&domain=tracking.scoped.test')[2]['rule']['denyallow']==['safe.scoped.test','work.scoped.test']
        assert dns('www.tiktok.com')==3
        assert dns('www.netflix.com')==3
        assert request('/api/v1/config')[2]['policies'][0]['blocked_services']['catalog_version']==2
        assert request('/api/v1/config')[2]['policies'][0]['blocked_services']['ids']==['tiktok','netflix']
        assert request('/api/v1/policies')[2][0]['service_schedule']['state']=='active'
        assert dns('www.google.no',cname='forcesafesearch.google.com')==0
    finally:stop(process)
    master.chmod(0o644)
    rejected=subprocess.run([binary,'--config',str(config)],env=env,capture_output=True,timeout=5)
    assert rejected.returncode!=0 and token.encode() not in rejected.stderr
    print(json.dumps({'uid':os.getuid(),'capabilities':0,'public_network':False,'checks':['service_binding_pattern_recovery','typed_suffix_pattern_record_recovery','bundled_rewrite_feed_recovery','exact_address_set_exception_recovery','literal_pattern_address_recovery','filtering_disabled_rewrite_state','wildcard_address_recovery','global_rewrite_switch_recovery','historical_DNS_rewrite_layout_recovery','family_passthrough_import_recovery','rewrite_activation_import_recovery','tag_scope_CLI_restart_backup','client_scope_CLI_restart_backup','dnstype_CLI_restart_backup','badfilter_CLI_restart_backup','client_migration_CLI','DS_parent_restart','private_master_file','HTTPS_trust','password_2FA','secure_cookie','DNS_filter','local_DNS','privacy_restart','session_restart','backup_verify','SafeSearch_restart','service_blocks_restart','weekly_schedule_restart','catalog_v2_restart','private_file_rejection'],'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest()}))
