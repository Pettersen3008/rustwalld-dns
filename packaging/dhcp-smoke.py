#!/usr/bin/env python3
"""DHCP DORA/renew/release in a network-none container with a private veth pair."""
import ipaddress,json,os,socket,struct,subprocess,tempfile,time
from pathlib import Path
subprocess.run(['dnsmasq','--test','--conf-file=/example.conf'],check=True)
for command in [('ip','link','add','fixture-server','type','veth','peer','name','fixture-client'),('ip','addr','add','172.31.239.1/24','dev','fixture-server'),('ip','link','set','fixture-server','up'),('ip','link','set','fixture-client','up')]:subprocess.run(command,check=True)
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    config=root/'dnsmasq.conf'
    config.write_text('port=0\ninterface=fixture-server\nbind-interfaces\nno-hosts\nno-resolv\ndhcp-range=172.31.239.100,172.31.239.110,255.255.255.0,5m\ndhcp-option=option:router,172.31.239.1\ndhcp-option=option:dns-server,172.31.239.1\ndhcp-leasefile='+str(root/'leases')+'\n')
    server=subprocess.Popen(['dnsmasq','--keep-in-foreground','--user=root','--log-facility=-','--log-dhcp','--conf-file='+str(config)],stdout=subprocess.DEVNULL)
    try:
        time.sleep(.2)
        assert server.poll() is None
        client=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
        client.bind(('fixture-client',0x0003));client.settimeout(3)
        mac=b'\x02\x00\x00\x00\x00\x01';xid=0x1234ABCD
        def packet(kind,address=b'\0'*4,requested=None,server_id=None):
            header=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0x8000,address,b'\0'*4,b'\0'*4,b'\0'*4,mac+b'\0'*10,b'\0'*64,b'\0'*128)
            options=b'\x63\x82\x53\x63'+bytes([53,1,kind])+bytes([55,3,1,3,6])+bytes([12,11])+b'fixture-nas'
            if requested:options+=bytes([50,4])+requested
            if server_id:options+=bytes([54,4])+server_id
            return (header+options+b'\xff').ljust(300,b'\0')
        def send(data,destination='255.255.255.255'):
            ip=struct.pack('!BBHHHBBH4s4s',0x45,0,28+len(data),1,0,64,17,0,data[12:16],socket.inet_aton(destination))
            words=struct.unpack('!10H',ip);checksum=sum(words)
            while checksum>>16:checksum=(checksum&65535)+(checksum>>16)
            ip=ip[:10]+struct.pack('!H',(~checksum)&65535)+ip[12:]
            udp=struct.pack('!HHHH',68,67,8+len(data),0)
            client.send(b'\xff'*6+mac+b'\x08\x00'+ip+udp+data)
        def exchange(data,expected):
            send(data)
            while True:
                frame=client.recv(8192)
                if len(frame)>=42 and frame[12:14]==b'\x08\x06' and frame[20:22]==b'\x00\x01':
                    # A renewing client responds to ARP without configuring host IP state.
                    sender_mac=frame[22:28];sender_ip=frame[28:32];target_ip=frame[38:42]
                    arp=struct.pack('!HHBBH',1,0x0800,6,4,2)+mac+target_ip+sender_mac+sender_ip
                    client.send(sender_mac+mac+b'\x08\x06'+arp)
                    continue
                if len(frame)<42 or frame[12:14]!=b'\x08\x00' or frame[23]!=17:continue
                offset=14+(frame[14]&15)*4
                if frame[offset:offset+4]!=struct.pack('!HH',67,68):continue
                response=frame[offset+8:]
                if len(response)<240 or struct.unpack_from('!I',response,4)[0]!=xid:continue
                assert response[0]==2 and response[236:240]==b'\x63\x82\x53\x63'
                options={};offset=240
                while offset<len(response):
                    code=response[offset];offset+=1
                    if code==255:break
                    if code==0:continue
                    length=response[offset];offset+=1;options[code]=response[offset:offset+length];offset+=length
                if options.get(53)==bytes([expected]):return response[16:20],options
        address,options=exchange(packet(1),2)
        assert options[6]==socket.inet_aton('172.31.239.1') and options[3]==socket.inet_aton('172.31.239.1')
        leased,_=exchange(packet(3,requested=address,server_id=options[54]),5)
        assert leased==address
        text=(root/'leases').read_text();assert 'fixture-nas' in text and str(ipaddress.ip_address(address)) in text
        renewed,_=exchange(packet(3,address=address),5);assert renewed==address
        send(packet(7,address=address,server_id=options[54]),'172.31.239.1')
        deadline=time.monotonic()+3
        while 'fixture-nas' in (root/'leases').read_text() and time.monotonic()<deadline:time.sleep(.02)
        assert 'fixture-nas' not in (root/'leases').read_text()
        print(json.dumps({'dnsmasq':subprocess.check_output(['dnsmasq','--version'],text=True).splitlines()[0],'checks':['config','discover','offer','request','ack','dns_option','router_option','lease_file','renew','release'],'host_network':False,'public_dns':False}))
    finally:
        server.terminate();server.wait(timeout=5)
