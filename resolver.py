import sys, os
import struct
import socket
from timer import *
from _thread import *
import random

qtypes = {
        'A': 1, 'NS': 2, 'MD': 3, 'MF': 4, 'CNAME': 5,
        'SOA': 6, 'MB': 7, 'MG': 8, 'MR': 9, 'NULL': 10,
        'WKS': 11, 'PTR': 12, 'HINFO': 13, 'MINFO': 14,
        'MX': 15, 'TXT': 16, 'AAAA': 28, 'ANY': 255
        }

# Check if a string is valid IP address 
def is_ip(host):
    host_name_split = host.split(".")
    if len(host_name_split) != 4:
        return False
    valid = True
    for n in host_name_split:
        valid = valid and n.isnumeric() and int(n) in range(256) 
        if not valid:
            break
    return valid
        
class DNS_Resolver():
    # Initialize parameters 
    def __init__(self):
        self.servers = ["127.0.0.53"]       # List of servers to query
        self.port = 53          # Server port number
        self.cl = "IN"          # DNS query class 
        self.qtype = "A"        # Default query type 
        self.rec = True         # Recursive flag
        self.timeout = 1        # Initial timeout value in seconds
        self.retry = 3          # Number of retries
        self.domain = ""        # Default domain name for lookup
        # create client socket
        self.csocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Internet, UDP.
        self.timer = Timer(self.timeout)
        # Response data
        self.response_data = bytes()
        self.header = bytes()
        self.question = bytes() 
        self.sections = []
        
        start_new_thread(self.receive, ())
    
    # Create a DNS query packet using given parameters
    def make_query(self, host):
        try: 
            recurse = 1 << 8 if self.rec else 0
            host = host + self.domain if self.domain != "" else host
            tid = random.randrange(0, 65535)
            flags = recurse
            
            # Framing Header
            header_values = (tid, flags, 1, 0, 0, 0)
            header_fmt = struct.Struct('>H H H H H H')
            header = header_fmt.pack(*header_values)
            host_name_split = host.split(".")
            
            # Framing Question
            qname = bytes()
            for h in host_name_split:
                qname += bytes([len(h)]) + bytes(h, 'utf-8')
            qname += bytes([0])
            info_fmt = struct.Struct('>H H')
            info_values = (qtypes[self.qtype], 1)
            info = info_fmt.pack(*info_values)
            question = qname + info
            
            packet = header + question
            return packet
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
    
    def decode_rdata(self, data):
        try: 
            x, y = 0, 0
            data1, rdata = data, ""
            while True:
                length = data1[x]
                if length & 0xc0: 
                    ptr = int.from_bytes(data1[x:x+2], 'big')
                    ptr &= 0x3fff
                    data1 = self.response_data[ptr:]
                    x, y = 0, 0
                    continue
                if length == 0:
                    break
                x += 1
                y = x + length
                rdata += data1[x:y].decode('utf-8') + "."
                x = y
            rdata = rdata[:-1]
            return rdata
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
    
    def split_packet(self, packet, index):
        data = packet[:index]
        return data, packet[index:]

    # Function to decode DNS answer packet
    def decode_response(self, data):
        try:
            packet = data
            # Get header
            self.header, packet = self.split_packet(packet, 12)
            # Get self.question
            self.question, packet = self.split_packet(packet, packet.find(b'\x00')+5)
            
            # Get answer RRs
            self.sections = []
            while len(packet) > 1:
                name, packet = self.split_packet(packet, packet.find(b'\x00'))
                info, packet = self.split_packet(packet, 8)
                rlength, packet = self.split_packet(packet, 2)
                rdata, packet = self.split_packet(packet, struct.unpack('>H', rlength)[0])

                section = name + info + rlength + rdata
                self.sections.append(section)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
                
    def format_output(self):
        global qtypes
        try:
            response_code = int.from_bytes(self.header[2:4], byteorder='big') & 15
            qname = self.decode_rdata(self.question)
            
            if (response_code == 0):
                for section in self.sections:
                    name, section = self.split_packet(section, section.find(b'\x00'))
                    info, section = self.split_packet(section, 8)
                    rlength, section = self.split_packet(section, 2)
                    rdata, section = self.split_packet(section, struct.unpack('>H', rlength)[0])
                    
                    qtype = info[1]
                    if qtype == 1:
                        ip_address = ".".join([
                            str(rdata[-4])
                          , str(rdata[-3])
                          , str(rdata[-2])
                          , str(rdata[-1])
                        ])
                        print("Name: {}\nAddress: {}".format(qname, ip_address))
                    elif qtype == 2:
                        ans = self.decode_rdata(rdata)
                        print("{} nameserver = {}".format(qname, ans))
                    elif qtype == 5:
                        ans = self.decode_rdata(rdata)
                        print("{} cname = {}".format(qname, ans))
                    elif qtype == 6:
                        origin, rdata = self.split_packet(rdata,
                                rdata.find(b'\x0c')+1)
                        origin = self.decode_rdata(origin)
                        mail_addr, rdata = self.split_packet(rdata,
                                rdata.find(b'\x0c')+1)
                        mail_addr = self.decode_rdata(mail_addr)
                        serial = int.from_bytes(rdata[0:4], 'big')
                        refresh = int.from_bytes(rdata[4:8], 'big')
                        retry = int.from_bytes(rdata[8:12], 'big')
                        expire = int.from_bytes(rdata[12:16], 'big')
                        minimum = int.from_bytes(rdata[16:20], 'big')
                        print(qname)
                        print("\t origin = {}".format(origin))
                        print("\t mail addr = {}".format(mail_addr))
                        print("\t serial = {}".format(serial))
                        print("\t refresh = {}".format(refresh))
                        print("\t retry = {}".format(retry))
                        print("\t expire = {}".format(expire))
                        print("\t minimum = {}".format(minimum))
                    elif qtype == 15:
                        pref, rdata = self.split_packet(rdata, 2)
                        pref = int.from_bytes(pref, 'big')
                        ans = self.decode_rdata(rdata)
                        print("{} mail exchanger = {} {}".format(qname, pref, ans))
                    elif qtype == 28:
                        ip_address = ":".join([
                              str(rdata[-16:-14].hex())
                            , str(rdata[-14:-12].hex())
                            , str(rdata[-12:-10].hex())
                            , str(rdata[-10:-8].hex())
                            , str(rdata[-8:-6].hex())
                            , str(rdata[-6:-4].hex())
                            , str(rdata[-4:-2].hex())
                            , str(rdata[-2:].hex())
                        ])
                        print("Name: {}\nAddress: {}".format(qname, ip_address))
            elif (response_code == 1):
                print("\nFormat error. Unable to interpret query.\n")
            elif (response_code == 2):
                print("\nServer failure. Unable to process query.\n")
            elif (response_code == 3):
                print("\nName error. Domain name does not exist.\n")
            elif (response_code == 4):
                print("\nQuery request type not supported.\n")
            elif (response_code == 5):
                print("\nServer refused query.\n")
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
    
    def receive(self):
        while True:
            try:
                self.response_data, addr = self.csocket.recvfrom(1024)
                self.timer.stop()
            except Exception as e:
                print(e)

    # Send request, handle response/timeout and return resolved output or error
    def resolve(self, host):
        try: 
            # Transmit packet over UDP
            data = self.make_query(host)
            
            timer_val = self.timeout
            rcv_flag = 0
            for i in range(self.retry):
                for server in self.servers:
                    self.csocket.sendto(data, (server, self.port)) 
                    
                    # Receive the response packet 
                    self.timer.start()
                    while self.timer.running() and not self.timer.timeout():
                        pass
                    if self.timer.timeout():
                        self.timer.stop()
                    else:
                        rcv_flag = 1
                if rcv_flag:
                    break
                timer_val *= 2
                self.timer = Timer(timer_val)
                if i == self.retry-1:
                    print("Request timed out")
                    return

            self.decode_response(self.response_data)
        
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

