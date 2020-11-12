import codecs
import struct
import sys
import socket
import bitstring
from timer import *
from _thread import *
import os

qtypes = {
        'A': 1, 'NS': 2, 'MD': 3, 'MF': 4, 'CNAME': 5,
        'SOA': 6, 'MB': 7, 'MG': 8, 'MR': 9, 'NULL': 10,
        'WKS': 11, 'PTR': 12, 'HINFO': 13, 'MINFO': 14,
        'MX': 15, 'TXT': 16
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
        
class DNS_Client():
    def __init__(self, arg_list):
        self.resolver = DNS_Resolver()
        self.arg_list = arg_list
    
    def run(self):
        if len(self.arg_list) == 1 or (len(self.arg_list) == 3 and self.arg_list[1] == "-"):
            # Set default server for DNS lookup
            if len(self.arg_list) == 3 and self.arg_list[1] == "-":
                if is_ip(self.arg_list[2]):
                    self.resolver.servers[0] = self.arg_list[2]   # TODO use method instead
                else:
                    pass
                    # TODO resolve the servername, handle error if occur 
                # Interactive mode
            try: 
                while True:
                    cmd = input("> ")
                    cmd_list = cmd.split()
                    if cmd_list[0] == "exit":
                        break
                    elif cmd_list[0] == "set":
                        for i in range(1, len(cmd_list)):
                            self.set(cmd_list[i])
                    elif cmd_list[0] == "server":
                        self.server(cmd_list[1])
                    else:
                        self.resolver.resolve(cmd_list[0])
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
        else:
            # Non-Interactive mode
            self.resolver.resolve(self.arg_list[1])
    
    # This function will decode resolv.conf & set parameters accordingly
    def decode_resolv_conf(self): 
        # TODO
        pass
    
    # Implementation of set option of nslookup 
    def set(self, arg):
        # TODO suboptions - ndots, search list 
        global qtypes, qclasses
        try:
            arg_list = arg.split("=")
            if arg_list[0] == "all":
                # Display all parameters
                print("Default server: {}".format(self.resolver.servers[0]))
                print("Address: {}".format(self.resolver.servers[0] + "#" + str(self.resolver.port)))
                print("\nSet options:")
                print("timeout = {}".format(self.resolver.timeout))
                print("retry = {}".format(self.resolver.retry))
                print("port = {}".format(self.resolver.port))
                print("querytype = {}".format(self.resolver.qtype))
                print("class = {}".format(self.resolver.cl))
                print("recurse") if self.resolver.rec else print("norecurse")
            elif arg_list[0] == "recurse":
                self.resolver.rec = True
            elif arg_list[0] == "norecurse":
                self.resolver.rec = False
            elif arg_list[0] == "type":
                if arg_list[1].upper() in qtypes.keys():
                    self.resolver.qtype = arg_list[1].upper()
                else:
                    print("{} is not a valid query type".format(arg_list[1]))
            elif arg_list[0] == "timeout":
                if arg_list[1].isnumeric():
                    self.resolver.timeout = int(arg_list[1])
                else:
                    print("Enter a valid number")
            elif arg_list[0] == "retry":
                if arg_list[1].isnumeric():
                    self.resolver.retry = int(arg_list[1])
                else:
                    print("Enter a valid number")
            elif arg_list[0] == "port":
                if arg_list[1].isnumeric():
                    self.resolver.port = int(arg_list[1])
                else:
                    print("Enter a valid number")
            else:
                print("Not a valid option")
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
                
    def server(self, server):
        self.resolver.servers.insert(0, server)
        print("Default server: {}".format(self.resolver.servers[0]))
        print("Address: {}".format(self.resolver.servers[0] + "#" + str(self.resolver.port)))


class DNS_Resolver():
    # Initialize parameters 
    def __init__(self):
        # TODO make variables private 
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
        opcode = 1 << 11 if is_ip(host) else 0
        recurse = 1 << 8 if self.rec else 0
        host = host + self.domain if self.domain != "" else host
        tid = 0x1111
        flags = opcode | recurse
        
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
        print(self.qtype)
        info_values = (qtypes[self.qtype], 1)
        info = info_fmt.pack(*info_values)
        question = qname + info
        
        packet = header + question
        print(packet)
        return packet
    
    def decode_rdata(self, data):
        try: 
            data = bytearray(data)
            x, y = 0, 0
            rdata = ""
            while y < len(data):
                length = data[x]
                #print(length)
                if not length: # TODO
                    break
                x += 1
                y = x + length
                rdata += data[x:y].decode() + "."
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
    def decode_response(self, host, data):
        try:
            packet = data
            # Get header
            self.header, packet = self.split_packet(packet, 12)
            #ancount = int.from_bytes(self.header[6:8], byteorder='big')
            #print(ancount)
            #response_code = int.from_bytes(self.header[2:4], byteorder='big') & 15
            #print(response_code)

            # Get self.question
            self.question, packet = self.split_packet(packet, packet.find(b'\x00')+5)
            #qname = self.decode_rdata(self.question)
            #qtype = int.from_bytes(self.question[-4:-2], byteorder='big')
            #print(qname)
            #print(qtype)
            
            # Get answer RRs
            self.sections = []
            while len(packet) > 1:
                name, packet = self.split_packet(packet, packet.find(b'\x00'))
                info, packet = self.split_packet(packet, 8)
                rlength, packet = self.split_packet(packet, 2)
                rdata, packet = self.split_packet(packet, struct.unpack('>H', rlength)[0])
                #ans = self.decode_rdata(rdata)
                #print(ans)

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
            rdata_list = []
            for section in self.sections:
                name, section = self.split_packet(section, section.find(b'\x00'))
                info, section = self.split_packet(section, 8)
                rlength, section = self.split_packet(section, 2)
                rdata, section = self.split_packet(section, struct.unpack('>H', rlength)[0])
                rdata_list.append(rdata)
                #ans = self.decode_rdata(rdata)
                #print("{} nameserver = {}".format(qname, ans))

            # Check for errors.
            if (response_code == 0):
                if self.qtype == "A":
                    data = rdata_list[0]
                    ip_address = ".".join([
                        str(data[-4:-3])
                      , str(data[-3:-2])
                      , str(data[-2:-1])
                      , str(data[-1:])
                    ])
                    print("Name: {}\nAddress: {}".format(qname, ip_address))
                elif self.qtype == "NS":
                    for rdata in rdata_list:
                        ans = self.decode_rdata(rdata)
                        print("{} nameserver = {}".format(qname, ans))
                elif self.qtype == "CNAME":
                    for rdata in rdata_list:
                        ans = self.decode_rdata(rdata)
                        print("{} cname = {}".format(host, ans))
                    #x = y + 128
                    #y = x + 8
                    #for i in range(num_of_records):
                    #    cname = ""
                    #    while True:
                    #        size = int(data[x:y].hex, 16)
                    #        if size == 0 or size == 192:
                    #            break
                    #        x = y
                    #        y = x + 8 * size
                    #        cname += codecs.decode(data[x:y].hex, "hex_codec").decode() + "."
                    #        x = y
                    #        y = x + 8
                elif self.qtype == "MX":
                    for rdata in rdata_list:
                        pref, rdata = self.split_packet(rdata, 1)
                        ans = self.decode_rdata(rdata)
                        print("{} mail exchanger = {} {}".format(host, pref, ans))
                    #x = y + 144
                    #y = x + 8
                    #for i in range(num_of_records):
                    #    cname = ""
                    #    pref = int(data[x-8:y-8].hex, 16)
                    #    while True:
                    #        size = int(data[x:y].hex, 16)
                    #        if size == 0 or size == 192:
                    #            break
                    #        print(size)
                    #        x = y
                    #        y = x + 8 * size
                    #        cname += codecs.decode(data[x:y].hex, "hex_codec").decode() + "."
                    #        x = y
                    #        y = x + 8
                    #    print("{} mail exchanger = {} {}".format(host, pref, cname))
                    #    x += 16*8
                    #    y = x + 8
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
                if addr[0] == self.servers[0]:
                    self.timer.stop()
            except Exception as e:
                print(e)

    # Send request, handle response/timeout and return resolved output or error
    def resolve(self, host):
        try: 
            # Transmit packet over UDP
            data = self.make_query(host)
            #print(data.tobytes())
            
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
                        #print("Timeout for packet")
                        self.timer.stop()
                    else:
                        rcv_flag = 1
                if rcv_flag:
                    break
                timer_val *= 2
                self.timer = Timer(timer_val)
                if i == self.retry-1:
                    print("Timeout")
                    return

            data = self.response_data
            self.decode_response(host, data)
            self.format_output()
        
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

def main():
    client = DNS_Client(sys.argv)
    client.run()

if __name__ == "__main__":
    main()
