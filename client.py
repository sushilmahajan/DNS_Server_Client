import codecs
import sys
import socket
import bitstring
from timer import *
from _thread import *

qtypes = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "SOA": 6, "PTR": 12}
qclasses = {"IN": "0x0001", "CH": "0x0003", "HS": "0x0004"}

# Convert string or number to hex
def to_hex(x):
    result = "0"
    if type(x).__name__ == "int" and x >= 0:
        result = hex(x)
        if x < 16:
            result = "0" + result[2:]
    elif type(x).__name__ == "str":
        result = "".join([hex(ord(y))[2:] for y in x])
    return "0x" + result

# Check if a string is valid IP address 
def is_ip(host):
    host_name_to = host.split(".")
    if len(host_name_to) != 4:
        return False
    valid = True
    for n in host_name_to:
        valid = valid and n.isnumeric() and int(n) in range(256) 
        if not valid:
            break
    return valid
        
class DNS_Resolver():
    # Initialize parameters 
    def __init__(self):
        # TODO make variables private 
        self.domain = ""        # Default domain name for lookup
        self.servers = ["127.0.0.53"]       # List of servers to query
        self.def_server = "127.0.0.53"    # Default server for DNS lookup, 
        self.port = 53        # Server port number
        self.timeout = 1        # Initial timeout value in seconds
        self.retry = 3          # Number of retries
        self.cl = "IN"          # DNS query class 
        self.qtype = "A"        # Default query type 
        self.rec = True         # Recursive flag
        # create client socket
        self.csocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Internet, UDP.
        self.timer = Timer(self.timeout)
        self.data = ""
        
        start_new_thread(self.receive, ())
    
    # This function will decode resolv.conf & set parameters accordingly
    def decode_resolv_conf(self): 
        # TODO
        pass
    
    # Implementation of set option of nslookup 
    def set(self, arg):
        # TODO suboptions - ndots, search list 
        global qtypes, qclasses
        arg_list = arg.split("=")
        if arg_list[0] == "all":
            # Display all parameters
            print("Default server: {}".format(self.def_server))
            print("Address: {}".format(self.def_server + "#" + str(self.port)))
            print("\nSet options:")
            print("timeout = {}".format(self.timeout))
            print("retry = {}".format(self.retry))
            print("port = {}".format(self.port))
            print("querytype = {}".format(self.qtype))
            print("class = {}".format(self.cl))
            print("recurse") if self.rec else print("norecurse")
        elif arg_list[0] == "recurse":
            self.rec = True
        elif arg_list[0] == "norecurse":
            self.rec = False
        elif arg_list[0] == "class":
            if arg_list[1].upper() in qclasses.keys():
                self.cl = arg_list[1].upper()
            else:
                print("{} is not a valid class".format(arg_list[1]))
        elif arg_list[0] == "type":
            if arg_list[1].upper() in qtypes.keys():
                self.qtype = arg_list[1].upper()
            else:
                print("{} is not a valid query type".format(arg_list[1]))
        elif arg_list[0] == "timeout":
            if arg_list[1].isnumeric():
                self.timeout = int(arg_list[1])
            else:
                print("Enter a valid number")
        elif arg_list[0] == "retry":
            if arg_list[1].isnumeric():
                self.retry = int(arg_list[1])
            else:
                print("Enter a valid number")
        elif arg_list[0] == "port":
            if arg_list[1].isnumeric():
                self.port = int(arg_list[1])
            else:
                print("Enter a valid number")
                
    def server(self, server):
        self.def_server = server
        self.servers[0] = server

    # Create a DNS query packet using given parameters
    def make_query(self, host):
        global qtypes, qclasses
        dns_query_format = [
                "uint:16=id"
                , "uint:16=flags"
                , "uint:16=qdcount"
                , "uint:16=ancount"
                , "uint:16=nscount"
                , "uint:16=arcount"
                ]
        dns_query = {
                "id": 0x1a2b 
                , "flags": 0x100 
                , "qdcount": 1 
                , "ancount": 0
                , "nscount": 0
                , "arcount": 0
                }
        
        host_name_to = host.split(".")
        opcode = 1 << 11 if is_ip(host) else 0
        recurse = 1 << 8 if self.rec else 0
        dns_query["flags"] = opcode | recurse

        # Construct the QNAME:
        # size|label|size|label|size|...|label|0x00
        j = 0
        for i, tmp in enumerate(host_name_to):
            host_name_to[i] = host_name_to[i].strip()
            dns_query_format.append("hex=" + "qname" + str(j))
            dns_query["qname" + str(j)] = to_hex(len(host_name_to[i]))
            j += 1
            dns_query_format.append("hex=" + "qname" + str(j))
            dns_query["qname" + str(j)] = to_hex(host_name_to[i])
            j += 1
        # Add a terminating byte.
        dns_query_format.append("hex=qname" + str(j))
        dns_query["qname" + str(j)] = to_hex(0)
        # Set the type and class now.
        dns_query_format.append("uintbe:16=qtype")
        dns_query["qtype"] = qtypes[self.qtype] # For the A record.
        dns_query_format.append("hex=qclass")
        dns_query["qclass"] = qclasses[self.cl] # For IN or Internet.
        # Convert the struct to a bit string.
        data = bitstring.pack(",".join(dns_query_format), **dns_query)
        return data
    
    # Function to decode DNS answer packet
    def decode_response(self, host, data):
        global qtypes, qclasses
        host_name_to = host.split(".")

        data = bitstring.BitArray(bytes=data)
        # Unpack the receive DNS packet and extract the IP the host name resolved to.
        # Get the host name from the QNAME located just past the received header.
        host_name_from = []
        # First size of the QNAME labels starts at bit 96 and goes up to bit 104.
        # size|label|size|label|size|...|label|0x00
        x = 96
        y = x + 8
        for i, _ in enumerate(host_name_to):
            # Based on the size of the very next label indicated by
            # the 1 octet/byte before the label, read in that many
            # bits past the octet/byte indicating the very next
            # label size.
        
            # Get the label size in hex. Convert to an integer and times it
            # by 8 to get the number of bits.
            increment = (int(str(data[x:y].hex), 16) * 8)
            x = y
            y = x + increment
            # Read in the label, converting to ASCII.
            host_name_from.append(codecs.decode(data[x:y].hex, "hex_codec").decode())
            # Set up the next iteration to get the next label size.
            # Assuming here that any label size is no bigger than
            # one byte.
            x = y
            y = x + 8 # Eight bits to a byte.
        response_code = str(data[28:32].hex)
        result = {'host_name': None, 'ip_address': None}

        # Check for errors.
        if (response_code == "0"):
            result['host_name'] = ".".join(host_name_from)
            num_of_records = int(data[48:64].hex, 16)
            
            if self.qtype == "A":
                result['ip_address'] = ".".join([
                    str(data[-32:-24].uintbe)
                  , str(data[-24:-16].uintbe)
                  , str(data[-16:-8].uintbe)
                  , str(data[-8:].uintbe)
                ])
                print(result)
            elif self.qtype == "NS":
                x = y + 128
                y = x + 8
                for i in range(num_of_records):
                    size = int(data[x:y].hex, 16)
                    x = y
                    y = x + 8 * size
                    print("nameserver = {}".format(codecs.decode(data[x:y].hex, "hex_codec").decode()))
                    x = y + 14*8
                    y = x + 8
            elif self.qtype == "CNAME":
                pass
            
        return response_code, result
    
    def receive(self):
        self.data, addr = self.csocket.recvfrom(1024)
        self.timer.stop()

    # Send request, handle response/timeout and return resolved output or error
    def resolve(self, host):
        # Transmit packet over UDP
        data = self.make_query(host)
        
        timer_val = self.timeout
        rcv_flag = 0
        print(time.time())
        for i in range(self.retry):
            for server in self.servers:
                self.csocket.sendto(data.tobytes(), (server, self.port)) 
                
                # Receive the response packet 
                self.timer.start()
                while self.timer.running() and not self.timer.timeout():
                    pass
                if self.timer.timeout():
                    #print("Timeout for packet")
                    self.timer.stop()
                else:
                    rcv_flag = 1
                    print("Response received")
            if rcv_flag:
                break
            timer_val *= 2
            self.timer = Timer(timer_val)
            if i == self.retry-1:
                print("Timeout")
                print(time.time())
                sys.exit()


        data = self.data
        # Decode response packe & print the result/error
        response_code, result = self.decode_response(host, data)
        
        if (response_code == "0"):
            pass
            #print(result)
        elif (response_code == "1"):
            print("\nFormat error. Unable to interpret query.\n")
        elif (response_code == "2"):
            print("\nServer failure. Unable to process query.\n")
        elif (response_code == "3"):
            print("\nName error. Domain name does not exist.\n")
        elif (response_code == "4"):
            print("\nQuery request type not supported.\n")
        elif (response_code == "5"):
            print("\nServer refused query.\n")

def main():
    resolver = DNS_Resolver()
    if len(sys.argv) == 1 or (len(sys.argv) == 3 and sys.argv[1] == "-"):
        # Set default server for DNS lookup
        if len(sys.argv) == 3 and sys.argv[1] == "-":
            if is_ip(sys.argv[2]):
                resolver.def_server = sys.argv[2]   # TODO use method instead
            else:
                pass
                # TODO resolve the servername, handle error if occur 
        # Interactive mode
        cmd = input("> ")
        cmd_list = cmd.split()
        while cmd_list[0] != "exit":
            if cmd_list[0] == "set":
                for i in range(1, len(cmd_list)):
                    resolver.set(cmd_list[i])
            elif cmd_list[0] == "server":
                resolver.server(cmd_list[1])
            else:
                resolver.resolve(cmd_list[0])
            cmd = input("> ")
            cmd_list = cmd.split()
    else:
        # Non-Interactive mode
        resolver.resolve(sys.argv[1])

if __name__ == "__main__":
    main()
