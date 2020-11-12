from resolver import *

myserver = 1

class DNS_Client():
    def __init__(self, arg_list):
        self.resolver = DNS_Resolver()
        self.arg_list = arg_list
        if myserver:
            self.resolver.servers[0] = "127.0.0.1"
            self.resolver.port = 8000
    
    def run(self):
        if len(self.arg_list) == 1 or (len(self.arg_list) == 3 and self.arg_list[1] == "-"):
            # Set default server for DNS lookup
            if len(self.arg_list) == 3 and self.arg_list[1] == "-":
                if is_ip(self.arg_list[2]):
                    self.resolver.servers[0] = self.arg_list[2]   # TODO use method instead
                else:
                    # TODO resolve the servername, handle error if occur 
                    #self.resolver.resolve(self.arg_list[2])
                    pass
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
                        self.resolver.format_output()
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
        else:
            # Non-Interactive mode
            self.resolver.resolve(self.arg_list[1])
            self.resolver.format_output()
    
    # This function will decode resolv.conf & set parameters accordingly
    def decode_resolv_conf(self): 
        # TODO
        pass
    
    # Implementation of set option of nslookup 
    def set(self, arg):
        # TODO suboptions - ndots, search list 
        global qtypes
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


def main():
    client = DNS_Client(sys.argv)
    client.run()

if __name__ == "__main__":
    main()
