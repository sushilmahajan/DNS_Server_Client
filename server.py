from cache import *
from resolver import *

mutex = allocate_lock()
cache = Cache()

def client_handler(ssocket, addr, data):
    try:
        global cache, qtypes
        csocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resolver = DNS_Resolver()
        
        # Decode data -> get qtype, qname
        resolver.decode_response(data)
        header, question = resolver.header, resolver.question
        qname = resolver.decode_rdata(question)
        qtype = question[question.find(b'\x00')+2]
        for i in qtypes:
            if qtype == qtypes[i]:
                qtype = i
                break

        response_code, sections = 7, []
        
        # Find in cache
        if cache.exists(qname, qtype):
            sections = cache.get(qname, qtype)
            if sections != None:
                response_code = 0
                print("Found in cache")
        # Else if recursive, Forward request to 8.8.8.8
        if response_code == 7 and header[2] & 1:
            resolver.qtype = qtype
            resolver.servers[0] = "8.8.8.8"
            
            resolver.resolve(qname)
            header2 = resolver.header
            response_code = int.from_bytes(header2[2:4], byteorder='big') & 15
            if response_code == 0:
                sections = resolver.sections
            if not cache.exists(qname, qtype):
                cache.insert(qname, qtype, sections)
                cache.printc()
        
        # Frame response
        header = header[:3] + bytes([(header[3] & 0xf0) | response_code]) + header[4:]
        answers = bytes()
        if response_code == 0:
            header = header[:7] + bytes([len(sections)]) + header[8:]
            for section in sections: 
                answers += section 
        packet = header + question + answers
        mutex.acquire()
        ssocket.sendto(packet, addr)
        mutex.release()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)


def main():
    ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ("127.0.0.1", 8000)
    ssocket.bind(server_addr)
    print("Server started...")
    while True:
        try:
            data, addr = ssocket.recvfrom(1024) 
            start_new_thread(client_handler, (ssocket, addr, data))
        except:
            break

if __name__ == "__main__":
    main()
