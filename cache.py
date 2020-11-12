import calendar
import time
import os
import copy
import codecs
import string
import struct
#from resolver import *


#NAME_OFFSET = b'\xc0\x0c'
#PADDING = '11'
#def set_padding(n):
#    return (8 - len(n)) * '0' + n
#def get_qname(record, packet=None):
#    index, qname = 0, ''
#    qname = ''
#    try:
#        while True:
#            if record[index] == 0:
#                break
#            size = record[index]
#            if set_padding(bin(size)[2:])[:2] == PADDING:
#                offset = codecs.encode(record[index:index+2], 'hex').decode()
#                offset = int(bin(int(offset, 16))[4:], 2)
#                index, record = offset, packet
#                continue
#            index += 1
#            for i in range(index, index+size):
#                qname += chr(record[i])
#            qname += '.'
#            index += size
#    except Exception:
#        return ''
#    return qname



def get_cur_time():
    return int(time.time())



class Cache:
    def __init__(self):
        self.cache = {}
        self.outdate_time = 0
#        self.used_qtypes = set()
    
    def printc(self):
        print(self.cache)

    def push(self, qname, qtype, sections):
        if qname not in self.cache:
            self.cache[qname] = {}
#        self.used_qtypes.add(qtype)
        entity = CachedEntity(sections)
        self.cache[qname][qtype] = entity
        #print(self.cache.keys())
        #print(self.cache[qname].keys())
        print(self.cache)
        #return entity.get_inner_qnames()

    def contains(self, qname, qtype):
        try: 
            print(self.cache)
            return qname in self.cache and qtype in self.cache[qname].keys()
        except Exception as e:
            print(e)

    def get(self, qname, qtype):
        #answer = b''
        sections = []
        is_outdated = False
        value = self.cache[qname][qtype]

        for field in value.sections:
            cur_time = get_cur_time()
            new_ttl = field.start_time + field.ttl - cur_time
            if new_ttl < self.outdate_time:
                is_outdated = True
                break
            #field.set_ttl(new_ttl)
            #field.start_time = cur_time
            
            #answer += field.section
            sections.append(field.section)
        if is_outdated:
            del value
            return None
        return sections

    #def _process_head(self, head, id):
    #    return id + head[2:]


class InnerEntity:
    def __init__(self, ttl, start_time, section):
        self.ttl        = ttl
        self.start_time = start_time
        self.section    = section

    #def set_ttl(self, new_ttl):
    #    self.ttl = new_ttl
    #    self.section = self.section[:6] + struct.pack('>I', new_ttl) + self.section[10:]


class CachedEntity():
    def __init__(self, sections):
        #resolver = DNS_Resolver(packet)
        #resolver.decode_response(packet)
        #sections = resolver.sections

        self.sections = []
        for section in sections:
            self.sections.append(InnerEntity(self.get_raw_ttl(section), get_cur_time(), section))

        #self.question = question
        #self._raw_packet = packet
        #self.head = b''

        #self._inner_qnames = []

        #self._process_packet(packet)

    def get_raw_ttl(self, section):
        ttl = section[6:10]
        return struct.unpack('>I', ttl)[0]
    
    #def _split_section(self, section):
    #    rlength = struct.unpack('>H', section[10:12])[0]
    #    return section[:12+rlength], section[12+rlength:]
    #
    #def _process_packet(self, packet):
    #    self.head = packet[:12]
    #    #print(self.head)
    #    spacket = packet[12:]
    #    #print(spacket)
    #    sections = self._parse_sections(self.head, spacket)

    #    for section in sections:
    #        self.sections.append(InnerEntity(self.get_raw_ttl(section), get_cur_time(), section))

    #def _parse_sections(self, head, packet):
    #    spacket = head + packet
    #    question, packet = self._split_packet(packet, packet.find(b'\x00')+5)
    #    sections = []

    #    while len(packet) > 1:
    #        name, packet = self._split_packet(packet, packet.find(b'\x00'))
    #        #print("NAME: ", name)
    #        info, packet = self._split_packet(packet, 8)
    #        #print("INFO: ", info)
    #        rlength, packet = self._split_packet(packet, 2)
    #        #print("RLENGTH: ", rlength)
    #        rdata, packet = self._split_packet(packet, struct.unpack('>H', rlength)[0])
    #        #print("RDATA: ", rdata)

    #        #self._process_rdata(info, rdata, spacket)

    #        section = name + info + rlength + rdata
    #        sections.append(section)
    #    #if sections[-1].startswith(b'\x00\x00'):
    #    #    sections = sections[:-1]
    #    return sections

    #def _process_rdata(self, info, rdata, packet):
    #    if self.qtype not in [15, 2]:
    #        return
    #    offset = codecs.encode(rdata[-2:], 'hex').decode()
    #    if offset is not '':
    #        qname = self.__get_qname(rdata, packet)
    #        print("QNAME: ", qname)
    #        self._inner_qnames.append(qname)

    #def __get_qname(self, rdata, packet):
    #    ndata = rdata[2:] if self.qtype != 2 else rdata
    #    return get_qname(ndata, packet)


    #def _split_packet(self, packet, index):
    #    data = packet[:index]
    #    return data, packet[index:]


    #def get_inner_qnames(self):
    #    return self._inner_qnames


#packet = b'\x11\x11\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x06google\x03com\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\x00\x00\x02#\x00\x11\x00\x1e\x04alt2\x05aspmx\x01l\xc0\x0c\xc0\x0c\x00\x0f\x00\x01\x00\x00\x02#\x00\t\x002\x04alt4\xc0/\xc0\x0c\x00\x0f\x00\x01\x00\x00\x02#\x00\x04\x00\n\xc0/\xc0\x0c\x00\x0f\x00\x01\x00\x00\x02#\x00\t\x00\x14\x04alt1\xc0/\xc0\x0c\x00\x0f\x00\x01\x00\x00\x02#\x00\t\x00(\x04alt3\xc0/'
#p = b'\x06google'
##packet = bytearray(packet)
#print(packet.hex())
#qtype, question = "", ""
#temp = CachedEntity(packet, qtype, question)
##temp.process_packet(packet)
#p = bytes([(p[0] & 0xf0) | 2]) + p[1:]
#print(p)

