import time
import struct

def get_time():
    return int(time.time())

class Cache:
    def __init__(self):
        self.cache = {}
    
    def printc(self):
        print(self.cache)

    def insert(self, qname, qtype, sections):
        if qname not in self.cache:
            self.cache[qname] = {}
        entity = ResourceRecordGroup(sections)
        self.cache[qname][qtype] = entity

    def exists(self, qname, qtype):
        return qname in self.cache and qtype in self.cache[qname].keys()

    def get(self, qname, qtype):
        sections = []
        is_outdated = False
        value = self.cache[qname][qtype]

        for field in value.sections:
            cur_time = get_time()
            new_ttl = field.start_time + field.ttl - cur_time
            if new_ttl < 0:
                is_outdated = True
                break
            sections.append(field.section)
        if is_outdated:
            del value
            return None
        return sections


class ResourceRecord:
    def __init__(self, ttl, start_time, section):
        self.ttl        = ttl
        self.start_time = start_time
        self.section    = section

class ResourceRecordGroup():
    def __init__(self, sections):
        self.sections = []
        for section in sections:
            self.sections.append(ResourceRecord(self.get__ttl(section), get_time(), section))

    def get__ttl(self, section):
        ttl = section[6:10]
        return struct.unpack('>I', ttl)[0]
