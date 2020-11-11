import codecs
import sys
import socket
import bitstring
from _thread import *
from timer import *
from client import *
from cache import *



def client_handler(ssocket, addr, data):
    csocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Decode data -> get qtype, qname
    global qtypes, qclasses

    data = bitstring.BitArray(bytes=data)
    # Unpack the receive DNS packet and extract the IP the host name resolved to.
    # Get the host name from the QNAME located just past the received header.
    host_name_from = []
    # First size of the QNAME labels starts at bit 96 and goes up to bit 104.
    # size|label|size|label|size|...|label|0x00
    x = 96
    y = x + 8
    while True::
        # Based on the size of the very next label indicated by
        # the 1 octet/byte before the label, read in that many
        # bits past the octet/byte indicating the very next
        # label size.
    
        # Get the label size in hex. Convert to an integer and times it
        # by 8 to get the number of bits.
        increment = (int(str(data[x:y].hex), 16) * 8)
        if increment == 0:
            break
        x = y
        y = x + increment
        # Read in the label, converting to ASCII.
        host_name_from.append(codecs.decode(data[x:y].hex, "hex_codec").decode())
        # Set up the next iteration to get the next label size.
        # Assuming here that any label size is no bigger than
        # one byte.
        x = y
        y = x + 8 # Eight bits to a byte.
    x = y
    y = x + 16
    qtype = int(str(data[x:y].hex), 16)
    qname = ".".join(host_name_from)
    # Find in cache
    # Else if recursive, Forward request to 2.2.2.2
    # Frame response

def main():
    ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ("127.0.0.1", 53)
    ssocket.bind(server_addr)
    while True:
        try:
            data, addr = ssocket.recvfrom(1024) 
            start_new_thread(client_handler, (ssocket, addr, data))
        except:
            break
