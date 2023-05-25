'''

    Example:
    python3 gtp_dialer.py -d 10.10.1.1 -a internet -g 172.16.62.2 -s 10.15.8.1 -n SGW -t GTPv2
    python3 gtp_dialer.py -d 10.10.1.2 -a internet -g 172.16.62.2 -s 10.15.8.1 -G 1.2.3.4 -n MME -t GTPv2 -f 10.128.1.2 -u testes@apnxpto -w paswordxpto

    
'''



import sys

if sys.platform != "linux" and sys.platform != "linux2":
    print("Operating system not supported. Exiting.\n")
    exit(1)

import fcntl
import os	
import struct
import socket
import subprocess
import random
import select
import signal
import hashlib
import binascii

import time
from threading import Thread
from optparse import OptionParser


GTP_LOCAL_HOST = ''
GTP_C_LOCAL_PORT = 2123
GTP_C_REMOTE_PORT = 2123
GTP_U_LOCAL_PORT = 2152
GTP_U_REMOTE_PORT = 2152

DEFAULT_IMSI = '123456789012345'
DEFAULT_MSISDN = '1234567890'
DEFAULT_IMEI = '1234567812345678'
DEFAULT_OPERATOR = '12345'
DEFAULT_APN = 'internet'

DEFAULT_NSAPI = 5

HASH_PASS = '123456qwertyasdfghzxcvbn'

DHCP_CLIENT_NAME = 'GTP Dialer'

ie_size = { 1:1, 2:8, 3:6, 4:4, 5:4, 8:1, 9:28, 11:1, 12:3, 13:1, 14:1, 15:1, 16:4, 17:4, 18:5, 19:1, 20:1, 21:1, 22:9, 23:1, 24:1, 25:2, 26:2, 27:2, 28:2, 29:1, 127:4 }

class bcolors:
    BLUE = '\u001b[34m'
    YELLOW = '\u001b[33m'
    GREEN = '\u001b[32m'
    RED = '\u001b[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BACKGROUNDBLACK = '\u001b[40m'

def bytes2hex(byteArray):     
    return ''.join(hex(i).replace("0x", "0x0")[-2:] for i in byteArray)

def hex2bytes(hexString):
    return bytearray.fromhex(hexString)


def mac2str(mac):
    mac_hex = bytes2hex(mac)
    mac_str = ''
    for  i in range(0,len(mac_hex),2):
        mac_str += mac_hex[i:i+2] + ':'
    return mac_str[:-1]

def str2bytes(word):
    str_bytes = word.encode()
    return str_bytes    

def bytes_to_int(b):
    return int(binascii.hexlify(b),16) 

def int_to_bytes(i):
    return struct.pack("!I",i)

def checksum_carry_around_add(a,b):
    c = bytes_to_int(a) + bytes_to_int(b)
    c = int_to_bytes(c)
    r = (bytes_to_int(c) & bytes_to_int(b'\x00\x00\xFF\xFF')) + (bytes_to_int(c) >> 16)
    r = int_to_bytes(r)
    return r 

def checksum(msg):
    s = b'\x00\x00'

    #padding
    if len(msg) % 2 !=0:
        msg += b'\x00'

    for i in range(0, len(msg), 2):
        w = struct.pack("!BB",int(msg[i]), int(msg[i+1]))
        s = checksum_carry_around_add(s,w)
    
    r = int_to_bytes(~bytes_to_int(s) & bytes_to_int(b'\x00\x00\xFF\xFF'))

    #print("checksum: " + str(r[2:]))   

    return r[2:]



def dhcp_option(id, size, value):  
    return struct.pack("!B", id) + struct.pack("!B", size) + value

    
def dhcp_request_packet(dhcp_type, xid, mac, ip):  
    op = b'\x01' # Boot Request
    htype = b'\x01' # Ethernet
    hlen = b'\x06' # 6 bytes (MAC addr)
    hops = b'\x00' # 0 hop (hop > 1 when DHCP Relay)
    #xid = b'\x00\x00\x00\x00' # Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server.
    secs = b'\x00\x00' # Filled in by client, seconds elapsed since client began address acquisition or renewal process
    flags = b'\x00\x00' # Unicast
    ciaddr = str2ip("0.0.0.0")  # Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
    yiaddr = str2ip("0.0.0.0")  # 'your' (client) IP address 0.0.0.0 in requests
    siaddr = str2ip("0.0.0.0")  # IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    giaddr = str2ip("0.0.0.0")  # Relay agent IP address, used in booting via a relay agent.
    chaddr = mac + bytes(10) # Client hardware address (16 bytes)
    sname = bytes(64)   # Optional server host name, null terminated string. (64 bytes)
    file = bytes(128)   # Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER. (128 bytes)
    magic = b'\x63\x82\x53\x63' # RFC 951 
    
    opt_dhcp_type = dhcp_option(53,1, struct.pack("!B", dhcp_type))
    opt_dhcp_client_identifier = dhcp_option(61,7, b'\x01' + mac)
    opt_dhcp_hostname = dhcp_option(12,len(DHCP_CLIENT_NAME)+17, str2bytes(DHCP_CLIENT_NAME + mac2str(mac)))

    if ip == '':
        opt_ip = ''
    else:
        opt_ip = dhcp_option(50,4, ip)

    opt_dhcp_parameter_request_list = dhcp_option(55,9, b'\x01\x21\x03\x06\x0f\x1c\x33\x3a\x3b')
    opt_dhcp_end = b'\xff'
    
    p = op + htype + hlen + hops + xid + secs + flags
    p = p + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file + magic
    p = p + opt_dhcp_type
    p = p + opt_dhcp_client_identifier
    p = p + opt_dhcp_hostname
    if opt_ip != '':
        p = p + opt_ip
    p = p + opt_dhcp_parameter_request_list
    p = p + opt_dhcp_end

    return p
    
def dhcp_decode(dhcp_packet):  
    dhcp_param = dict()
    dhcp_param["op"] = dhcp_packet[0:1]
    dhcp_param["htype"] = dhcp_packet[1:2]
    dhcp_param["hlen"] = dhcp_packet[2:3]
    dhcp_param["hops"] = dhcp_packet[3:4]
    dhcp_param["xid"] = dhcp_packet[4:8]
    dhcp_param["secs"] = dhcp_packet[8:10]
    dhcp_param["flags"] = dhcp_packet[10:12]
    dhcp_param["ciaddr"] = dhcp_packet[12:16]
    dhcp_param["yiaddr"] = dhcp_packet[16:20]
    dhcp_param["siaddr"] = dhcp_packet[20:24]
    dhcp_param["giaddr"] = dhcp_packet[24:28]
    dhcp_param["chaddr"] = dhcp_packet[28:34]
    dhcp_param["sname"] = dhcp_packet[44:108]
    dhcp_param["file"] = dhcp_packet[108:236]
    dhcp_param["magic"] = dhcp_packet[236:240]

    pointer = 240
    
    while pointer < len(dhcp_packet):
        if dhcp_packet[pointer:pointer+1] == b'\xff':
            break
        else:
            t = struct.unpack('!B', dhcp_packet[pointer:pointer+1])[0]
            l = struct.unpack('!B', dhcp_packet[pointer+1:pointer+2])[0]
            dhcp_param[str(t)] = dhcp_packet[pointer+2:pointer+2+l]
            pointer = pointer + 2 + l 
        
    return dhcp_param 



def udp_header(scr_port, dst_port, payload_length):
      
    udp_src_port = struct.pack("!H", scr_port)
    udp_dst_port = struct.pack("!H", dst_port)
    udp_length = struct.pack("!H", payload_length + 8) #add UDP 8 byte header
    udp_checksum = struct.pack("!H", 0)
    
    return udp_src_port + udp_dst_port + udp_length + udp_checksum 

  

def ip_header_with_length(source_address, destination_address, protocol, calc_checksum, payload_length):
    ip_version_and_header_length = b'\x45' 
    ip_dscp = b'\x00'
    ip_total_length = struct.pack("!H", 20 + payload_length)
    #ip_total_length = b'\x00\x00'
    ip_identification = struct.pack("!H", 0)
    ip_flags_and_fragment_offset = b'\x40\x00'
    ip_ttl = struct.pack("!B", 64)
    ip_protocol = struct.pack("!B", protocol)
    ip_header_checksum = b'\x00\x00'
    ip_source_addr = str2ip(source_address)
    ip_destination_addr = str2ip(destination_address)
    
    h_begin = ip_version_and_header_length + ip_dscp + ip_total_length + ip_identification + ip_flags_and_fragment_offset + ip_ttl + ip_protocol
    h_end =  ip_source_addr + ip_destination_addr
        
    if calc_checksum == 1:
        ip_header_checksum = checksum(h_begin + ip_header_checksum + h_end)

    return h_begin + ip_header_checksum + h_end

		
def ip2str(ip_bytes):
    return socket.inet_ntop(socket.AF_INET,ip_bytes)
    
def str2ip(ip_str):
    return socket.inet_aton(ip_str)
   
def gtp_u_header(teid, length):
    
    gtp_flags = b'\x30'
    gtp_message_type = b'\xff'
    gtp_length = struct.pack("!H", length)
    gtp_teid = struct.pack("!I", teid)

    return gtp_flags + gtp_message_type + gtp_length + gtp_teid
    

def open_tun(n):
    TUNSETIFF = 0x400454ca
    IFF_TUN   = 0x0001
    IFF_TAP   = 0x0002
    IFF_NO_PI = 0x1000 # No Packet Information - to avoid 4 extra bytes

    TUNMODE = IFF_TUN | IFF_NO_PI
    MODE = 0
    DEBUG = 0
    if sys.platform == "linux" or sys.platform == "linux2":
        f = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(f, TUNSETIFF, struct.pack("16sH", bytes("tun%d" % n, "utf-8"), TUNMODE))
        #ifname = ifs[:16].strip("\x00")
        subprocess.call("ifconfig tun%d up" % n, shell=True) 
   
    return f

def bcd(chars):
    
    bcd_string = ""
    for i in range(len(chars) // 2):
        bcd_string += chars[1+2*i] + chars[2*i]   
    bcd_bytes = bytearray.fromhex(bcd_string)

    return bcd_bytes    


###### GTPv1 ######

def add_imsi(imsi):
    if len(imsi) % 2 == 1:
        imsi += "f"
    imsi = bcd(imsi)
    return b'\x02' + imsi

def add_selection_mode(sel_mode):
    return b'\x0f' + bytes([(252+int(sel_mode)) % 256])  

def add_random_teid(teid_type):
    global teid_local_control, teid_local_data

    rand_number = random.randrange(pow(2,32)-1)
    if teid_type == "data":
        teid_local_data = rand_number
        return b'\x10' + struct.pack("!L", rand_number)
    elif teid_type == "control":
        teid_local_control = rand_number
        return b'\x11' + struct.pack("!L", rand_number)

def add_nsapi(value):
    return b'\x14' + struct.pack("!B", value % 256)

def add_eua_ipv4():
    return b'\x80\x00\x02\xf1\x21'

def add_eua_ipv6():
    return b'\x80\x00\x02\xf1\x57'

def add_eua_ipv4v6():
    return b'\x80\x00\x02\xf1\x8d'

def add_apn(apn):
   apn_bytes = bytes()
   apn_list = apn.split(".") 
   
   for word in apn_list:
       apn_bytes += struct.pack("!B", len(word)) + word.encode()    
   return b'\x83\x00' + struct.pack("!B",len(apn_bytes)) + apn_bytes

def add_gsn_address(address):
    return b'\x85\x00\x04' + str2ip(address)

def add_msisdn(msisdn):
    if len(msisdn) % 2 == 1:
        msisdn += "f"
    msisdn = bcd(msisdn)
    return b'\x86' + struct.pack("!H", len(msisdn) + 1) + b'\x91' + msisdn
   
def return_random_bytes(size):
    if size == 0: return b''
    if size == 4: return struct.pack('!I', random.randrange(pow(2,32)-1))
    if size == 8: return struct.pack('!Q', random.randrange(pow(2,64)-1))
    if size == 16: return struct.pack('!Q', random.randrange(pow(2,64)-1)) + struct.pack('!Q', random.randrange(pow(2,64)-1))
    
def add_pco(pdptype, username, password, dhcp_flag, authentication_type):
    len_pco = 0
    pap = b'' 
    chap = b''
    dhcp = b''
    if username != None and password != None:
        if authentication_type == 'PAP':
            len_username = struct.pack("!B", len(username))
            username = username.encode()
            len_password = struct.pack("!B", len(password))
            password = password.encode()        
            len_pap_2B = struct.pack("!H", len(username)+len(password) + 6)
            len_pap_1B = struct.pack("!B", len(username)+len(password) + 6)
            len_pco = len(username)+len(password) + 6 + 3
            pap = b'\xc0\x23' + len_pap_1B + b'\x01\x01' + len_pap_2B + len_username + username + len_password + password
            chap = b''
        elif authentication_type == 'CHAP':
            value = return_random_bytes(16) 
            name = b'GTP Dialer'
            length = struct.pack("!H", len(value) + len(name) + 5)
            chap_challenge = b'\xc2\x23' + length[-1:] + b'\x01\x01' + length + b'\x10' + value + name
            username = username.encode()            
            password = password.encode()
            m = hashlib.md5()
            m.update(b'\x01' + password + value)
            hash = m.digest()
            length = struct.pack("!H", len(hash) + len(username) + 5)            
            chap_response = b'\xc2\x23' + length[-1:] + b'\x02\x01' + length + b'\x10' + hash + username
            chap = chap_challenge + chap_response 
            len_pco = len(chap)
            pap = b''
        
    if dhcp_flag == True:
        dhcp = b'\x00\x0b\x00'
        len_pco += 3

    if pdptype == "ipv4":
        len_pco = struct.pack("!H", 35 + len_pco)        
        return b'\x84' + len_pco + b'\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x0c\x00' + pap + chap + dhcp
    elif pdptype == "ipv6":
        len_pco = struct.pack("!H", 7 + len_pco)        
        return b'\x84' + len_pco + b'\x80\x00\x03\x00\x00\x01\x00' + pap + chap + dhcp
    elif pdptype == "ipv4v6":
        len_pco = struct.pack("!H", 41 + len_pco)        
        return b'\x84' + len_pco + b'\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x03\x00\x00\x0c\x00\x00\x01\x00' + pap + chap + dhcp

def add_qos():
    # quick version. requests 70Mbits DL and 5.8Mbits UL
    return b'\x87\x00\x0f\x01\x23\x43\x1f\x73\x96\xd2\xfe\x74\x83\xff\xff\x00\x80\x00'

def add_rat(rat):
    return b'\x97\x00\x01' + bytes([rat])

def add_common_flags():
    return b'\x94\x00\x01\x80'

def add_imei(imei):
    if len(imei) % 2 == 1:
        imei += "f"
    imei = bcd(imei)    
    return b'\x9a' + struct.pack("!H", len(imei))  + imei

def add_private_extension(identifier, value, value2):
    if identifier == 0:
        value_bytes = b'\x7a\x57\x00'
        value_bytes += value.encode()    
    elif identifier == 1:
        m = hashlib.md5()
        n = hashlib.sha1()
        m.update((value + HASH_PASS).encode())
        m_digest_password = m.digest()
        n.update(m_digest_password + HASH_PASS.encode() + value2) #value2 == TEID Control
        value_bytes = b'\x7a\x57\x01'
        value_bytes += n.digest()  
    elif identifier == 2:
        value_bytes = b'\x7a\x57\x02'
        value_bytes += socket.inet_aton(value)
    return b'\xff\x00' + struct.pack("!B",len(value_bytes)) + value_bytes    
    

### GTPv1 messages ###    
def cpc_request(apn, gtp_address, imsi, msisdn, pdptype, username, password, ggsn, username_pco, password_pco, dhcp, cc, operator, imei, authentication_type, rat, sel_mode):

    global sequence_number
    
    gtp_flags = b'\x32'
    gtp_message_type = b'\x10'
    gtp_length = b'\x00\x00' #length = 0. filled in the end
    gtp_teid = b'\x00\x00\x00\x00'
    gtp_sequence_number = struct.pack("!H", sequence_number)
    gtp_n_pdu = b'\x00'
    gtp_next_extension_header = b'\x00'
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_n_pdu + gtp_next_extension_header

    gtp_imsi = add_imsi(imsi)
    gtp_routing_area_identity = add_routing_area_identity(operator)
    gtp_selection_mode = add_selection_mode(sel_mode)    
    gtp_teid_local_data = add_random_teid("data")
    gtp_teid_local_control = add_random_teid("control")
    gtp_nsapi = add_nsapi(DEFAULT_NSAPI)
    gtp_cc = b'\x1a' + hex2bytes(cc)
    
    if pdptype == "ipv4":
        gtp_end_user_address = add_eua_ipv4()
    elif pdptype == "ipv6":
        gtp_end_user_address = add_eua_ipv6()
    elif pdptype == "ipv4v6":
        gtp_end_user_address = add_eua_ipv4v6()
    gtp_apn = add_apn(apn)
    gtp_pco = add_pco(pdptype, username_pco, password_pco, dhcp, authentication_type)    
    gtp_gsn_address = add_gsn_address(gtp_address)
    gtp_msisdn = add_msisdn(msisdn)
    gtp_qos = add_qos()   
    gtp_common_flags = add_common_flags()
    if rat is None:
        gtp_rat = add_rat(1)
    else:
        gtp_rat = add_rat(int(rat))    
    gtp_imei = add_imei(imei)
    
    gtp_ie = gtp_imsi + gtp_routing_area_identity + gtp_selection_mode + gtp_teid_local_data + gtp_teid_local_control + gtp_nsapi + gtp_cc + gtp_end_user_address + gtp_apn + gtp_pco + gtp_gsn_address + gtp_gsn_address + gtp_msisdn + gtp_qos + gtp_common_flags + gtp_rat + gtp_imei

    if username is not None and password is not None:
        gtp_pe1 = add_private_extension(0, username,None)
        gtp_pe2 = add_private_extension(1, password, gtp_teid_local_control[1:])
        gtp_ie += gtp_pe1 + gtp_pe2
    if ggsn is not None:
        gtp_pe3 = add_private_extension(2, ggsn, None)
        gtp_ie += gtp_pe3

    cpc_packet = bytearray(gtp_header + gtp_ie)

    length = len(cpc_packet) - 8    
    cpc_packet[3] = length % 256
    cpc_packet[2] = length // 256
    
    sequence_number +=1

    return cpc_packet 


def dpc_request(teid):

    global sequence_number

    gtp_flags = b'\x32'
    gtp_message_type = b'\x14'
    gtp_length = b'\x00\x08'
    gtp_teid = struct.pack("!L", teid)
    gtp_sequence_number = struct.pack("!H", sequence_number)
    gtp_n_pdu = b'\x00'
    gtp_next_extension_header = b'\x00'
    gtp_teardown_nsapi = b'\x13\xff\x14' + bytes([DEFAULT_NSAPI])

    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_n_pdu + gtp_next_extension_header
    
    sequence_number +=1

    return gtp_header + gtp_teardown_nsapi 


def dpc_response(teid, request_seq_num):

    gtp_flags = b'\x32'
    gtp_message_type = b'\x15'
    gtp_length = b'\x00\x06'
    gtp_teid = struct.pack("!L", teid)
    gtp_sequence_number = request_seq_num
    gtp_n_pdu = b'\x00'
    gtp_next_extension_header = b'\x00'
    
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_n_pdu + gtp_next_extension_header

    gtp_cause = b'\x01\x80'
    
    return gtp_header + gtp_cause


def upc_response(teid, request_seq_num, qos):

    gtp_flags = b'\x32'
    gtp_message_type = b'\x13'
    gtp_length = b'\x00\x00'
    gtp_teid = struct.pack("!L", teid)
    gtp_sequence_number = request_seq_num
    gtp_n_pdu = b'\x00'
    gtp_next_extension_header = b'\x00'
    
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_n_pdu + gtp_next_extension_header
    
    gtp_cause = b'\x01\x80'
    
    upc_packet = bytearray(gtp_header + gtp_cause)
    if qos != None:
        gtp_qos = b'\x87' + struct.pack("!H",len(qos)) + qos
        upc_packet += bytearray(gtp_qos)
    
    length = len(upc_packet) - 8
    
    upc_packet[3] = length % 256
    upc_packet[2] = length // 256

    return upc_packet
    
    
    
# Version not ready for extension headers. Validates TEID and cause=Requested Accepted in case of answer messages
# Uses a dictionary. Index is the IE, value are the data bytes. Length bytes (when they do exist) are discarted
def decode_gtpc(gtp_packet):
    global request_sequence_number

    valid = 0

    if int(gtp_packet[0]) // 16 == 3 and gtp_packet[4:8] == struct.pack("!L", teid_local_control) and int(gtp_packet[1]) % 2 == 1: #Response and Cause =128,129,130
        if int(gtp_packet[0]) % 16 == 0 and (gtp_packet[8:10] == b'\x01\x80' or gtp_packet[8:10] == b'\x01\x81' or gtp_packet[8:10] == b'\x01\x82'):
            pointer = 8
            valid = 1
        elif int(gtp_packet[0:1]) % 16 < 4 and (gtp_packet[12:14] == b'\x01\x80' or gtp_packet[12:14] == b'\x01\x81' or gtp_packet[12:14] == b'\x01\x82'):
            pointer = 12
            valid = 1

        # Proxy specific: if returned error is 240 - it means authentication is needed
        elif (int(gtp_packet[0]) % 16 == 0 and gtp_packet[8:10] == b'\x01\xF0') or (int(gtp_packet[0]) % 16 < 4 and gtp_packet[12:14] == b'\x01\xF0'):
            return 240
        # Proxy specific: if returned error is 239 - it means authentication is wrong
        elif (int(gtp_packet[0]) % 16 == 0 and gtp_packet[8:10] == b'\x01\xef') or (int(gtp_packet[0]) % 16 < 4 and gtp_packet[12:14] == b'\x01\xef'):
            return 239

    elif int(gtp_packet[0]) // 16 == 3 and gtp_packet[4:8] == struct.pack("!L", teid_local_control) and int(gtp_packet[1]) % 2 == 0: #Requests
        if int(gtp_packet[0]) % 16 == 0:
            pointer = 8
            valid = 1
            request_sequence_number = None
        elif int(gtp_packet[0]) % 16 < 4:
            pointer = 12
            valid = 1
            if int(gtp_packet[0]) % 16 > 1:
                request_sequence_number = gtp_packet[8:10]
    
    if valid == 1:
        decode_dict = {}
        while pointer < len(gtp_packet):
            if gtp_packet[pointer] < 128:
                decode_dict[gtp_packet[pointer]] = gtp_packet[pointer+1:pointer+1+ie_size[gtp_packet[pointer]]]
                pointer += 1+ie_size[gtp_packet[pointer]]
            else:
                length = 256 * gtp_packet[pointer + 1] + gtp_packet[pointer + 2]
                if gtp_packet[pointer] == 133:
                    # 133 is the first GSN (control) and 1133 is the second GSN (user plane)
                    if 133 in decode_dict:
                        decode_dict[1133] = gtp_packet[pointer+3:pointer+3+length]                        
                    else:
                        decode_dict[gtp_packet[pointer]] = gtp_packet[pointer+3:pointer+3+length]
                else:                     
                    decode_dict[gtp_packet[pointer]] = gtp_packet[pointer+3:pointer+3+length]                
                pointer += 3 + length
        
        return decode_dict
    else:
        return None
    

####### Endof GTPv1 #######

###############################################################################################################################################################

####### GTPv2 ##########


def decode_gtpc_v2(gtp_packet):
    global request_sequence_number

    valid = 0

    if int(gtp_packet[0]) // 16 == 4 and gtp_packet[4:8] == struct.pack("!L", teid_local_control) and int(gtp_packet[1]) % 2 == 1: #Response and Cause =128,129,130
        if (gtp_packet[16:17] == b'\x10' or gtp_packet[16:17] == b'\x11' or gtp_packet[16:17] == b'\x12' or gtp_packet[16:17] == b'\x13'):
            pointer = 12
            valid = 1
        else:  
            return -1
            
    elif int(gtp_packet[0]) // 16 == 4 and gtp_packet[4:8] == struct.pack("!L", teid_local_control) and int(gtp_packet[1]) % 2 == 0: #Requests
        pointer = 12
        valid = 1
        request_sequence_number = gtp_packet[8:11]
    
    if valid == 1:
        decode_dict = {}
        while pointer < len(gtp_packet):    
            type = gtp_packet[pointer]
            instance = gtp_packet[pointer + 3]
            length = 256 * gtp_packet[pointer + 1] + gtp_packet[pointer + 2]
        
            decode_dict[(type,instance)]= gtp_packet[pointer+4:pointer+4+length]                    
            pointer += 4 + length
        
        return decode_dict
    else:
        return None    
    
def decode_ie_v2(gtp_packet):

    decode_dict = {}
    pointer = 0
    while pointer < len(gtp_packet):     
        type = gtp_packet[pointer]
        instance = gtp_packet[pointer + 3]
        length = 256 * gtp_packet[pointer + 1] + gtp_packet[pointer + 2]
    
        decode_dict[(type,instance)]= gtp_packet[pointer+4:pointer+4+length]                    
        pointer += 4 + length       
    return decode_dict
   

def add_imsi_v2( instance, imsi):
    if len(imsi) % 2 == 1:
        imsi += "f"
    imsi = bcd(imsi)
    return b'\x01' + struct.pack("!H", len(imsi)) + struct.pack("!B",instance) + imsi

def add_imei_v2( instance, imei):
    if len(imei) % 2 == 1:
        imei += "f"
    imei = bcd(imei)  
    return b'\x4b' + struct.pack("!H", len(imei)) + struct.pack("!B",instance) + imei
   
def add_msisdn_v2(instance, msisdn):
    if len(msisdn) % 2 == 1:
        msisdn += "f"
    msisdn = bcd(msisdn) 
    return b'\x4c' + struct.pack("!H", len(msisdn)) + struct.pack("!B",instance) + msisdn
       
def add_serving_network_v2(instance, mccmnc): 
    if len(mccmnc)==5:
        mnc3 = 'f'
    else:
        mnc3 = mccmnc[5]    
    return b'\x53' + struct.pack("!H", 3) + struct.pack("!B",instance) + bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + mnc3 + mccmnc[3] + mccmnc[4])    

def add_routing_area_identity(mccmnc):
    if len(mccmnc)==5:
        mnc3 = 'f'
    else:
        mnc3 = mccmnc[5]
    return b'\x03' + bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + mnc3 + mccmnc[3] + mccmnc[4]) + b'\xff\xfe\xff'

def add_user_location_info_v2(instance, mccmnc, rat): # rat = 1 (sgsn) or 6 (mme ou sgw)
    if len(mccmnc)==5:
        mnc3 = 'f'
    else:
        mnc3 = mccmnc[5]
    mcc_mnc = bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + mnc3 + mccmnc[3] + mccmnc[4])  # 3 bytes
    
    if rat == 1:
        return b'\x56' + struct.pack("!H", 8) + struct.pack("!B",instance) + b'\x02' + mcc_mnc + b'\x00\x01\x00\x01'    
    else:
        return b'\x56' + struct.pack("!H", 13) + struct.pack("!B",instance) + b'\x18' + mcc_mnc + b'\x00\x01' + mcc_mnc + b'\x00\x00\x00\x01'
    

def add_rat_v2(instance, rat): # rat = 1 (sgsn) or 6 (mme ou sgw) or 3 (epdg, twan) but user can also set RAT to test erroneous scenarios
    return b'\x52' + struct.pack("!H", 1) + struct.pack("!B",instance) + bytes([rat])    
        
def add_indication_v2(instance, b1, b2, b3, b4, b5, b6):
    return b'\x4d' + struct.pack("!H", 6) + struct.pack("!B",instance) + bytes([b1,b2,b3,b4,b5,b6]) 

def add_random_f_teid_v2(instance, int_type, ip, teid):  # if teid=0 it generates a new random TEID, else it uses the received value (used in modify bearer)
    global teid_local_control, teid_local_data
    
    if teid==0:
        rand_number = random.randrange(pow(2,32)-1)
    else:
        rand_number = teid
    
    if int_type == "s11_c_mme":
        teid_local_control = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+10]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)
    
    elif int_type == "s5_c_sgw":
        teid_local_control = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+6]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)      
    
    elif int_type == "s5_c_pgw":       
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+7]) + struct.pack("!L", 0) + socket.inet_aton(ip)    

    elif int_type == "s2b_c_pgw":       
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+32]) + struct.pack("!L", 0) + socket.inet_aton(ip) 

    elif int_type == "s2a_c_pgw":       
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+36]) + struct.pack("!L", 0) + socket.inet_aton(ip) 
    
    elif int_type == "s4_c_sgsn":
        teid_local_control = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+17]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)    
    
    elif int_type == "s1_u_enb":
        teid_local_data = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+0]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)    
        
    elif int_type == "s4_u_sgsn":
        teid_local_data = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+15]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)
        
    elif int_type == "s5_u_sgw":
        teid_local_data = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+4]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)

    elif int_type == "s2b_c_epdg":
        teid_local_control = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+30]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)

    elif int_type == "s2b_u_epdg":
        teid_local_data = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+31]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)

    elif int_type == "s2a_c_twan":
        teid_local_control = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+35]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)

    elif int_type == "s2a_u_twan":
        teid_local_data = rand_number
        return b'\x57' + struct.pack("!H", 9) + struct.pack("!B",instance) + bytes([128+34]) + struct.pack("!L", rand_number) + socket.inet_aton(ip)


        
def add_apn_v2(instance,apn,operator):
    apn_bytes = bytes()
    if len(operator)==5:
        apn = apn + '.mnc0' + operator [3:5] + '.mcc' + operator [0:3] + '.gprs'
    else:
        apn = apn + '.mnc' + operator [3:6] + '.mcc' + operator [0:3] + '.gprs'        
        
    apn_l = apn.split(".") 
   
    for word in apn_l:
        apn_bytes += struct.pack("!B", len(word)) + word.encode()  
    return b'\x47' + struct.pack("!H",len(apn_bytes)) + struct.pack("!B",instance) + apn_bytes  

def add_selection_mode_v2(sel_mode):
    return b'\x80\x00\x01\x00' + bytes([int(sel_mode) % 256])

def add_pco_v2(pdptype, username, password, dhcp_flag, authentication_type, node):
    len_pco = 0
    pap = b''
    chap = b''
    dhcp = b''
    if username != None and password != None:
        if authentication_type == 'PAP':
            len_username = struct.pack("!B", len(username))
            username = username.encode()
            len_password = struct.pack("!B", len(password))
            password = password.encode()        
            len_pap_2B = struct.pack("!H", len(username)+len(password) + 6)
            len_pap_1B = struct.pack("!B", len(username)+len(password) + 6)
            len_pco = len(username)+len(password) + 6 + 3
            pap = b'\xc0\x23' + len_pap_1B + b'\x01\x01' + len_pap_2B + len_username + username + len_password + password
            chap = b''
        elif authentication_type == 'CHAP':
            value = return_random_bytes(16) 
            name = b'GTP Dialer'
            length = struct.pack("!H", len(value) + len(name) + 5)
            chap_challenge = b'\xc2\x23' + length[-1:] + b'\x01\x01' + length + b'\x10' + value + name

            username = username.encode()            
            password = password.encode()
            m = hashlib.md5()
            m.update(b'\x01' + password + value)
            hash = m.digest()
            length = struct.pack("!H", len(hash) + len(username) + 5)            
            chap_response = b'\xc2\x23' + length[-1:] + b'\x02\x01' + length + b'\x10' + hash + username

            chap = chap_challenge + chap_response             
            len_pco = len(chap)
            pap = b''
        
    if dhcp_flag == True:
        dhcp = b'\x00\x0b\x00'
        len_pco += 3
    
    if node in ("SGSN", "MME", "SGW"):
        ie_type = b'\x4e' # PCO
    else:
        ie_type = b'\xa3' # Additional PCO (APCO) for ePDG and TWAN
    
    if pdptype == "ipv4":
        len_pco = struct.pack("!H", 35 + len_pco)
        return ie_type + len_pco + b'\x00\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x0c\x00' + pap + chap + dhcp
    elif pdptype == "ipv6":
        len_pco = struct.pack("!H", 7 + len_pco)        
        return ie_type + len_pco + b'\x00\x80\x00\x03\x00\x00\x01\x00' + pap + chap + dhcp

    elif pdptype == "ipv4v6":
        len_pco = struct.pack("!H", 41 + len_pco)        
        return ie_type + len_pco + b'\x00\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x03\x00\x00\x0c\x00\x00\x01\x00' + pap + chap + dhcp
 
def add_pdn_type_v2(instance,pdn_type):
    return b'\x63\x00\x01\x00' + bytes([pdn_type])
        
def add_pdn_address_v2(instance, pdn_type, ipv4, ipv6):        
    if pdn_type == 1:
        return b'\x4f' + struct.pack("!H",5) + struct.pack("!B",instance) + bytes([pdn_type]) + socket.inet_aton(ipv4)
    elif pdn_type == 2:
        return b'\x4f' + struct.pack("!H",18) + struct.pack("!B",instance) + bytes([pdn_type]) + b'\x00' + socket.inet_pton(socket.AF_INET6, ipv6)
    elif pdn_type == 3:
        return b'\x4f' + struct.pack("!H",22) + struct.pack("!B",instance) + bytes([pdn_type]) + b'\x00' + socket.inet_pton(socket.AF_INET6, ipv6) + socket.inet_aton(ipv4)

def add_apn_restriction_v2():
    return b'\x7f\x00\x01\x00\x00'

def add_ambr_v2():
    return b'\x48\x00\x08\x00\x00\x0f\x42\x40\x00\x0f\x42\x40'    

def add_ebi_v2(instance,ebi):
    return b'\x49\x00\x01' + struct.pack("!B",instance) + bytes([ebi])

def add_bearer_qos_v2(instance, qci):
    return b'\x50\x00\x16' + struct.pack("!B",instance) + b'\x55' + struct.pack("!B",int(qci)) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def add_bearer_context_v2(instance, payload_bytes):
    return b'\x5d' + struct.pack("!H",len(payload_bytes)) + struct.pack("!B",instance) + payload_bytes

def add_timezone_v2():
    return b'\x72\x00\x02\x00\x8f\x02'    
    
    
### GTPv2 messages ###
def create_session_request(apn, gtp_address, imsi, msisdn, pdptype, ggsn, node, fixed_ipv4, fixed_ipv6, username, password, dhcp, cc, operator, rat, imei, authentication_type, qci, sel_mode):

    global sequence_number
     
    gtp_flags = b'\x48'
    gtp_message_type = b'\x20'
    gtp_length = b'\x00\x00'
    gtp_teid = b'\x00\x00\x00\x00'

    gtp_sequence_number = struct.pack("!B", sequence_number >> 16) + struct.pack("!H", sequence_number & 0xffff)
    gtp_spare = b'\x00'
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_spare

    gtp_imsi = add_imsi_v2(0,imsi)
    gtp_imei = add_imei_v2(0,imei)
    gtp_msisdn = add_msisdn_v2(0,msisdn)
    gtp_serving_network = add_serving_network_v2(0,operator)
    
    if node == "SGSN":
        if rat is None:
            gtp_user_location_info = add_user_location_info_v2(0,operator,1) 
            gtp_rat = add_rat_v2(0, 1)
        else:     
            gtp_user_location_info = add_user_location_info_v2(0,operator,int(rat)) 
            gtp_rat = add_rat_v2(0, int(rat))            
            
    elif node in ("EPDG", "TWAN"):
        if rat is None:    
            gtp_user_location_info = b'' 
            gtp_rat = add_rat_v2(0, 3)    
        else:
            gtp_user_location_info = b'' 
            gtp_rat = add_rat_v2(0, int(rat))         
    else:
        gtp_user_location_info = add_user_location_info_v2(0,operator,6) 
        if rat is not None:
            gtp_rat = add_rat_v2(0,int(rat))
        else:
            gtp_rat = add_rat_v2(0, 6)

    if pdptype == "ipv4v6":
        gtp_indication = add_indication_v2(0,128,0,0,0,0,0)
    else:    
        gtp_indication = add_indication_v2(0,0,0,0,0,0,0) 
        gtp_indication = b''        

    if node == "MME":
        gtp_teid_control = add_random_f_teid_v2(0,"s11_c_mme", gtp_address, 0) + add_random_f_teid_v2(1, "s5_c_pgw", ggsn, 0)
    elif node == "SGSN":
        gtp_teid_control = add_random_f_teid_v2(0,"s4_c_sgsn", gtp_address, 0) + add_random_f_teid_v2(1, "s5_c_pgw", ggsn, 0)   
    elif node == "SGW":
        gtp_teid_control = add_random_f_teid_v2(0,"s5_c_sgw", gtp_address, 0)
    elif node == "EPDG":
        gtp_teid_control = add_random_f_teid_v2(0,"s2b_c_epdg", gtp_address, 0)
    elif node == "TWAN":    
        gtp_teid_control = add_random_f_teid_v2(0,"s2a_c_twan", gtp_address, 0)
        
    gtp_apn = add_apn_v2(0,apn,operator)     
    gtp_selection_mode = add_selection_mode_v2(sel_mode)     
        
    if pdptype == "ipv4":
        gtp_pdn_type = add_pdn_type_v2(0,1)
        if fixed_ipv4 == None:
            gtp_pdn_address = add_pdn_address_v2(0,1,"0.0.0.0","::")
        else:
            gtp_pdn_address = add_pdn_address_v2(0,1,fixed_ipv4,"::")        
        gtp_pco = add_pco_v2("ipv4", username, password, dhcp, authentication_type, node)
        
    elif pdptype == "ipv6":
        gtp_pdn_type = add_pdn_type_v2(0,2)
        if fixed_ipv6 == None:
            gtp_pdn_address = add_pdn_address_v2(0,2,"0.0.0.0","::")
        else:
            gtp_pdn_address = add_pdn_address_v2(0,2,"0.0.0.0",fixed_ipv6)
        gtp_pco = add_pco_v2("ipv6", username, password, dhcp, authentication_type, node)
        
    elif pdptype == "ipv4v6":    
        gtp_pdn_type = add_pdn_type_v2(0,3)
        if fixed_ipv4 == None and fixed_ipv6 == None:
            gtp_pdn_address = add_pdn_address_v2(0,3,"0.0.0.0","::")
        elif fixed_ipv4 != None and fixed_ipv6 == None:
            gtp_pdn_address = add_pdn_address_v2(0,3,fixed_ipv4,"::")
        elif fixed_ipv4 == None and fixed_ipv6 != None:
            gtp_pdn_address = add_pdn_address_v2(0,3,"0.0.0.0",fixed_ipv6)
        else:
            gtp_pdn_address = add_pdn_address_v2(0,3,fixed_ipv4,fixed_ipv6)       
        gtp_pco = add_pco_v2("ipv4v6", username, password, dhcp, authentication_type, node)
    
    gtp_apn_restriction = add_apn_restriction_v2()    
    gtp_ambr = add_ambr_v2()    
        
    # ie from grouped gtp_bearer_context    
    gtp_bearer_id = add_ebi_v2(0,DEFAULT_NSAPI)
    if node == "SGSN":
        gtp_teid_data = add_random_f_teid_v2(1,"s4_u_sgsn", gtp_address, 0)
    elif node == "SGW":
        gtp_teid_data = add_random_f_teid_v2(2,"s5_u_sgw", gtp_address, 0)
    elif node == "EPDG":
        gtp_teid_data = add_random_f_teid_v2(5,"s2b_u_epdg", gtp_address, 0)
    elif node == "TWAN":
        gtp_teid_data = add_random_f_teid_v2(6,"s2a_u_twan", gtp_address, 0)        
    else:
        gtp_teid_data = b''
    gtp_bearer_qos = add_bearer_qos_v2(0, qci)    
        
    gtp_bearer_context = add_bearer_context_v2(0,gtp_bearer_id + gtp_teid_data + gtp_bearer_qos)    
    
    gtp_timezone = add_timezone_v2()    
    gtp_cc = b'\x5f\x00\x02\x00' + hex2bytes(cc)

    gtp_ie = gtp_imsi + gtp_imei + gtp_msisdn + gtp_serving_network + gtp_user_location_info + gtp_rat + gtp_indication + gtp_teid_control + gtp_apn + gtp_selection_mode + gtp_pdn_type + gtp_pdn_address + gtp_pco + gtp_apn_restriction + gtp_ambr + gtp_bearer_context + gtp_timezone + gtp_cc

    create_session_request_packet = bytearray(gtp_header + gtp_ie)

    length = len(create_session_request_packet) - 4
    
    create_session_request_packet[3] = length % 256
    create_session_request_packet[2] = length // 256
    
    sequence_number +=1

    return create_session_request_packet 


def modify_bearer_request(gtp_address, node): # only for mme or sgsn mode    
    
    global sequence_number, teid_local_control, teid_local_data, teid_remote_data, teid_remote_control
    
    gtp_flags = b'\x48'
    gtp_message_type = b'\x22'
    gtp_length = b'\x00\x00'
    gtp_teid = struct.pack("!L", teid_remote_control)

    gtp_sequence_number = struct.pack("!B", sequence_number >> 16) + struct.pack("!H", sequence_number & 0xffff)
    gtp_spare = b'\x00'
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_spare    

    
    gtp_bearer_id = add_ebi_v2(0,DEFAULT_NSAPI)
    if node == "SGSN":
        gtp_teid_data = add_random_f_teid_v2(3,"s4_u_sgsn", gtp_address, teid_local_data)
    elif node == "MME":
        gtp_teid_data = add_random_f_teid_v2(0,"s1_u_enb", gtp_address, 0)
      
    gtp_bearer_context = add_bearer_context_v2(0,gtp_bearer_id + gtp_teid_data)       

    modify_bearer_request_packet = bytearray(gtp_header + gtp_bearer_context)

    length = len(modify_bearer_request_packet) - 4
    
    modify_bearer_request_packet[3] = length % 256
    modify_bearer_request_packet[2] = length // 256
    
    sequence_number +=1

    return modify_bearer_request_packet     
    

def delete_session_request(gtp_address, node):

    global sequence_number, teid_local_control, teid_local_data, teid_remote_data, teid_remote_control
    
    gtp_flags = b'\x48'
    gtp_message_type = b'\x24'
    gtp_length = b'\x00\x00'
    gtp_teid = struct.pack("!L", teid_remote_control)

    gtp_sequence_number = struct.pack("!B", sequence_number >> 16) + struct.pack("!H", sequence_number & 0xffff)
    gtp_spare = b'\x00'
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_spare    

    gtp_bearer_id = add_ebi_v2(0,DEFAULT_NSAPI)
    
    if node == "SGSN" or node == "MME":
        gtp_indication = add_indication_v2(0,8,0,0,0,0,0)
    else:
        gtp_indication = b''

    if node == "MME":
        gtp_teid_control = add_random_f_teid_v2(0,"s11_c_mme", gtp_address, teid_local_control) 
    elif node == "SGSN":
        gtp_teid_control = add_random_f_teid_v2(0,"s4_c_sgsn", gtp_address, teid_local_control)    
    elif node == "SGW":
        gtp_teid_control = add_random_f_teid_v2(0,"s5_c_sgw", gtp_address, teid_local_control) 
    elif node == "EPDG":
        gtp_teid_control = add_random_f_teid_v2(0,"s2b_c_epdg", gtp_address, teid_local_control) 
    elif node == "TWAN":
        gtp_teid_control = add_random_f_teid_v2(0,"s2a_c_twan", gtp_address, teid_local_control)         

    delete_session_request_packet = bytearray(gtp_header + gtp_bearer_id + gtp_indication + gtp_teid_control)

    length = len(delete_session_request_packet) - 4
    
    delete_session_request_packet[3] = length % 256
    delete_session_request_packet[2] = length // 256
    
    sequence_number +=1

    return delete_session_request_packet 
        

def create_bearer_response(sequence_number):  # current version rejects dedicated bearer creation from pgw

    global teid_remote_control

    gtp_flags = b'\x48'
    gtp_message_type = b'\x60'
    gtp_length = b'\x00\x00'
    gtp_teid = struct.pack("!L", teid_remote_control)

    gtp_sequence_number = sequence_number
    gtp_spare = b'\x00'
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_spare  

    gtp_cause = b'\x02\x00\x02\x00\x72\x01'
    gtp_bearer_id = add_ebi_v2(0,DEFAULT_NSAPI+1)
    
    gtp_bearer_context = add_bearer_context_v2(0,gtp_bearer_id + gtp_cause) 
    
    create_bearer_response_packet = bytearray(gtp_header + gtp_cause + gtp_bearer_context)
    
    length = len(create_bearer_response_packet) - 4
    
    create_bearer_response_packet[3] = length % 256
    create_bearer_response_packet[2] = length // 256
    
    return create_bearer_response_packet 
    

def update_bearer_response(sequence_number):

    global teid_remote_control

    gtp_flags = b'\x48'
    gtp_message_type = b'\x62'
    gtp_length = b'\x00\x00'
    gtp_teid = struct.pack("!L", teid_remote_control)

    gtp_sequence_number = sequence_number
    gtp_spare = b'\x00'
    gtp_header = gtp_flags + gtp_message_type + gtp_length + gtp_teid + gtp_sequence_number + gtp_spare  

    gtp_cause = b'\x02\x00\x02\x00\x10\x00'
    gtp_bearer_id = add_ebi_v2(0,DEFAULT_NSAPI)
    
    gtp_bearer_context = add_bearer_context_v2(0,gtp_bearer_id + gtp_cause) 
    
    update_bearer_response_packet = bytearray(gtp_header + gtp_cause + gtp_bearer_context)
    
    length = len(update_bearer_response_packet) - 4
    
    update_bearer_response_packet[3] = length % 256
    update_bearer_response_packet[2] = length // 256
    
    return update_bearer_response_packet     

    
####### Endof GTPv2 ########

##########################################################################################################################################################

def signal_handler(signum, frame):
    raise Exception("Timed out!")

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))), fields[0]

def get_default_gateway_darwin():
    proc = subprocess.Popen("route -n get default | grep gateway", stdout=subprocess.PIPE, shell=True)
    gateway_address = str(proc.stdout.read()).split('gateway: ')[1].split('\\')[0]
    proc = subprocess.Popen("route -n get default | grep interface", stdout=subprocess.PIPE, shell=True)
    gateway_interface = str(proc.stdout.read()).split('interface: ')[1].split('\\')[0]
    return gateway_address, gateway_interface    

def get_default_source_address():  
    proc = subprocess.Popen("/sbin/ifconfig | grep -A 1 " + get_default_gateway_linux()[1] + " | grep inet", stdout=subprocess.PIPE, shell=True)
    res = str(proc.stdout.read())
    try:
        addr = res.split('addr:')[1].split()[0]
    except:
        addr = res.split('inet ')[1].split()[0]   
    return addr

def get_default_source_address_darwin():
    proc = subprocess.Popen("/sbin/ifconfig | grep -A 5 " + get_default_gateway_darwin()[1] + " | grep 'inet '", stdout=subprocess.PIPE, shell=True)
    addr = str(proc.stdout.read()).split('inet ')[1].split()[0]
    return addr

def generic_cli(cli):
    proc = subprocess.Popen(cli, stdout=subprocess.PIPE, shell=True)
    output = str(proc.stdout.read())
    return output

def delete_routes(netns, addresses, gtp_kernel, teid_local_data, end_user_address):
    # delete previous added routes, and replaces dns resolv.conf file with the previous one (backup)
    for address in addresses:
        if sys.platform == "linux" or sys.platform == "linux2":
            subprocess.call("route del " + address + "/32", shell=True)

    if (dns_addresses != None or dns_addresses_ipv6 != None) and not netns:
        print ("12. Replacing /etc/resolv.conf with the backup file.\n")
        subprocess.call("cp /etc/resolv.backup.conf /etc/resolv.conf", shell=True)  
    
    if gtp_kernel == True:
        subprocess.call("ip addr del " + end_user_address + "/32 dev lo", shell=True)
        subprocess.call("killall gtp-tunnel", shell=True)
        subprocess.call("killall gtp-link", shell=True)
    if netns is not None:
        subprocess.call("ip netns del " + netns, shell=True)  
    if gtp_kernel == True:
        subprocess.call("gtp-tunnel delete gtp1 v1 " + str(teid_local_data), shell=True)
        subprocess.call("gtp-link del gtp1", shell=True)
        subprocess.call("modprobe -r gtp", shell=True)        


def pco_dns(pco):
    dns_result = []
    # fast method to search for DNS without decoding PCO IE
    if len(pco) > 12:
        for i in range(len(pco)-12):
            if pco[i] == 129 and pco[i+1] == 6 and pco[i+6] == 131 and pco[i+7] == 6:
                dns_primary = socket.inet_ntoa(bytes(pco[i+2:i+6]))
                dns_secondary = socket.inet_ntoa(bytes(pco[i+8:i+12]))
                dns_result.append(dns_primary)
                dns_result.append(dns_secondary)
                return dns_result
            elif pco[i] == 129 and pco[i+1] == 6:
                dns_primary = socket.inet_ntoa(bytes(pco[i+2:i+6]))
                dns_result.append(dns_primary)
                return dns_result

    else:
        return None   

def pco_dns_ipv6(pco):
    dns_result = []
    # fast method to search for DNS without decoding PCO IE
    if len(pco) > 12:
        for i in range(len(pco)-19+1):
            if pco[i] == 0 and pco[i+1] == 3 and pco[i+2] == 16:
                dns = socket.inet_ntop(socket.AF_INET6, bytes(pco[i+3:i+19]))
                dns_result.append(dns)
        if dns_result == []:
            return None
        else:
            return dns_result
    else:
        return None   


def pco_pcscf(pco):
    pcscf_result = []
    # fast method to search for PCSCF without decoding PCO IE
    if len(pco) > 6:
        for i in range(len(pco)-6):
            if pco[i] == 0 and pco[i+1] == 12 and pco[i+2] == 4:
                pcscf = socket.inet_ntoa(bytes(pco[i+3:i+7]))
                pcscf_result.append(pcscf)
        if pcscf_result == []:
            return None
        else:
            return pcscf_result
    else:
        return None   

def pco_pcscf_ipv6(pco):
    pcscf_result = []
    # fast method to search for P-CSCF IPv6 without decoding PCO IE
    if len(pco) > 18:
        for i in range(len(pco)-18):
            if pco[i] == 0 and pco[i+1] == 1 and pco[i+2] == 16:
                pcscf = socket.inet_ntop(socket.AF_INET6, bytes(pco[i+3:i+19]))
                pcscf_result.append(pcscf)
        if pcscf_result == []:
            return None
        else:
            return pcscf_result
    else:
        return None



#######################################################################        
	
def encapsulate_gtp_u(args):  
    
    global s_gtpu

    tap_fd = args[0]
    gre_dst_ip = args[1]
    teid = args[2]

    while True:
        tap_packet = os.read(tap_fd, 1514)
        s_gtpu.sendto(gtp_u_header(teid, len(tap_packet)) + tap_packet, (gre_dst_ip, GTP_U_REMOTE_PORT))

    return 0


def decapsulate_gtp_u(args):
    
    global s_gtpu

    tap_fd = args[0]
    gtp_src_ip = args[1]
    teid = args[2]

    while True:
        gtp_packet, gtp_address = s_gtpu.recvfrom(2000)
        # check packet source
        if gtp_address[0] == gtp_src_ip:
            #is G-PDU? has the correct TEID?
            if gtp_packet[0:2] == b'\x30\xff' and gtp_packet[4:8] == struct.pack("!L", teid):
                os.write(tap_fd,gtp_packet[8:])
            elif gtp_packet[1:2] == b'\xff' and gtp_packet[4:8] == struct.pack("!L", teid):
                os.write(tap_fd,gtp_packet[12:])
            # is echo request?
            elif gtp_packet[1:2] == b'\x01':
                gtp_echo_response = bytearray(gtp_packet) + b'\x0e\x00'
                gtp_echo_response[1] = 2
                gtp_echo_response[3] += 2
                s_gtpu.sendto(gtp_echo_response, gtp_address)

    return 0

def exec_in_netns(netns_name, cmd, shell=True):
    if netns_name:
        cmd = "ip netns exec %s %s" % (netns_name, cmd)
    print("cmd: %s" % cmd)
    subprocess.call(cmd, shell=shell)

def add_dir(netns_name):
    if not os.path.isdir('/etc/netns'):        
        os.mkdir('/etc/netns')
    if not os.path.isdir('/etc/netns/' + netns_name):   
        os.mkdir('/etc/netns/'  + netns_name)


########################################################## M A I N ##########################################################

def main():

    global options

    global s_gtpc, s_gtpu, sequence_number, teid_local_control, teid_local_data, ie_size, dns_addresses, dns_addresses_ipv6, request_sequence_number, teid_remote_data, teid_remote_control
  
    parser = OptionParser()
    parser.add_option("-t", "--tunnel_type", dest="tunnel_type", default="GTP", help="tunnel Type: GTP (Default), GTPv2")
    parser.add_option("-d", "--tunnel_dst_ip", dest="tunnel_dst_ip", help="tunnel IP GTP endpoint")
    parser.add_option("-i", "--dev_id", dest="dev_id", default=10, help="tun/tap device index")
    parser.add_option("-a", "--apn_name", dest="apn_name", default=DEFAULT_APN, help="APN name")
    parser.add_option("-I", "--imsi", dest="imsi", default=DEFAULT_IMSI, help="IMSI")
    parser.add_option("-M", "--msisdn", dest="msisdn", default=DEFAULT_MSISDN, help="MSISDN")
    parser.add_option("-p", "--pdptype", dest="pdptype", default="ipv4", help="PDP type (ipv4, ipv6 or ipv4v6)")
    parser.add_option("-s", "--gtp_source_address", dest="gtp_address", help="GTP source address (for GTP-C and GTP-U)") 
    parser.add_option("-S", "--ip_source_address", dest="ip_source_address", help="IP source address. If not specified, the bind is done for all IPs")     
    parser.add_option("-g", "--gateway_ip_address", dest="gateway_ip_address", help="gateway IP address")
    parser.add_option("-n", "--nodetype", dest="nodetype", default="SGSN", help="Node type (SGSN, MME, SGW, EPDG or TWAN)")
    parser.add_option("-E", "--imei", dest="imei", default=DEFAULT_IMEI, help="IMEI")
    parser.add_option("-f", "--fixed_ipv4", dest="fixed_ipv4", help="Static IPv4 for session")
    parser.add_option("-F", "--fixed_ipv6", dest="fixed_ipv6", help="Static IPv6 for session")    
    parser.add_option("-U", "--username", dest="username", help="username (for gtp proxy access)")
    parser.add_option("-P", "--password", dest="password", help="password (for gtp proxy access)")
    parser.add_option("-G", "--ggsn", dest="ggsn", help="ggsn/pgw ip address (for gtp proxy access or when set to SGSN/MME node in GTPv2)")    
    parser.add_option("-H", "--hash", dest="password_to_hash", help="password hash calculation (for gtp proxy access)")
    parser.add_option("-v", "--version", action="store_true", dest="version", default=False, help="version")
    parser.add_option("-u", "--username_pco", dest="username_pco", help="username (for APN)")
    parser.add_option("-w", "--password_pco", dest="password_pco", help="password (for APN)")
    parser.add_option("-A", "--authentication_type", dest="authentication_type", default="PAP", help="authentication type: PAP (default), CHAP")
    parser.add_option("-T", "--timeout", dest="timeout", default="2", help="timeout for session establishment")    
    parser.add_option("-D", "--dhcp", action="store_true", dest="dhcp", default=False, help="Deferred IP allocation using DHCP (ipv4)")
    parser.add_option("-C", "--cc", dest="cc", default="0800", help="Charging Characteristics")
    parser.add_option("-O", "--operator", dest="operator", default=DEFAULT_OPERATOR, help="Operator MCCMNC for ULI")
    parser.add_option("-R", "--rat", dest="rat", help="Radio Access Type")
    parser.add_option("-Q", "--quit", action="store_true", dest="quit", default=False, help="Quit immediately after activating session")  
    parser.add_option("-N", "--netns", dest="netns", help="Name of network namespace for tun device")
    parser.add_option("-Z", "--gtp-kernel", action="store_true", dest="gtp_kernel", help="Use GTP Kernel. Needs libgtpnl", default=False)
    parser.add_option("-X", "--no-default", action="store_true", dest="no_default", help="Does not install default route", default=False)
    parser.add_option("-q", "--qci", dest="qci", default="8", help="QCI") 
    parser.add_option("--selmode", dest="sel_mode", default="0", help="Selection Mode (0, 1 oe 2)") 

    (options, args) = parser.parse_args()

    if options.version == True:
        print("GTP Dialer: Version 3.0 by Fabricio Ferraz (fasferraz@gmail.com) 2022")
        exit(1)  
    if options.password_to_hash is not None:
        m = hashlib.md5()
        m.update((options.password_to_hash + HASH_PASS).encode())
        print('\n' + bytes2hex(m.digest()) + '\n')
        exit(1)
        
    if options.gtp_address is None:
        if sys.platform == "linux" or sys.platform == "linux2":
            options.gtp_address = get_default_source_address()

    if options.gateway_ip_address is None:
        if sys.platform == "linux" or sys.platform == "linux2":
            options.gateway_ip_address = get_default_gateway_linux()[0]

    if options.tunnel_type == "GTP" or options.tunnel_type == "GTPv2":
        if sys.platform != "linux" and sys.platform != "linux2":
            print("Operating system not supported. Exiting.\n")
            exit(1)
        if options.tunnel_dst_ip is None:
            print("A Tunnel IP endpoint is required!\n")
            exit(1)
        if options.apn_name is None:
            print("An APN name is required!\n")
            exit(1)        
        if options.gtp_address is None:
            print("A GTP source address is required!\n")
            exit(1)
        if options.pdptype not in ("ipv4", "ipv6", "ipv4v6"):
            print ("Unknown PDP Type!\n")
            exit(1)
        if options.nodetype not in ("SGSN", "MME", "SGW", "EPDG", "TWAN"):
            print ("Unknown Node Type!\n")
            exit(1)       
        if options.tunnel_type == "GTP" and (options.nodetype in ("MME", "SGW", "EPDG", "TWAN")):
            print ("Node type not compatible with GTP version")
            exit(1)            
        if options.tunnel_type == "GTP" and (options.fixed_ipv4 != None or options.fixed_ipv6 != None):
            print ("Static IP functionality is not implemented for GTP")
            exit(1)  
        if len(options.operator) < 5 or len(options.operator) > 6:
            print ("MCC-MNC should be 5 or 6 hex digits long")
            exit(1)           
        if len(options.cc) != 4:
            print ("CC should be 4 hex digits long")
            exit(1)         

        teid_remote_data = 0
        teid_local_data = 0
        teid_remote_control = 0
        sequence_number = 0
        remote_destinations = []
        remote_destinations.append(options.tunnel_dst_ip)

        print (bcolors.BOLD)
        print (bcolors.YELLOW + "   _____ _______ _____    _____  _       _           ")
        print (bcolors.YELLOW + "  / ____|__   __|  __ \  |  __ \(_)     | |          ")
        print (bcolors.YELLOW + " | |  __   | |  | |__) | | |  | |_  __ _| | ___ _ __ ")
        print (bcolors.GREEN  + " | | |_ |  | |  |  ___/  | |  | | |/ _` | |/ _ \ '__|")
        print (bcolors.GREEN  + " | |__| |  | |  | |      | |__| | | (_| | |  __/ |   ")
        print (bcolors.BLUE   + "  \_____|  |_|  |_|      |_____/|_|\__,_|_|\___|_|   by fasferraz@gmail (2012-2022)")
        print (bcolors.ENDC)        
 
        print (" 1. Adding route to GGSN IP Address pointing to the current default gateway")
        # Add route for destination Node ip address pointing to the default gateway
        if sys.platform == "linux" or sys.platform == "linux2":
            subprocess.call("route add " + options.tunnel_dst_ip + "/32 gw " + options.gateway_ip_address, shell=True)

        ######################################################################
        ##########################  Control  Plane  ##########################
        ###################################################################### 

        print (" 2. Creating GTP-C Socket")
        # GTP_C Socket
        s_gtpc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind socket to local host and port
        try:
            if options.ip_source_address is None:
                s_gtpc.bind((GTP_LOCAL_HOST, GTP_C_LOCAL_PORT))
            else:
                s_gtpc.bind((options.ip_source_address, GTP_C_LOCAL_PORT))    
                
        except socket.error as msg:
            print (' 3. Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1] + '\n')
            print (" 4. Deleting route to GGSN IP created in step 1. Exiting\n")
            if sys.platform == "linux" or sys.platform == "linux2":
                subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)    
            exit(1)

        ### GTPv1 tree ###
        ### GTPv1 tree ###
        ### GTPv1 tree ###
        if options.tunnel_type == "GTP":

            print (" 3. Sending Create PDP Context to GGSN")
            # Create session 
            s_gtpc.sendto(cpc_request(options.apn_name, options.gtp_address, options.imsi, options.msisdn, options.pdptype, options.username, options.password, options.ggsn, options.username_pco, options.password_pco, options.dhcp, options.cc, options.operator, options.imei, options.authentication_type, options.rat, options.sel_mode), (options.tunnel_dst_ip, GTP_C_REMOTE_PORT))	

            # alarm triggering for timeout, in case there is no answer from GGSN
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(int(options.timeout)) 
            try:
                gtp_packet, gtp_address = s_gtpc.recvfrom(2000)	
                signal.alarm(0)

            except Exception as msg:
                print (' 4. No answer from GGSN. Exiting. Message: ' + str(msg) + '\n')
                if sys.platform == "linux" or  sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                exit(1)  
        
            if gtp_address[0] != options.tunnel_dst_ip:
                print (" 4. Answer received but not from the GGSN. Deleting route to GGSN created in step 1. Exiting\n")
                if sys.platform == "linux" or  sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)

                exit(1)

            if gtp_packet[1:2] == b'\x01':
                gtp_echo_response = bytearray(gtp_packet) + b'\x0e\x00'
                gtp_echo_response[1] = 2
                gtp_echo_response[3] += 2
                s_gtpc.sendto(gtp_echo_response, gtp_address)

                # alarm triggering for timeout, in case there is no answer from GGSN
                signal.signal(signal.SIGALRM, signal_handler)
                signal.alarm(int(options.timeout)) 
                try:
                    gtp_packet, gtp_address = s_gtpc.recvfrom(2000)	
                    signal.alarm(0)
    
                except Exception as msg:
                    print (' 4. No answer from GGSN. Exiting. Message: ' + str(msg) + '\n')
                    if sys.platform == "linux" or  sys.platform == "linux2":
                        subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                    exit(1)

        
            # gtpc decoding
            cpc_response = decode_gtpc(bytearray(gtp_packet))
            if cpc_response == None or cpc_response == 240 or cpc_response == 239:
                if cpc_response == None:
                    print (" 4. Answer received but decode failed. Deleting route to GGSN created in step 1. Exiting")
                elif cpc_response == 240:
                    print (" 4. Answer received. Authentication needed. Please use -U and -P options to provide username and password. Deleting route to GGSN created in step 1.   Exiting")
                elif cpc_response == 239:
                    print (" 4. Answer received. Authentication failed: Wrong username or password. Deleting route to GGSN created in step 1. Exiting")
                if sys.platform == "linux" or sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                exit(1)
        
            print (" 4. Answer received and GTP decoded.")
            tunnel_dst_ip_gtpu = ip2str(cpc_response[1133])
            print ('    => GGSN GTP-U IP Adresss: ' + str(tunnel_dst_ip_gtpu))

            if tunnel_dst_ip_gtpu not in remote_destinations:
                remote_destinations.append(tunnel_dst_ip_gtpu)

            tunnel_dst_ip_gtpc = ip2str(cpc_response[133])
            print ('    => GGSN GTP-C IP Adresss: ' + str(tunnel_dst_ip_gtpc))
    
            if tunnel_dst_ip_gtpc not in remote_destinations:
                remote_destinations.append(tunnel_dst_ip_gtpc)
    
            end_user_address = ""
            end_user_address_ipv6 = ""        
            ipv6_identifier_aux = []
            ipv6_prefix_aux = []
            if len(cpc_response[128]) == 6:
                end_user_address = ip2str(cpc_response[128][2:])
            elif len(cpc_response[128]) == 18:
                end_user_address_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes(cpc_response[128][2:]))
                ipv6_identifier_aux = cpc_response[128][2:]
                ipv6_prefix_aux = cpc_response[128][2:]
            elif len(cpc_response[128]) == 22:
                end_user_address = ip2str(cpc_response[128][2:6])
                end_user_address_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes(cpc_response[128][6:]))
                ipv6_identifier_aux = cpc_response[128][6:]
                ipv6_prefix_aux = cpc_response[128][6:]

            if end_user_address != "":
                print ('    => End-User IPv4 Adresss: ' + str(end_user_address))
            if end_user_address_ipv6 != "":
                for x in range(0, 8):
                    ipv6_prefix_aux[x+8] = 0
                    ipv6_identifier_aux[x] = 0
                ipv6_identifier_aux[0] = 254
                ipv6_identifier_aux[1] = 128
                ipv6_prefix = socket.inet_ntop(socket.AF_INET6, bytes(ipv6_prefix_aux))
                ipv6_identifier = socket.inet_ntop(socket.AF_INET6, bytes(ipv6_identifier_aux))
                print ('    => End-User IPv6 Address: ' + str(end_user_address_ipv6))
                print ('    => End-User IPv6 Address (Prefix): ' + str(ipv6_prefix))
                print ('    => End-User IPv6 Address (Identifier): ' + str(ipv6_identifier))

            teid_remote_data = struct.unpack("!L", cpc_response[16])[0]
            print ('    => TEID Data Remote: ' + str(teid_remote_data))   
            teid_remote_control = struct.unpack("!L", cpc_response[17])[0]
            print ('    => TEID Control Remote: ' + str(teid_remote_control))
            dns_addresses = pco_dns(cpc_response[132])
            print ('    => DNS Addresses IPv4: ' + str(dns_addresses))
            dns_addresses_ipv6 = pco_dns_ipv6(cpc_response[132])
            print ('    => DNS Addresses IPv6: ' + str(dns_addresses_ipv6))
            pcscf_addresses = pco_pcscf(cpc_response[132])
            print ('    => P-CSCF Addresses IPv4: ' + str(pcscf_addresses))
            pcscf_addresses_ipv6 = pco_pcscf_ipv6(cpc_response[132])
            print ('    => P-CSCF Addresses IPv6: ' + str(pcscf_addresses_ipv6))
            if end_user_address == "" and end_user_address_ipv6 == "":
                print (" 5. No End-User Address Received. Exiting.\n")
                exit(1)

        ### GTPv2 tree ###
        ### GTPv2 tree ###
        ### GTPv2 tree ###
        elif options.tunnel_type == "GTPv2":           
           
            print (" 3. Sending Create Session Request to SGW/PGW")
            # Create session  
            s_gtpc.sendto(create_session_request(options.apn_name, options.gtp_address, options.imsi, options.msisdn, options.pdptype, options.ggsn, options.nodetype, options.fixed_ipv4, options.fixed_ipv6, options.username_pco, options.password_pco, options.dhcp, options.cc, options.operator, options.rat, options.imei, options.authentication_type, options.qci, options.sel_mode), (options.tunnel_dst_ip, GTP_C_REMOTE_PORT))	

            # alarm triggering for timeout, in case there is no answer from SGW or PGW
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(int(options.timeout))   # 2 seconds
            try:
                gtp_packet, gtp_address = s_gtpc.recvfrom(2000)	
                signal.alarm(0)

            except Exception as msg:
                print (' 4. No answer from SGW/PGW. Exiting. Message: ' + str(msg) + '\n')
                if sys.platform == "linux" or  sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                exit(1)  
        
            if gtp_address[0] != options.tunnel_dst_ip:
                print (" 4. Answer received but not from the SGW/PGW. Deleting route to SGW/PGW created in step 1. Exiting\n")
                if sys.platform == "linux" or  sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                exit(1)
        
            if gtp_packet[1:2] == b'\x01':
                gtp_echo_response = bytearray(gtp_packet)
                gtp_echo_response[1] = 2
                s_gtpc.sendto(gtp_echo_response, gtp_address)
                
                # alarm triggering for timeout, in case there is no answer from GGSN
                signal.signal(signal.SIGALRM, signal_handler)
                signal.alarm(int(options.timeout)) 
                try:
                    gtp_packet, gtp_address = s_gtpc.recvfrom(2000)	
                    signal.alarm(0)
    
                except Exception as msg:
                    print (' 4. No answer from GGSN. Exiting. Message: ' + str(msg) + '\n')
                    if sys.platform == "linux" or  sys.platform == "linux2":
                        subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                    exit(1)


            # gtpc v2 decoding             
            create_session_response = decode_gtpc_v2(bytearray(gtp_packet))
            if create_session_response == None or create_session_response == -1:
                if create_session_response == None:
                    print (" 4. Answer received but decode failed. Deleting route to SGW/PGW created in step 1. Exiting")
                elif create_session_response == -1:
                    print (" 4. Answer received. Request not Accepted.   Exiting")

                if sys.platform == "linux" or sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                exit(1)
        
            print (" 4. Answer received and GTPv2 decoded.")

            bearer_context_decode = decode_ie_v2(create_session_response[(93,0)]) 
            if options.nodetype == "SGW":            
                tunnel_dst_ip_gtpu = ip2str(bearer_context_decode[(87,2)][5:9])
                print ('    => PGW GTP-U IP Adresss: ' + str(tunnel_dst_ip_gtpu))
                if tunnel_dst_ip_gtpu not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpu)
                tunnel_dst_ip_gtpc = ip2str(create_session_response[(87,1)][5:9])
                print ('    => PGW GTP-C IP Adresss: ' + str(tunnel_dst_ip_gtpc))
                if tunnel_dst_ip_gtpc not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpc)                   
            elif options.nodetype == "EPDG":            
                tunnel_dst_ip_gtpu = ip2str(bearer_context_decode[(87,4)][5:9])
                print ('    => PGW GTP-U IP Adresss: ' + str(tunnel_dst_ip_gtpu))
                if tunnel_dst_ip_gtpu not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpu)
                tunnel_dst_ip_gtpc = ip2str(create_session_response[(87,1)][5:9])
                print ('    => PGW GTP-C IP Adresss: ' + str(tunnel_dst_ip_gtpc))
                if tunnel_dst_ip_gtpc not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpc)
            elif options.nodetype == "TWAN":            
                tunnel_dst_ip_gtpu = ip2str(bearer_context_decode[(87,5)][5:9])
                print ('    => PGW GTP-U IP Adresss: ' + str(tunnel_dst_ip_gtpu))
                if tunnel_dst_ip_gtpu not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpu)
                tunnel_dst_ip_gtpc = ip2str(create_session_response[(87,1)][5:9])
                print ('    => PGW GTP-C IP Adresss: ' + str(tunnel_dst_ip_gtpc))
                if tunnel_dst_ip_gtpc not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpc)
            else:
                if options.nodetype == "SGSN":
                    tunnel_dst_ip_gtpu = ip2str(bearer_context_decode[(87,1)][5:9])
                elif options.nodetype == "MME":
                    tunnel_dst_ip_gtpu = ip2str(bearer_context_decode[(87,0)][5:9])
                print ('    => SGW GTP-U IP Adresss: ' + str(tunnel_dst_ip_gtpu))
                if tunnel_dst_ip_gtpu not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpu)
                tunnel_dst_ip_gtpc = ip2str(create_session_response[(87,0)][5:9])
                print ('    => SGW GTP-C IP Adresss: ' + str(tunnel_dst_ip_gtpc))     
                if tunnel_dst_ip_gtpc not in remote_destinations:
                    remote_destinations.append(tunnel_dst_ip_gtpc)

                
            end_user_address = ""
            end_user_address_ipv6 = ""
            ipv6_identifier_aux = []
            ipv6_prefix_aux = []
            if len(create_session_response[(79,0)]) == 5:
                end_user_address = ip2str(create_session_response[(79,0)][1:])
            elif len(create_session_response[(79,0)]) == 18:
                end_user_address_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes(create_session_response[(79,0)][2:]))
                ipv6_identifier_aux = create_session_response[(79,0)][2:]
                ipv6_prefix_aux = create_session_response[(79,0)][2:]
            elif len(create_session_response[(79,0)]) == 22:
                end_user_address = ip2str(create_session_response[(79,0)][18:])
                end_user_address_ipv6 = socket.inet_ntop(socket.AF_INET6, bytes(create_session_response[(79,0)][2:18]))
                ipv6_identifier_aux = create_session_response[(79,0)][2:18]
                ipv6_prefix_aux = create_session_response[(79,0)][2:18]

            if end_user_address != "":
                print ('    => End-User IPv4 Adresss: ' + str(end_user_address))
            if end_user_address_ipv6 != "":
                for x in range(0, 8):
                    ipv6_prefix_aux[x+8] = 0
                    ipv6_identifier_aux[x] = 0
                ipv6_identifier_aux[0] = 254
                ipv6_identifier_aux[1] = 128
                ipv6_prefix = socket.inet_ntop(socket.AF_INET6, bytes(ipv6_prefix_aux))
                ipv6_identifier = socket.inet_ntop(socket.AF_INET6, bytes(ipv6_identifier_aux))

                print ('    => End-User IPv6 Address: ' + str(end_user_address_ipv6))
                print ('    => End-User IPv6 Address (Prefix): ' + str(ipv6_prefix))
                print ('    => End-User IPv6 Address (Identifier): ' + str(ipv6_identifier))

            if options.nodetype == "SGW":
                teid_remote_data = struct.unpack("!L", bearer_context_decode[(87,2)][1:5])[0]
            elif options.nodetype == "SGSN":
                teid_remote_data = struct.unpack("!L", bearer_context_decode[(87,1)][1:5])[0]    
            elif options.nodetype == "MME":
                teid_remote_data = struct.unpack("!L", bearer_context_decode[(87,0)][1:5])[0]
            elif options.nodetype == "EPDG":
                teid_remote_data = struct.unpack("!L", bearer_context_decode[(87,4)][1:5])[0]
            elif options.nodetype == "TWAN":
                teid_remote_data = struct.unpack("!L", bearer_context_decode[(87,5)][1:5])[0]                
            print ('    => TEID Data Remote: ' + str(teid_remote_data))
    
            if options.nodetype in ("SGW", "EPDG", "TWAN"):
                teid_remote_control = struct.unpack("!L", create_session_response[(87,1)][1:5])[0]                
            else:
                teid_remote_control = struct.unpack("!L", create_session_response[(87,0)][1:5])[0]                
            print ('    => TEID Control Remote: ' + str(teid_remote_control))
            if options.nodetype in ("SGSN", "MME", "SGW"):
                dns_addresses = pco_dns(create_session_response[(78,0)])
                print ('    => DNS Addresses IPv4: ' + str(dns_addresses))
                dns_addresses_ipv6 = pco_dns_ipv6(create_session_response[(78,0)])
                print ('    => DNS Addresses IPv6: ' + str(dns_addresses_ipv6))
                pcscf_addresses = pco_pcscf(create_session_response[(78,0)])
                print ('    => P-CSCF Addresses IPv4: ' + str(pcscf_addresses))
                pcscf_addresses_ipv6 = pco_pcscf_ipv6(create_session_response[(78,0)])
                print ('    => P-CSCF Addresses IPv6: ' + str(pcscf_addresses_ipv6))
            else:
                dns_addresses = pco_dns(create_session_response[(163,0)])
                print ('    => DNS Addresses IPv4: ' + str(dns_addresses))
                dns_addresses_ipv6 = pco_dns_ipv6(create_session_response[(163,0)])
                print ('    => DNS Addresses IPv6: ' + str(dns_addresses_ipv6))
                pcscf_addresses = pco_pcscf(create_session_response[(163,0)])
                print ('    => P-CSCF Addresses IPv4: ' + str(pcscf_addresses))
                pcscf_addresses_ipv6 = pco_pcscf_ipv6(create_session_response[(163,0)])
                print ('    => P-CSCF Addresses IPv6: ' + str(pcscf_addresses_ipv6))               
                
            if end_user_address == "" and end_user_address_ipv6 == "":
                print (" 5. No End-User Address Received. Exiting.\n")
                exit(1)

            ### MODIFY BEARER REQUEST for MME ###
            if options.nodetype == "MME":
                print (" 4.1. Sending Modify Bearer Request to SGW")
                s_gtpc.sendto(modify_bearer_request(options.gtp_address, options.nodetype), (tunnel_dst_ip_gtpc, GTP_C_REMOTE_PORT))	

                # alarm triggering for timeout, in case there is no answer from SGW
                signal.signal(signal.SIGALRM, signal_handler)
                signal.alarm(int(options.timeout))
                try:
                    gtp_packet, gtp_address = s_gtpc.recvfrom(2000)	
                    signal.alarm(0)

                except Exception as msg:
                    print (' 4.2. No answer from SGW. Exiting. Message: ' + str(msg) + '\n')
                    if sys.platform == "linux" or  sys.platform == "linux2":
                        subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                    exit(1)  
        
                if gtp_address[0] != options.tunnel_dst_ip:
                    print (" 4.2. Answer received but not from the SGW. Deleting route to SGW created in step 1. Exiting\n")
                    if sys.platform == "linux" or  sys.platform == "linux2":
                        subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                    exit(1)
        
                #decodes gtpc
                modify_bearer_response = decode_gtpc_v2(bytearray(gtp_packet))
                if modify_bearer_response == None or modify_bearer_response == -1:
                    if modify_bearer_response == None:
                        print (" 4.2. Answer received but decode failed. Deleting route to SGW/PGW created in step 1. Exiting")
                    elif modify_bearer_response == -1:
                        print (" 4.2. Answer received. Request not Accepted.   Exiting")

                    if sys.platform == "linux" or sys.platform == "linux2":
                        subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)

                    exit(1)

        ### QUIT OPTION ###        
        if options.quit == True:
            if options.tunnel_type == "GTP":
                # sends DeletePDPContext
                print ("\n11. Exiting. Deleting PDP Context. Removing routes previously created.")
                s_gtpc.sendto(dpc_request(teid_remote_control), (tunnel_dst_ip_gtpc, GTP_C_REMOTE_PORT))
                
            elif options.tunnel_type == "GTPv2":
                # sends DeleteSessionRequest
                print ("\n11. Exiting. Deleting PDN Session. Removing routes previously created.")
                s_gtpc.sendto(delete_session_request(options.gtp_address, options.nodetype), (tunnel_dst_ip_gtpc, GTP_C_REMOTE_PORT))
                
            delete_routes(options.netns, remote_destinations, options.gtp_kernel, teid_local_data, end_user_address)   
            exit(1)         
                
        ######################################################################
        ###########################  User   Plane  ###########################
        ######################################################################       

        if options.gtp_kernel == False:
            # if control plane is ok, then start GTP-U Socket
            print (" 5. Creating GTP-U Socket")
            s_gtpu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
            # Bind socket to local host and port
            try:
                if options.ip_source_address is None:
                    s_gtpu.bind((GTP_LOCAL_HOST, GTP_U_LOCAL_PORT))
                else:
                    s_gtpu.bind((options.ip_source_address, GTP_U_LOCAL_PORT))            
            except socket.error as msg:
                print (' 6. Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
                print (" 7. Deleting route to SGW/PGW/GGSN IP created in step 1. Exiting")
                if sys.platform == "linux" or sys.platform == "linux2":
                    subprocess.call("route del " + options.tunnel_dst_ip + "/32", shell=True)
                exit(1)
    
            # Creates tunnel interface	
            print (" 6. Creating Tunnel Interface")
            dev = open_tun(options.dev_id)
    
        if dns_addresses != None or dns_addresses_ipv6 != None:
            print (" 7. DNS: Backing up current /etc/resolv.conf. Creating a new one:")
            if options.netns:
                # create directory for namespace if it doesn't exist
                add_dir(options.netns) 
                
                with open("/etc/netns/%s/resolv.conf" % options.netns, "w") as file_obj:
                    if dns_addresses != None:
                        for i in dns_addresses:
                            print ('    => Adding DNS IPv4 ' + str(i))
                            file_obj.write("nameserver %s\n" % i)
                    if dns_addresses_ipv6 != None:        
                        for i in dns_addresses_ipv6:
                            print ('    => Adding DNS IPv6 ' + str(i))
                            file_obj.write("nameserver %s\n" % i)
            else:
                subprocess.call("cp /etc/resolv.conf /etc/resolv.backup.conf", shell=True)  
                subprocess.call("echo > /etc/resolv.conf", shell=True) 
                if dns_addresses != None:
                    for i in dns_addresses:
                        print ('    => Adding DNS IPv4 ' + str(i))
                        subprocess.call("echo 'nameserver " + i +"' >> /etc/resolv.conf", shell=True) 
                if dns_addresses_ipv6 != None:          
                    for i in dns_addresses_ipv6:
                        print ('    => Adding DNS IPv6 ' + str(i))
                        subprocess.call("echo 'nameserver " + i +"' >> /etc/resolv.conf", shell=True)    

        print (" 8. Configuring End User Address in the Tunnel interface")
        # add routes to possible different control or userplane IP addresses received in CreateSessionResponse or CreatePDPContextResponse
        if len(remote_destinations) > 1:
            for index, address in enumerate(remote_destinations):
                if index !=0:
                    if sys.platform == "linux" or sys.platform == "linux2":
                        subprocess.call("route add " + address + "/32 gw " + options.gateway_ip_address, shell=True)
     

        if end_user_address == "0.0.0.0":
            
            # alarm triggering for timeout for DHCP process
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(int(options.timeout))   # 2 seconds
            
            try:
                # dhcp process over GTP-u (userplane)
                mac = b'\x4e\xbb\x6d\x01\x00\x01' 
                # send dhcp_discovery
                udp_payload = dhcp_request_packet(1,mac[0:2]+mac[4:6],mac,'')
                dhcp_discovery_packet = ip_header_with_length("0.0.0.0","255.255.255.255", 17, 1, 8 + len(udp_payload)) + udp_header(68, 67, len(udp_payload)) + udp_payload
                s_gtpu.sendto(gtp_u_header(teid_remote_data, len(dhcp_discovery_packet)) + dhcp_discovery_packet, (tunnel_dst_ip_gtpu, GTP_U_REMOTE_PORT))
        
                flag = 0
                while flag < 1:
                    gtp_packet, gtp_address = s_gtpu.recvfrom(2000)
                    dhcp_packet = gtp_packet[8+28:]
                    dhcp_param = dhcp_decode(dhcp_packet)
            
                    if dhcp_param["op"] == b'\02' and dhcp_param["53"] == b'\x02':
                        udp_payload = dhcp_request_packet(3,mac[0:2]+mac[4:6],mac,dhcp_param["yiaddr"])
                        dhcp_offer_packet = ip_header_with_length("0.0.0.0","255.255.255.255", 17, 1, 8 + len(udp_payload)) + udp_header(68, 67, len(udp_payload)) + udp_payload
                        s_gtpu.sendto(gtp_u_header(teid_remote_data, len(dhcp_offer_packet)) + dhcp_offer_packet, (tunnel_dst_ip_gtpu, GTP_U_REMOTE_PORT))
                    
                    elif dhcp_param["op"] == b'\x02' and dhcp_param["53"] == b'\x05':
                        end_user_address = ip2str(dhcp_param["yiaddr"])
                        flag = 1   
                        signal.alarm(0)
                        
            except Exception as msg:
                print (' DHCP Process unsuccessful. Exiting. Message: ' + str(msg) + '\n')
                if sys.platform == "linux" or  sys.platform == "linux2":
                    delete_routes(options.netns, remote_destinations, options.gtp_kernel, teid_local_data, end_user_address) 
                exit(1)
        
        if options.netns:
            # create netns and move the tun device into it
            subprocess.call("ip netns add %s" % options.netns, shell=True)
            if options.gtp_kernel == False:
                subprocess.call("ip link set dev tun%s netns %s" % (str(options.dev_id), options.netns), shell=True)
                # moving to netns brings device down again so we need to turn it up
                exec_in_netns(options.netns, "ip link set dev tun%s up" % str(options.dev_id))
        
        if options.gtp_kernel == True:
            subprocess.call("modprobe gtp", shell=True)

        if end_user_address != "":         
            if sys.platform == "linux" or sys.platform == "linux2":

                if options.gtp_kernel == False:
                    exec_in_netns(options.netns, "ip addr add " + end_user_address + "/32 dev tun" + str(options.dev_id))
                else:
                    exec_in_netns(options.netns, "ip addr add " + end_user_address + "/32 dev lo")
                    exec_in_netns(options.netns, "gtp-link add gtp1 --sgsn > /tmp/log-gtp-link1 2>&1 &")
                    exec_in_netns(options.netns, "gtp-tunnel add gtp1 v1 " + str(teid_local_data) + " " + str(teid_remote_data) + " " + end_user_address + " " + tunnel_dst_ip_gtpu)

                if options.no_default == False:
                    if options.netns is not None:
                        if options.gtp_kernel == False:
                            print (" 9.1 Adding default route (0.0.0.0/0) pointing to the tunnel interface")
                            exec_in_netns(options.netns, "route add -net 0.0.0.0/0 gw " + end_user_address)
                        else:
                            print (" 9.1.Z Adding default route (0.0.0.0/0) pointing to the gtpu interface")
                            exec_in_netns(options.netns, "route add -net 0.0.0.0/0 dev gtp1")                        
                    else:
                        if options.gtp_kernel == False:
                            print (" 9.1 Adding default routes (0.0.0.0/1 and 128.0.0.0/1) pointing to the tunnel interface (to prevail over any current default route (0.0.0.0/0) already existing in the system)")    
                            exec_in_netns(options.netns, "route add -net 0.0.0.0/1 gw " + end_user_address)
                            exec_in_netns(options.netns, "route add -net 128.0.0.0/1 gw " + end_user_address)
                        else:
                            print (" 9.1.Z Adding default routes (0.0.0.0/1 and 128.0.0.0/1) pointing to the gtpu interface (to prevail over any current default route (0.0.0.0/0) already existing in the system)")    
                            exec_in_netns(options.netns, "route add -net 0.0.0.0/1 dev gtp1")
                            exec_in_netns(options.netns, "route add -net 128.0.0.0/1 dev gtp1")                        

        if end_user_address_ipv6 != "":
            # Adds fe80 + identifier. OS processes RouterAdvertisement/RouterSolicitation
            if sys.platform == "linux" or sys.platform == "linux2":
                exec_in_netns(options.netns, "ip -6 addr add " + ipv6_identifier + "/64 dev tun" + str(options.dev_id))
                if options.no_default == False:
                    if options.netns is not None:
                        print (" 9.2 Adding default route (::/0) pointing to the tunnel interface")
                        exec_in_netns(options.netns, "route -A inet6 add ::/0 dev tun" + str(options.dev_id))
                    else:
                        print (" 9.2 Adding default routes (::/1 and 8000::/1) pointing\ to the tunnel interface (to prevail over any current default route (::/0) already existing in the system)")
                        exec_in_netns(options.netns, "route -A inet6 add ::/1 dev tun" + str(options.dev_id))
                        exec_in_netns(options.netns, "route -A inet6 add 8000::/1 dev tun" + str(options.dev_id))
   
        if options.gtp_kernel == False:
            print ("10. Starting threads: GTP-U encapsulation and GTP-U decapsulation.")
            worker1 = Thread(target = encapsulate_gtp_u, args = ([dev, tunnel_dst_ip_gtpu, teid_remote_data],))
            worker2 = Thread(target = decapsulate_gtp_u, args = ([dev, tunnel_dst_ip_gtpu, teid_local_data],)) 
            worker1.setDaemon(True)
            worker2.setDaemon(True)
            worker1.start()
            worker2.start()

        print ("\nPress q to quit\n")        

        while True:
            socket_list = [sys.stdin, s_gtpc]
            # Get the list of sockets which are readable
            read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
         
            for sock in read_sockets:
     
                if sock == s_gtpc:
                    gtp_packet, gtp_address = s_gtpc.recvfrom(2000)
         
                    # validates packet source
                    if gtp_address[0] == tunnel_dst_ip_gtpc:

                        # gtp-c echo-request?
                        if gtp_packet[1:2] == b'\x01':
                            if options.tunnel_type == "GTP":
                                gtp_echo_response = bytearray(gtp_packet) + b'\x0e\x00'
                                gtp_echo_response[1] = 2
                                gtp_echo_response[3] += 2
                            else:
                                gtp_echo_response = bytearray(gtp_packet)
                                gtp_echo_response[1] = 2
                            s_gtpc.sendto(gtp_echo_response, gtp_address)
     
                        elif options.tunnel_type == "GTP":
                            # delete pdp context?
                            if gtp_packet[1:2] == b'\x14' and gtp_packet[4:8] == struct.pack("!L", teid_local_control):
                                dpc_request_msg = decode_gtpc(bytearray(gtp_packet)) # decode to check if request_sequence_number
                                s_gtpc.sendto(dpc_response(teid_remote_control, request_sequence_number), gtp_address)
                                print ("\n11. Exiting. Deleting PDP Context (GGSN Initiated). Removing routes previously created.")
                                delete_routes(options.netns, remote_destinations, options.gtp_kernel, teid_local_data, end_user_address)  
                                exit(1)
                            # update_pdp_context_request?
                            elif gtp_packet[1:2] == b'\x12' and gtp_packet[4:8] == struct.pack("!L", teid_local_control):
                                upc_request = decode_gtpc(bytearray(gtp_packet))
                                # if upc_request has qos we need to include it in answer
                                if upc_request != None:
                                    if 135 in upc_request:
                                        s_gtpc.sendto(upc_response(teid_remote_control, request_sequence_number, upc_request[135]), gtp_address)
                                    else:
                                        s_gtpc.sendto(upc_response(teid_remote_control, request_sequence_number, None), gtp_address) 
                        else:  # is GTPv2
                            # delete bearer request?
                            if gtp_packet[1:2] == b'\x63' and gtp_packet[4:8] == struct.pack("!L", teid_local_control):
                                gtp_response = bytearray(gtp_packet)
                                gtp_response[4:8] = struct.pack("!L", teid_remote_control)
                                gtp_response[1:2] = b'\x64'
                                gtp_response[3] += 6
                                gtp_response += b'\x02\x00\x02\x00\x10\x00'
                                                                                                          
                                s_gtpc.sendto(gtp_response, gtp_address)
                                print ("\n11. Exiting. Delete Bearer Request received (SGW/PGW Initiated). Removing routes previously created.")
                                delete_routes(options.netns, remote_destinations,  options.gtp_kernel, teid_local_data, end_user_address)  
                                exit(1)
                            # create bearer request?
                            elif gtp_packet[1:2] == b'\x5f' and gtp_packet[4:8] == struct.pack("!L", teid_local_control):
                                gtp_response = create_bearer_response(gtp_packet[8:11])
                                s_gtpc.sendto(gtp_response, gtp_address)
                                print ("\n10.1. Create Bearer Request received. Rejecting Bearer activation.")
                            # update bearer request?
                            elif gtp_packet[1:2] == b'\x61' and gtp_packet[4:8] == struct.pack("!L", teid_local_control):
                                gtp_response = update_bearer_response(gtp_packet[8:11])
                                s_gtpc.sendto(gtp_response, gtp_address)
                                print ("\n10.2. Update Bearer Request received. Sending Update Bearer Response.")

                else:
                    msg = sys.stdin.readline()
                    if msg == "q\n":
                        if options.tunnel_type == "GTP":
                            # sends DeletePDPContext
                            print ("\n11. Exiting. Deleting PDP Context. Removing routes previously created.")
                            s_gtpc.sendto(dpc_request(teid_remote_control), (tunnel_dst_ip_gtpc, GTP_C_REMOTE_PORT))
                            
                        elif options.tunnel_type == "GTPv2":
                            # sends DeleteSessionRequest
                            print ("\n11. Exiting. Deleting PDN Session. Removing routes previously created.")
                            s_gtpc.sendto(delete_session_request(options.gtp_address, options.nodetype), (tunnel_dst_ip_gtpc, GTP_C_REMOTE_PORT))
                            
                        delete_routes(options.netns, remote_destinations,  options.gtp_kernel, teid_local_data, end_user_address)   
                        exit(1)
                        
        os.close(dev)
        exit(1)

if __name__ == "__main__":
    main()



