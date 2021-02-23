#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, SCTP, Raw, SCTPChunkData
from scapy.layers.inet import _IPOption_HDR

##imports for adding P4 entry
p4_path = "/home/sdn/dev/multi-mobile-edge-cloud/p4-control/gtp_02_physical"
sys.path.append(p4_path)
import remote_add_entry

##active_ues is a dictionary to store the UE's IP and downlink TEID
##<KEY, VALUE>
##<mme_ue_s1ap_teid, (IPv4, TEID)>
##note to self: consider using array for performance, the range of
##  mme_ue_s1ap_teid is [0,65535].
active_ues = {}

##takes a byte string and returns a string
def get_ip_str(ipv4):
    ip = ""
    for byte in ipv4:
        ip = ip+str(byte)+'.'
    return ip[:-1]

def handle_pkt(pkt):
    print("got a packet")
    #pkt.show2()
    #hexdump(pkt)
    #sys.stdout.flush()
    s1ap=pkt[SCTPChunkData].data
    hexdump(s1ap)
    #hexdump(s1ap[0:2])
    code = s1ap[0:2]
    if (code == b'\x00\x09'):
        print("HAS IP")

        mme_ue_s1ap_id = s1ap[12:14]
        id_enb_ue_s1ap_id = s1ap[14:16]
        print("MME_UE_S1AP_ID\t", mme_ue_s1ap_id)
        print("eNB_UE_S1AP_ID\t", id_enb_ue_s1ap_id)

        ## the following is getting the UE's IP
        ## some header lengths are flexible,
        ## use print statement and wireshark to debug if things get out of wack
        len_up_to_nas = 58
        nas_pdu = s1ap[len_up_to_nas:]
        #hexdump(nas_pdu)
        len_nas_header = 10 ## lets hope this doesn't change
        len_tai_list = int.from_bytes(nas_pdu[len_nas_header:len_nas_header+1], "big")
        #print(len_tai_list, "= tracking area identity list length")
        len_esm_msg = int.from_bytes(nas_pdu[len_nas_header+len_tai_list+1: len_nas_header+len_tai_list+3], "big") ## add 1 for tai length byte
        #print(len_esm_msg, "= ESM message container length")
        esm_msg = nas_pdu[len_nas_header+len_tai_list: len_nas_header+len_tai_list+len_esm_msg]
        #hexdump(esm_msg)
        len_ems_header = 6 ## lets hope this doesn't change
        len_eps_qos = int.from_bytes(esm_msg[len_ems_header: len_ems_header+1], "big")
        #print(len_eps_qos, "= EPS quality of service length")
        len_apn = int.from_bytes(esm_msg[len_ems_header+len_eps_qos:len_ems_header+len_eps_qos+1], "big")
        #print(len_apn, "= Access point name length")
        len_pdn_header = 2 ## lets hope this doesn't change
        pdn_ipv4 = esm_msg[len_ems_header+len_eps_qos+len_apn+2+len_pdn_header: len_ems_header+len_eps_qos+2+len_apn+len_pdn_header+4]
        hexdump(pdn_ipv4)
        mme_id = int.from_bytes(mme_ue_s1ap_id, 'big')
        ##check for valid mme_id
        if mme_id >= 0 and mme_id <= 65535:
            pass
        else:
            print("exiting, not valid mme_id: ", mme_id)
            return -1

        if mme_id in active_ues:
            active_ues[mme_id][0] = pdn_ipv4
        else:
            active_ues[mme_id] = [pdn_ipv4, -1]
            print("new entry: ", active_ues[mme_id])
            
        if active_ues[mme_id][1] == -1:
            print("missing TEID, No remote add to p4 table, expected behavior")
            pass
        else:
            print("performing remote add with:")
            print(active_ues[mme_id])
            ## Remote add code.
            ## prototype for
            ## remote_add_entry.add_e(string ip, int dl_tid, string p4_path)
            dl_tid = int.from_bytes(active_ues[mme_id][1], 'big')
            ip = get_ip_str(active_ues[mme_id][0])
            print(ip, dl_tid)
            remote_add_entry.add_e(ip, dl_tid, p4_path)
            

    elif (code == b'\x20\x09'):
        print("HAS TEID")
        
        mme_ue_s1ap_id = s1ap[11:13]
        id_enb_ue_s1ap_id = s1ap[13:15]
        gtp_teid = s1ap[34:38]
        print("MME_UE_S1AP_ID\t", mme_ue_s1ap_id)
        print("eNB_UE_S1AP_ID\t", id_enb_ue_s1ap_id)
        print("GTP_TEID\t", gtp_teid)
        mme_id = int.from_bytes(mme_ue_s1ap_id, 'big')
        ##check for valid mme_id
        if mme_id >= 0 and mme_id <= 65535:
            pass
        else:
            print("exiting, not valid mme_id: ", mme_id)
            return -1

        if mme_id in active_ues:
            active_ues[mme_id][1] = gtp_teid
        else:
            active_ues[mme_id] = [-1, gtp_teid]
            print("new entry: ", active_ues[mme_id])
            
        if active_ues[mme_id][0] == -1:
            print("missing IPv4, No remote add to p4 table")
            pass
        else:
            print("performing remote add with:")
            print(active_ues[mme_id])
            ## Remote add code.
            ## prototype for
            ## remote_add_entry.add_e(string ip, int dl_tid, string p4_path)
            dl_tid = int.from_bytes(active_ues[mme_id][1], 'big')
            ip = get_ip_str(active_ues[mme_id][0])
            print(ip, dl_tid)
            remote_add_entry.add_e(ip, dl_tid, p4_path)
    
    elif (code == b'\x20\x17'):
        print("HAS UEContextReleaseComplete")
        mme_ue_s1ap_id = s1ap[11:13]            
        print("MME_UE_S1AP_ID\t", mme_ue_s1ap_id)
        mme_id = int.from_bytes(mme_ue_s1ap_id, 'big')
        ##check for valid mme_id
        if mme_id >= 0 and mme_id <= 65535:
            pass
        else:
            print("exiting, not valid mme_id: ", mme_id)
            return -1
        if mme_id in active_ues:
            if active_ues[mme_id][0] != -1:
                ip = get_ip_str(active_ues[mme_id][0])
                remote_add_entry.remove_e(ip, p4_path)
                print("performing remote remove with: " + ip)
            del active_ues[mme_id]
            
    print("Printing active_ues", active_ues)

## sniffing on the port 2, the EDGE port
def main():
    ifaces = filter(lambda i: 'enx000acd367f8b' in i, os.listdir('/sys/class/net/'))
    iface = ""
    for i in ifaces:
        iface = i
        break
    print(iface)
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    ## sniff filters SCTPs with a DATA chunk that contains an S1AP 
    sniff(iface = iface,
          lfilter = lambda pkt: SCTPChunkData in pkt and pkt[SCTPChunkData].proto_id == 0x12,
          prn = lambda x: handle_pkt(x))
    
if __name__ == '__main__':
    main()
