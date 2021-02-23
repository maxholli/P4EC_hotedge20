import json
import os
import subprocess

def add_e(ip, teid, path):    
    ## Build json directory
    entry_encap = {}
    entry_encap['target'] = "bmv2"
    entry_encap['p4info'] = "build/gtpv2-l2.p4.p4info.txt"
    entry_encap['bmv2_json'] = "build/gtpv2-l2.json"
    entry_encap['table_entries'] = []
    entry_encap['table_entries'].append({"table": "MyIngress.ue_at_eNB",
                                   "match": {"hdr.ipv4.dstAddr": [ip, 32]},
                                   "action_name": "MyIngress.forward_to_ue",
                                   "action_params": {"eNBip": "192.168.1.2",
                                                     "eNBmac": "64:a8:37:26:01:99",
                                                     "pgwToUE": teid}
                                   })
    ## write to file
    with open(path + '/entry_encap.txt', 'w') as outfile:  
        json.dump(entry_encap, outfile)

    p = subprocess.Popen(["python", "add_entry.py", "entry_encap.txt"], cwd=path)
    p.wait()
    #bashCommand = "python " + path + "/add_entry.py " + path + "/entry_encap.txt"
    #os.system(bashCommand)


    ## Build json directory
    entry_decap = {}
    entry_decap['target'] = "bmv2"
    entry_decap['p4info'] = "build/gtpv2-l2.p4.p4info.txt"
    entry_decap['bmv2_json'] = "build/gtpv2-l2.json"
    entry_decap['table_entries'] = []
    entry_decap['table_entries'].append({"table": "MyIngress.ue_svc_match",
                                         "match": {"hdr.inner_ipv4.srcAddr": ip,
                                                   "hdr.inner_ipv4.dstAddr": "192.168.1.253"},
                                         "action_name": "MyIngress.ue_getsvcnum",
                                         "action_params": {"svc_num": 1}
    })
    ## write to file
    with open(path + '/entry_decap.txt', 'w') as outfile:  
        json.dump(entry_decap, outfile)

    p = subprocess.Popen(["python", "add_entry.py", "entry_decap.txt"], cwd=path)
    p.wait()
    #bashCommand = "python " + path + "/add_entry.py " + path + "/entry_decap.txt"
    #os.system(bashCommand)

def remove_e(ip, path):    
    ## Build json directory
    entry_encap = {}
    entry_encap['target'] = "bmv2"
    entry_encap['p4info'] = "build/gtpv2-l2.p4.p4info.txt"
    entry_encap['bmv2_json'] = "build/gtpv2-l2.json"
    entry_encap['table_entries'] = []
    entry_encap['table_entries'].append({"table": "MyIngress.ue_at_eNB",
                                   "match": {"hdr.ipv4.dstAddr": [ip, 32]},
                                   "action_name": "MyIngress.forward_to_ue",
                                   "action_params": {"eNBip": "192.168.1.2",
                                                     "eNBmac": "64:a8:37:26:01:99",
                                                     "pgwToUE": 21212121}
                                   })
    ## write to file
    with open(path + '/entry_encap.txt', 'w') as outfile:  
        json.dump(entry_encap, outfile)

    p = subprocess.Popen(["python", "remove_entry.py", "entry_encap.txt"], cwd=path)
    p.wait()
    #bashCommand = "python " + path + "/add_entry.py " + path + "/entry_encap.txt"
    #os.system(bashCommand)


    ## Build json directory
    entry_decap = {}
    entry_decap['target'] = "bmv2"
    entry_decap['p4info'] = "build/gtpv2-l2.p4.p4info.txt"
    entry_decap['bmv2_json'] = "build/gtpv2-l2.json"
    entry_decap['table_entries'] = []
    entry_decap['table_entries'].append({"table": "MyIngress.ue_svc_match",
                                         "match": {"hdr.inner_ipv4.srcAddr": ip,
                                                   "hdr.inner_ipv4.dstAddr": "192.168.1.253"},
                                         "action_name": "MyIngress.ue_getsvcnum",
                                         "action_params": {"svc_num": 1}
    })
    ## write to file
    with open(path + '/entry_decap.txt', 'w') as outfile:  
        json.dump(entry_decap, outfile)

    p = subprocess.Popen(["python", "remove_entry.py", "entry_decap.txt"], cwd=path)
    p.wait()
    #bashCommand = "python " + path + "/add_entry.py " + path + "/entry_decap.txt"
    #os.system(bashCommand)

