from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner
from scanners.reconnaissance.Nikto.nikto_scanner import NiktoScanner
from scanners.reconnaissance.nuclei.nuclei_scanner import NucleiScanner
from scanners.credential_security.credential_scanner import CredentialScanner
from scanners.network.tcpdump.tcpdump_scanner import TcpdumpScanner

def get_scanner_metadata():
    return [{"name":"nmap",
             "display_name": "Nmap Scanner",
             "scan_types":[
                 "quick","service","os","aggressive","full"
             ]},
             {"name":"nikto",
              "display_name" : "Nikto",
              "scan_types":[
                  "basic","ssl","redirects","info","injection"
              ]},
              {"name":"nuclei",
               "display_name": "Nuclei",
               "scan_types":["default"]},
               {
                   "name":"credential_scanner",
                   "display_name":"Credential Security Scanner",
                   "scan_types":["hash_identification","hashcat","john"]
               },
               {
                   "name": "tcpdump",
                   "category": "network",
                   "description": "Passive network traffic packet capture and security exposure inspection",
                   "scan_types": ["quick_capture", "traffic_audit"],
                   "target_type": "interface",},
                {
                  "name": "hping3",
                  "category": "network",
                  "description": "Active Layer 3/4 packet probing, latency auditing, and reachability inspection",
                  "scan_types": ["icmp_ping", "syn_probe", "syn_probe_https"],
                  "target_type": "host",},
               ]