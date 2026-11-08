from scanners.reconnaissance.nmap.nmap_scanner import NmapScanner
from scanners.reconnaissance.Nikto.nikto_scanner import NiktoScanner
from scanners.reconnaissance.nuclei.nuclei_scanner import NucleiScanner
from scanners.credential_security.credential_scanner import CredentialScanner

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
               }]