class NmapParser:
    """parses nmap output into structured data"""
    def parse(self,output):
        lines=output.splitlines()
        result={
                    "target":None,
                    "ip":None,
                    "host_status":None,
                    "ports":[],
                    "scanner":None,
                    "scan_type":None
                }
        
        for line in lines:
            if line.startswith("Nmap scan report for"):
                data=line.replace("Nmap scan report for", "")
                target,ip=data.split(" (")
                result["target"]=target.strip()
                result["ip"]=ip.rstrip(")")
            elif line.startswith("Host is up"):
                if "up" in line.lower():
                    result["host_status"]="UP"
            parts=line.split()
            if len(parts)>=3 and "/" in parts[0]:
                ports,protocol=parts[0].split("/")
                state=parts[1]
                service=parts[2]
                version=" ".join(parts[3:]) if len(parts) > 3 else None
                port_info={
                    "port":ports,
                    "protocol":protocol,
                    "state":state,
                    "service":service,
                    "version":version
                }
                result["ports"].append(port_info)

        return result