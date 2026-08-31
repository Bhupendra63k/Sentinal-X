import json 

class NucleiParser:
    def parse(self,output):
        findings=[]
        for line in output.splitlines():
            line=line.strip()

            if not line:
                continue
            try:
                data=json.loads(line)
                findings.append(data)
            except json.JSONDecodeError:
                continue

        return findings

if __name__=="__main__":
    sample='{"template-id":"test","info":{"name":"Test finding","severity":"info"}}'
    parser=NucleiParser()
    result=parser.parse(sample)
    print(result)