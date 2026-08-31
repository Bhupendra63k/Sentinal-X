from dataclasses import dataclass,field
from typing import Optional

@dataclass
class Finding:

    scanner:str
    target:str
    finding_id:str
    title:str
    severity:str="Info"
    description:str=""
    evidence:str=""
    recommendation:str=""

    def to_dict(self):
        return{
            "scanner":self.scanner,
            "target":self.target,
            "finding_id":self.finding_id,
            "title":self.title,
            "severity":self.severity,
            "description":self.description,
            "evidence":self.evidence,
            "recommendation":self.recommendation

        }