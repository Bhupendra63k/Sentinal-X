from abc import ABC,abstractmethod
from typing import Dict,Any

class BaseScanner(ABC):
    name:str=""
    category:str="general"
    description:str=""
    target_type:str="host"
    include_in_pipeline:bool=False
    pipeline_order:int=99
    default_pipeline_scan:str=""
    scan_commands:Dict[str,Any]={}

    @abstractmethod
    def scan(self,scan_type:str,target:str,**kwargs) -> Dict[str,Any]:
        pass

    def get_metadata(self)->Dict[str,Any]:
        return {
            "name":self.name,
            "category":self.category,
            "description":self.description,
            "target_type":self.target_type,
            "scan_types":list(self.scan_commands.keys()),
            "include_in_pipeline":self.include_in_pipeline,
            "pipeline_order":self.pipeline_order,
        }