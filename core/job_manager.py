import asyncio
from datetime import datetime
from typing import Dict,List,Optional
from fastapi import Websocket

class ScanJob:
    def __init__(self,scan_id:str,scanner:str,scan_type:str,target:str):
        self.scan_id=scan_id
        self.scanner=scanner
        self.scan_type=scan_type
        self.target=target
        self.status="PENDING"
        self.created_at=datetime.utcnow().isoformat()
        self.logs:List[str]=[]
        self.findings:List[dict]=[]
        self.result:Optional[dict]=None
        self.error:Optional[str]=None


class JobManager:
    def __init__(self):
        self.jobs:Dict[str,ScanJob]={}
        self.active_connection:Dict[str,List[Websocket]]={}

    def create_job(self,scan_id:str,scanner:str,scan_type:str,target:str) ->ScanJob:
        job =ScanJob(scan_id,scanner,scan_type,target)
        self.jobs[scan_id]=job
        self.active_connection[scan_id]=[]
        return job

    def get_job(self,scan_id:str) -> Optional[ScanJob]:
        return self.jobs.get(scan_id)
    
    async def connect_ws(self,scan_id:str,websocket:Websocket):
        await websocket.accept()
        if scan_id not in self.active_connection:
            self.active_connection[scan_id]=[]
        self.active_connection[scan_id].append(websocket)

    def disconnect_ws(self,scan_id:str,websocket:Websocket):
        if scan_id in self.active_connection:
            if websocket in self.active_connection[scan_id]:
                self.active_connection[scan_id].remove(websocket)

    async def broadcast_event(self,scan_id:str,event_type:str,payload:dict):
        job=self.jobs.get(scan_id)
        if event_type=="log" and job:
            job.logs.append(payload.get("message",""))
        elif event_type=="finding" and job:
            job.findings.append(payload.get("finding",{}))

        message={
            "scan_id":scan_id,
            "type":event_type,
            "timestamp":datetime.utcnow().isoformat(),
            "data":payload
        }
        if scan_id in self.active_connection:
            stale_connections=[]
            for connection in self.active_connection[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    stale_connections.append(connection)

            for stale in stale_connections:
                self.active_connection[scan_id].remove(stale)