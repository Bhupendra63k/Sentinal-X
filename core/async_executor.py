import asyncio
import json
import time
from core.job_manager import JobManager
from history.scan_history import ScanHistory

async def execute_scanner_task(job_id:str,scanner_instance,scan_type:str,target:str,job_manager:JobManager,scan_history:ScanHistory):
    job=job_manager.get_job(job_id)
    if not job:
        return
    job.status="RUNNING"
    await job_manager.broadcast_event(job_id,"status_change",{"status":"RUNNING","message":f"Starting {job.scanner} scan on {target}"},)
    start_time=time.time()
    collected_stdout=[]
    collected_findings=[]
    try:
        if job.scanner=="nuclei":
            normalized_target=target if target.startswith(("http://","https://")) else f"https://{target}"
            command=["nuclei","-u",normalized_target]+scanner_instance.scan_commands.get(scan_type,["-silent","-jsonl"])
        elif job.scanner=="nikto":
            flags=list(scanner_instance.scan_commands.get(scan_type,["-ask","no","-maxtime","120s"]))
            normalized_target=target if target.startswith(("http://","https://")) else f"https://{target}"
            if normalized_target.startswith("https://") and "-ssl" not in flags:
                flags.append("-ssl")
            command=["nikto"]+flags+["-h",normalized_target]
        else:
            raise ValueError(f"scanner {job.scanner} not supported for streaming execution.")

        process=await asyncio.create_subprocess_exec(*command,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        while True:
            line_bytes=await process.stdout.readline()
            if not line_bytes:
                break
            line=line_bytes.decode("utf-8",errors="replace").strip()
            if not line:
                continue
            collected_stdout.append(line)
            if job.scanner=="nuclei" and line.startswith("{"):
                try:
                    parsed_list=scanner_instance.parser.parse(line,target)
                    for finding in parsed_list:
                        collected_findings.append(finding)
                        await job_manager.broadcast_event(job_id,"finding",{"finding":finding})
                except Exception:
                    pass
            await job_manager.broadcast_event(job_id,"finding",{"message":line})

        await process.wait()
        duration=round(time.time()-start_time,2)
        if job.scanner=="nikto":
            full_output="\n".join(collected_stdout)
            collected_findings=scanner_instance.parser.parse(full_output,target)
        result_payload={"scan_id":job_id,"scanner":job.scanner,"scan_type":scan_type,"status":"COMPLETED","target":target,"duration":duration,"summary":{"total_findings":len(collected_findings)},"findings":collected_findings,"error":None}
        job.status="COMPLETED"
        job.result=result_payload
        scan_history.save_scan(result_payload)
        await job_manager.broadcast_event(
            job_id,"completed",{"status":"COMPLETED","duration":duration,"findings_count":len(collected_findings)},
        )

    except Exception as exc:
        duration=round(time.time()-start_time,2)
        job.status="FAILED"
        job.error=str(exc)
        failure_payload={
            "scan_id":job_id,"scanner":job.scanner,"scan_type":scan_type,"status":"FAILED","target":target,"duration":duration,"findings":[],"error":str(exc)}
        scan_history.save_scan(failure_payload)
        await job_manager.broadcast_event(
            job_id,"error",{"status":"FAILED","error":str(exc)}
        )
