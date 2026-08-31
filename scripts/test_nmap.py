import subprocess

result=subprocess.run(
    ["nmap","scan.nmap.org"],
    capture_output=True,
    text=True
)

print(result.stdout)