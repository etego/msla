import os
import subprocess
mslatcpagentipv4 = "iperf -s -p 5001 -i 1 >./mslatcpcertagent.log"
mslatcpagent4 = subprocess.Popen(mslatcpagentipv4, shell=True, stderr=subprocess.PIPE)
"""
while True:
    out = mslaagent4.stderr.read(1)
    if out == '' and mslatcpagent4.poll() != None:
        break
    if out != '':
        sys.stdout.write(out)
        sys.stdout.flush()
"""
