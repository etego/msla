import os
import subprocess
mslaudpagentipv4 = "iperf -s -u -p 5002 -i 1 >./mslaudpcertagent.log"
mslaudpagent4 = subprocess.Popen(mslaudpagentipv4, shell=True, stderr=subprocess.PIPE)
"""
while True:
    out = mslaudpagent4.stderr.read(1)
    if out == '' and mslaudpagent4.poll() != None:
        break
    if out != '':
        sys.stdout.write(out)
        sys.stdout.flush()
"""
