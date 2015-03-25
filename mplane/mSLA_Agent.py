# mPlane Protocol Reference Implementation
# tStat component code
#
# (c) 2013-2014 mPlane Consortium (http://www.ict-mplane.eu)
#               Author: Edion TEGO
# mSLAcert-Agent-V-1.0.0
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
# Find proccess and kill it if you cannot bind port
# ps aux | grep -i iperf
# sudo kill proccess_ID
#

import threading
from datetime import datetime
from time import sleep
import time
import mplane.model
import mplane.scheduler
import mplane.utils
import mplane.tstat_caps
from urllib3 import HTTPSConnectionPool
from urllib3 import HTTPConnectionPool
from socket import socket
import ssl
import argparse
import sys
import re
import json
import subprocess
import collections
from datetime import datetime, timedelta
from ipaddress import ip_address
import tornado.web
import tornado.ioloop
from subprocess import Popen

DEFAULT_IP4_NET = "192.168.1.0/24"
DEFAULT_SUPERVISOR_IP4 = '127.0.0.1'
DEFAULT_SUPERVISOR_PORT = 8888
REGISTRATION_PATH = "register/capability"
SPECIFICATION_PATH = "show/specification"
RESULT_PATH = "register/result"

DUMMY_DN = "Dummy.Distinguished.Name"

print("    ###########################################################################################################");
print("    ###$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     $$$$$$$$  $$$$$$       $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ##$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$  $$$  $$$$$$  $$$$$  $$$$$  $$$$$$  $$$$$$$$$$$$$$    $$$$$$$$##");
print("    ##$$$$$$$$$$$$$      $$$$$$$$$$$$$$$$$$$$$  $$$$$  $$$$  $$$$  $$$$$$$  $$$$$        $$$$$$  $$$$  $$$$$$##");
print("    ##$$$$$$$$$$   ;$$$$   $$$$$$       $$$$$$  $$$$  $$$$$  $$$$$$$$$   $  $$$$$  $$$$$  $$$$  $$$$$  $$$$$$##");
print("    ##$$$$$$$$   $$$$$$$$  $$$$   $$$$$  $$$$$  $$  $$$$$$$  $$$$$$$  $$$$  $$$$$  $$$$$  $$$$        $$$$$$$##");
print("    ##$$$$$$   $$$$$$$$$$!      $$$$$$$   $$$$   $$$$$$$$$$  $$$$$  $$$$$$  $$$$$  $$$$$  $$$$  $$$$$$$$$$$$$##");
print("    ##$$$$   $$$$$$$$$$$$$$  $$$$$$$$$$$  $$$$  $$$$$$$$$$$  $$$$  $$$$$    $$$$$  $$$$$  $$$$  $$$$$  $$$$$$##");
print("    ##$$$  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$  $$$$  $$$$$$$$$$$  $$$$$       $  $$$$$  $$$$$  $$$$$       $$$$$$$##");
print("    ###$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ##$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$_____________________&______________________&_____________&_______________$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$$___| mSLAcert probe| TCP & UDP Agent verification and certification|_______$$$$$$$$$$$$$$$$$$##");
print("    ###########################################################################################################");


"""
Implements mSLA-Agent proxy for integration into 
the mPlane reference implementation.
(capability push, specification pull)

"""
commands = [
    'echo Starteded on	$(date)	-------------------->> ./results/mslaTCP.receive.client.txt',
    'iperf -s -p 5001 -i 1 -f k >> ./results/mslaTCP.receive.client.txt &',
    'pid5001=$!',
#    'echo Ended on	$date	------------------------------->> ./mslaTCP.receive.client.txt',
    'echo Starteded on	$(date)	-------------------->> ./results/mslaUDP.receive.client.txt',
    'iperf -s -u -p 5002 -i 1 -f  k >> ./results/mslaUDP.receive.client.txt &',
    'pid5002=$!',
#    'echo Ended on	$date	------------------------------->> ./mslaUDP.receive.client.txt',
]
# run in parallel and store locally the result
processes = [Popen(cmd, shell=True) for cmd in commands]

def sla_AGENT_capability(ip4addr):
    cap = mplane.model.Capability(label="msla-AGENT-Probe-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ip4addr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("mSLA.udpCapacity.download.iperf")
    return cap
    

class mSLAcert_Agent_Service(mplane.scheduler.Service):
    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or 
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or 
                 cap.has_parameter("destination.ip6")) and
                (cap.has_result_column("mSLA.udpCapacity.download.iperf"))):
            raise ValueError("capability not acceptable")
        super(mSLAcert_Agent_Service, self).__init__(cap)

    def run(self, spec, check_interrupt):
         # unpack parameters
        period = spec.when().period().total_seconds()
        duration = spec.when().duration().total_seconds()
        if duration is not None and duration > 0:
            count = int(duration / period)
        else:
            count = None
        
        agent = []
        a = time.time()
        time.sleep(count)
        report_i_am_agent = -1001
        b = time.time()
        
        # derive a result from the specification
        res = mplane.model.Result(specification=spec)
        # put actual start and end time into result
        res.set_when(mplane.model.When(a , b))
        # are we returning aggregates or raw numbers?
        if res.has_result_column("mSLA.udpCapacity.download.iperf"):
                res.set_result_value("mSLA.udpCapacity.download.iperf", report_i_am_agent)
                #os.system("scp ./results/mslaTCP.receive.client.txt USER@Repository:/repository/temp/")
                #os.system("scp ./results/mslaUDP.receive.client.txt USER@Repository:/repository/temp/")
        return res


def parse_args():
    global args
    parser = argparse.ArgumentParser(description="Run an mPlane mSLAcert probe agent")
    parser.add_argument('-4','--ip4addr', metavar="source-v4-address",
                        help="mSLA-test from the given IPv4 address")
    parser.add_argument('-6', '-ip6addr', metavar="source-v6-address",
                        help="mSLA-test from the given IPv6 address")
    parser.add_argument('-s', '--sec', metavar="security-on-off",
                        help="Toggle security on/off. Values: 0=on,1=off")
    parser.add_argument('-n', '--net-address', metavar='net-address', default=DEFAULT_IP4_NET, dest='IP4_NET',
                        help='Subnet IP4 and netmask observed by this probe (in the format x.x.x.x/n)')
    parser.add_argument('-d', '--supervisor-ip4', metavar='supervisor-ip4', default=DEFAULT_SUPERVISOR_IP4, dest='SUPERVISOR_IP4',
                        help='Supervisor IP address')
    parser.add_argument('-p', '--supervisor-port', metavar='supervisor-port', default=DEFAULT_SUPERVISOR_PORT, dest='SUPERVISOR_PORT',
                        help='Supervisor port number')
    parser.add_argument('--disable-ssl', action='store_true', default=False, dest='DISABLE_SSL',
                        help='Disable secure communication')
    parser.add_argument('-c', '--certfile', metavar="path-of-cert-file", dest='CERTFILE', default = None,
                        help="Location of the configuration file for certificates")
    args = parser.parse_args()

   
def manually_test_msla():
    svc = mSLAcert_Agent_Service(sla_AGENT_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))
       
class HttpProbe():
    """
    This class manages interactions with the supervisor:
    registration, specification retrievement, and return of results
    
    """
    
    def __init__(self, immediate_ms = 5000):
        parse_args()
        self.dn = None
        ip4addr = None
        ip6addr = None        
        # check if security is enabled, if so read certificate files
        self.security = not args.DISABLE_SSL
        if self.security:
            mplane.utils.check_file(args.CERTFILE)
            self.cert = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "cert"))
            self.key = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "key"))
            self.ca = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "ca-chain"))
            mplane.utils.check_file(self.cert)
            mplane.utils.check_file(self.key)
            mplane.utils.check_file(self.ca)
            self.pool = HTTPSConnectionPool(args.SUPERVISOR_IP4, args.SUPERVISOR_PORT, key_file=self.key, cert_file=self.cert, ca_certs=self.ca)
        else: 
            self.pool = HTTPConnectionPool(args.SUPERVISOR_IP4, args.SUPERVISOR_PORT)
            self.cert = None
        
        # get server DN, for Access Control purposes
        self.dn = self.get_dn()
        
        # generate a Service for each capability
        self.immediate_ms = immediate_ms
        self.scheduler = mplane.scheduler.Scheduler(self.security, self.cert)
        self.scheduler.add_service(mSLAcert_Agent_Service(sla_AGENT_capability(ip4addr)))


        
        
    def get_dn(self):
        """
        Extracts the DN from the server. 
        If SSL is disabled, returns a dummy DN
        
        """
        if self.security == True:
            
            # extract DN from server certificate.
            # Unfortunately, there seems to be no way to do this using urllib3,
            # thus ssl library is being used
            s = socket()
            c = ssl.wrap_socket(s,cert_reqs=ssl.CERT_REQUIRED, keyfile=self.key, certfile=self.cert, ca_certs=self.ca)
            c.connect((args.SUPERVISOR_IP4, args.SUPERVISOR_PORT))
            cert = c.getpeercert()
            
            dn = ""
            for elem in cert.get('subject'):
                if dn == "":
                    dn = dn + str(elem[0][1])
                else: 
                    dn = dn + "." + str(elem[0][1])
        else:
            dn = DUMMY_DN
        return dn
     
    def register_to_supervisor(self):
        """
        Sends a list of capabilities to the Supervisor, in order to register them
        
        """
        url = "/" + REGISTRATION_PATH
        
        # generate the capability list
        caps_list = ""
        no_caps_exposed = True
        for key in self.scheduler.capability_keys():
            cap = self.scheduler.capability_for_key(key)
            if (self.scheduler.ac.check_azn(cap._label, self.dn)):
                caps_list = caps_list + mplane.model.unparse_json(cap) + ","
                no_caps_exposed = False
        caps_list = "[" + caps_list[:-1].replace("\n","") + "]"
        connected = False
        
        if no_caps_exposed is True:
           print("\nNo Capabilities are being exposed to the Supervisor, check permission files. Exiting")
           exit(0)
        
        # send the list to the supervisor, if reachable
        while not connected:
            try:
                res = self.pool.urlopen('POST', url, 
                    body=caps_list.encode("utf-8"), 
                    headers={"content-type": "application/x-mplane+json"})
                connected = True
                
            except:
                print("Supervisor unreachable. Retrying connection in 5 seconds")
                sleep(5)
                
        # handle response message
        if res.status == 200:
            body = json.loads(res.data.decode("utf-8"))
            print("\nCapability registration outcome:")
            for key in body:
                if body[key]['registered'] == "ok":
                    print(key + ": Ok")
                else:
                    print(key + ": Failed (" + body[key]['reason'] + ")")
            print("")
        else:
            print("Error registering capabilities, Supervisor said: " + str(res.status) + " - " + res.data.decode("utf-8"))
            exit(1)
    
    def check_for_specs(self):
        """
        Poll the supervisor for specifications
        
        """
        url = "/" + SPECIFICATION_PATH
        
        # send a request for specifications
        res = self.pool.request('GET', url)
        if res.status == 200:
            
            # specs retrieved: split them if there is more than one
            specs = mplane.utils.split_stmt_list(res.data.decode("utf-8"))
            for spec in specs:
                
                # hand spec to scheduler
                reply = self.scheduler.receive_message(self.dn, spec)
                
                # return error if spec is not authorized
                if isinstance(reply, mplane.model.Exception):
                    result_url = "/" + RESULT_PATH
                    # send result to the Supervisor
                    res = self.pool.urlopen('POST', result_url, 
                            body=mplane.model.unparse_json(reply).encode("utf-8"), 
                            headers={"content-type": "application/x-mplane+json"})
                    return
                
                # enqueue job
                job = self.scheduler.job_for_message(reply)
                
                # launch a thread to monitor the status of the running measurement
                t = threading.Thread(target=self.return_results, args=[job])
                t.start()
                
        # not registered on supervisor, need to re-register
        elif res.status == 428:
            print("\nRe-registering capabilities on Supervisor")
            self.register_to_supervisor()
        pass
    
    def return_results(self, job):
        """
        Monitors a job, and as soon as it is complete sends it to the Supervisor
        
        """
        url = "/" + RESULT_PATH
        reply = job.get_reply()
        
        # check if job is completed
        while job.finished() is not True:
            if job.failed():
                reply = job.get_reply()
                break
            sleep(1)
        if isinstance (reply, mplane.model.Receipt):
            reply = job.get_reply()
        
        # send result to the Supervisor
        res = self.pool.urlopen('POST', url, 
                body=mplane.model.unparse_json(reply).encode("utf-8"), 
                headers={"content-type": "application/x-mplane+json"})
                
        # handle response
        if res.status == 200:
            print("Result for " + reply.get_label() + " successfully returned!")
        else:
            print("Error returning Result for " + reply.get_label())
            print("Supervisor said: " + str(res.status) + " - " + res.data.decode("utf-8"))
        pass

if __name__ == "__main__":
    mplane.model.initialize_registry()
    probe = HttpProbe()
    
    # register this probe to the Supervisor
    probe.register_to_supervisor()
    
    # periodically polls the Supervisor for Specifications
    print("Checking for Specifications...")
    while(True):
        probe.check_for_specs()
        sleep(5)
