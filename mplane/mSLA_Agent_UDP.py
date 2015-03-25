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
print("    ###$$$$$$$$$| mSLAcert probe| _______________ UDP Agent verification and certification|$$$$$$$$$$$$$$$$$$##");
print("    ###########################################################################################################");


"""
Implements mSLA-Agent proxy for integration into 
the mPlane reference implementation.
(capability push, specification pull)

"""
from subprocess import Popen

commands = [
    'iperf -s -p 5001 -i 1 -f k &',
    'pid5001=$!',
    'iperf -s -u -p 5002 -i 1 -f k &',
    'pid5002=$!',
]
# run in parallel
processes = [Popen(cmd, shell=True) for cmd in commands]


_tcpslaline_re = re.compile("[+\s+\d+]\s+\d.+\d+-\s+(\d+.+\d)\s+sec\s+(\d+.+\d+)\s+MBytes\s+(\d+\d.+\d+)\s+Mbits/sec")

_tcpsla4cmd = "iperf"
_tcpsla6cmd = "iperf"
_tcpslaopts = ["-n"]
_tcpslaopt_period = "-i"
_tcpslaopt_count = "-t"
_tcpslaopt_source = "-c"

tcpslaValue = collections.namedtuple("tcpslaValue", ["time", "interval", "transfer", "bandwidth"])

_mslaline_re = re.compile("[+\s+\d+]\s+\d.+\d+-\s+(\d+.+\d)\s+sec\s+(\d+.+\d+)\s+MBytes\s+(\d+\d.+\d+)\s+Mbits/sec")

_udpreport_re = re.compile("[+\s+\d+]\s+\d.+\d+-\s+(\d+.+\d)\s+sec\s+(\d+.+\d+)\s+MBytes\s+(\d+\d.+\d+)\s+Mbits/sec\s+(\d+.+\d+)\s+ms\s+(\d+)/(\d+)\s+\(+(\d+.\d+\%)+\)")

udpreportvalue = collections.namedtuple("udpreportValue", ["time", "transfer", "bandwidthmean", "jitter", "lost", "total", "error"])

_msla4cmd = "iperf"
_msla6cmd = "iperf"
_mslaopts = ["-n"]
_mslaopt_period = "-i"
_mslaopt_count = "-t"
_mslaopt_source = "-c"
_mslaopt_band = "-b 1000m"
_mslaopt_port = "-p 5002"
_mslaopt_testudp = "-u"

mslaValue = collections.namedtuple("mslaValue", ["time", "interval", "transfer", "bandwidth"])

def _parse_msla_line(line):
    m = _mslaline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()
    return  mslaValue(datetime.utcnow(), int(float(mg[0])), int(float(mg[1])), int(float(mg[2])))
 #   or return udpreportvalue(datetime.utcnow(), int(float(mg[0])), int(float(mg[1])), int(float(mg[2])), int(float(mg[3])), int(float(mg[4])), int(float(mg[5])), chr(mg[6]))


def _parse_tcpsla_line(line):
    m = _tcpslaline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()
    return tcpslaValue(datetime.utcnow(), int(float(mg[0])), int(float(mg[1])), int(float(mg[2])))


def _parse_msla_last_line(line):
    lst = _udpreport_re.search(line)
    if lst is None:
       return None
    lstg = lst.groups()
    return udpreportvalue(datetime.utcnow(), int(float(lstg[0])), int(float(lstg[1])), int(float(lstg[2])), int(float(lstg[3])), int(float(lstg[4])), int(float(lstg[5])), chr(lstg[6]))
    
def _msla4_process(sipaddr, dipaddr, period=None, count=None, testudp=None, band=None, port=None):
    return _msla_process(_msla4cmd, testudp, dipaddr, period, count, band, port)

def _msla_process(progname, sipaddr, dipaddr, period=None, count=None, testudp=None, band=None, port=None):
    msla_argv = [progname]
    msla_argv += [_mslaopt_testudp, str(testudp)]
    msla_argv += [_mslaopt_source, str(dipaddr)]
    if period is not None:
        msla_argv += [_mslaopt_period, str(period)]
    if count is not None:
        msla_argv += [_mslaopt_count, str(count)]
    msla_argv += [_mslaopt_band, str(band)]
    msla_argv += [_mslaopt_port, str(port)]


    print("running " + " ".join(msla_argv))

    return subprocess.Popen(msla_argv, stdout=subprocess.PIPE)

def slas_mean_udpbandwidthmean( mslas):
    return int(sum(map(lambda x: x.bandwidthmean,  mslas)) / len( mslas))

def slas_mean_udpjitter( mslas):
    return int(sum(map(lambda x: x.jitter,  mslas)) / len( mslas))
 
def slas_mean_udperror( mslas):
    return int(sum(map(lambda x: x.error,  mslas)) / len( mslas))


def sla_tcp_AGENT_capability(ip4addr):
    cap = mplane.model.Capability(label="msla-TCP-AGENT-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ip4addr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("mSLA-AGENT-DESTINATION-ip4-TCP")
    return cap


def sla_udp_AGENT_capability(ip4addr):
    cap = mplane.model.Capability(label="msla-UDP-AGENT-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ip4addr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("mSLA-AGENT-DESTINATION-ip4-UDP")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.jitter")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.error") 
    return cap

"""
Implements mSLAcert Agent proxy for integration into 
the mPlane reference implementation.
(capability push, specification pull)

"""

class mSLAcert_Agent_Service(mplane.scheduler.Service):
    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or 
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or 
                 cap.has_parameter("destination.ip6")) and
                (cap.has_result_column("mSLA-AGENT-DESTINATION-ip4-TCP") or
                 cap.has_result_column("mSLA-AGENT-DESTINATION-ip4-UDP") or
                 cap.has_result_column("mSLA.udpCapacity.download.iperf.jitter") or                
                 cap.has_result_column("mSLA.udpCapacity.download.iperf.error"))):
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

        if spec.has_parameter("destination.ip4"):
            sipaddr = spec.get_parameter_value("source.ip4")
            dipaddr = spec.get_parameter_value("destination.ip4")
            msla_process = _msla4_process(sipaddr, dipaddr, period, count)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            msla_process = _msla6_process(sipaddr, dipaddr, period, count)
        else:
            raise ValueError("Missing destination")

        # read output from  msla
        mslas = []
        for line in  msla_process.stdout:
            if check_interrupt():
                break
            onemsla = _parse_msla_line(line.decode("utf-8"))
            if onemsla is not None:
                print(" msla "+repr(onemsla))
                mslas.append(onemsla)
 
        # shut down and reap
        try:
             msla_process.kill()
        except OSError:
            pass
        msla_process.wait()

        # derive a result from the specification
        res = mplane.model.Result(specification=spec)
        out_file = open("./UDPtest.txt","w")

        # put actual start and end time into result
        res.set_when(mplane.model.When(a = mslas_start_time(mslas), b = mslas_end_time(mslas)))

        # are we returning aggregates or raw numbers?
        if res.has_result_column("mSLA.udpCapacity.download.iperf"):
            # raw numbers
            for i, onemsla in enumerate(mslas):
                res.set_result_value("mSLA.udpCapacity.download.iperf", onemsla.bandwidth, i)
                out_file.write("mSLA.udpCapacity.download.iperf" + "    " + "UDP-Bandwidth=" + repr(onemsla.bandwidth) + "    " + repr(i) + '\n')
            if res.has_result_column("time"):
                for i, onemsla in enumerate(mslas):
                    res.set_result_value("time", onemsla.time, i)
                    out_file.write("time" + "    " + repr(onemsla.time) + "    " + repr(i) + '\n')
        else:
            # aggregates. single row.
            if res.has_result_column("mSLA.udpCapacity.download.iperf.min"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.min",  mslas_min_udpCapacity(mslas))
                out_file.write("mSLA.udpCapacity.download.iperf.min" + "    " + repr(mslas_min_udpCapacity( mslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.mean"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.mean",  mslas_mean_udpCapacity(mslas))
                out_file.write("mSLA.udpCapacity.download.iperf.mean" + "    " + repr( mslas_mean_udpCapacity(mslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.median"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.median",  mslas_median_udpCapacity(mslas))
                out_file.write("mSLA.udpCapacity.download.iperf.median" + "    " + repr(mslas_median_udpCapacity(mslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.max"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.max",  mslas_max_udpCapacity(mslas))
                out_file.write("mSLA.udpCapacity.download.iperf.max" + "    " + repr(mslas_max_udpCapacity(mslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.timecountseconds"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.timecountseconds", len(mslas))
                out_file.write("mSLA.udpCapacity.download.iperf.timecountseconds" + "    " + repr(len(mslas)) + '\n')
                #os.system("scp ./UDPtest.txt USER@Repository:/repository/temp/")
                out_file.close()
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
    svc = mSLAcert_Agent_Service(sla_tcp_AGENT_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = mSLAcert_Agent_Service(sla_udp_AGENT_capability(LOOP4))
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
        self.scheduler.add_service(mSLAcert_Agent_Service(sla_tcp_AGENT_capability(ip4addr)))
        self.scheduler.add_service(mSLAcert_Agent_Service(sla_udp_AGENT_capability(ip4addr)))
        
        
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
