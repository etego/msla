# mPlane Protocol Reference Implementation
#
# (c) 2013-2014 mPlane Consortium (http://www.ict-mplane.eu)
#				Author: Edion TEGO
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
#

import threading
from datetime import datetime
import time
from time import sleep
import mplane.model
import mplane.scheduler
import mplane.utils
from urllib3 import HTTPSConnectionPool
from urllib3 import HTTPConnectionPool
import argparse
import sys
import re
import json
import ipaddress
import threading
import subprocess
import collections
from datetime import datetime, timedelta
from ipaddress import ip_address
import tornado.web
import tornado.ioloop


DEFAULT_IP4_NET = "127.0.0.1/24"
DEFAULT_SUPERVISOR_IP4 = '127.0.0.1'
DEFAULT_SUPERVISOR_PORT = 8888
REGISTRATION_PATH = "register/capability"
SPECIFICATION_PATH = "show/specification"
RESULT_PATH = "register/result"
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
print("    ###$$$$$$$|Politecnico di Torino|Fondazione Ugo Bordoni| SSB Progetti| Telecom Italia|&$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$---------------------&----------------------&-------------&---------------$$$$$$$$$$$$$$$$$$$$##");
print("    ##$$$$________________________&_______&_________________&_______________$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$|Alcatel-Lucent Bell Labs|EURECOM| Telecom Paritech| NEC Europe LTD| $$$$$$$$$$$$$$$$$$$$$$$$&&&&&$$##");
print("    ###$$$------------------------&-------&-----------------&---------------$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ##$$________________________________________&________&_____________________________________________$$$$$$##");
print("    ###|Telefonica Investigacion Y Desarrollo Sa|Netvisor|Forschungszentrum Telekommunikation Wien Gmbh|$$$$$##");
print("    ###$----------------------------------------&--------&---------------------------------------------$$$$$$##");
print("    ##$$$$$$$$_______________________&____________________&_____________________________________________$$$$$##");
print("    ##$$$$$$$|Fachhochschule Augsburg||Universite de Liege|Eidgenoessische Technische Hochschule Zurich |$$$$##");
print("    ###$$$$$$$-----------------------&--------------------&---------------------------------------------$$$$$##");
print("    ###$$$$$$$$$$$$$$$$$$$$$$$______________________&_______$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$$$$$$$$$$$$$$$|Alcatel-Lucent Bell Nv|FASTWEB|$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$#");
print("    ###$$$$$$$$$$$$$$$$$$$$$$$----------------------&-------$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##");
print("    ###$$$$$$$$$| mSLAcert probe| RTT, TCP throughput and UDP throughput verification and certification|$$$$$##");
print("    ###########################################################################################################");

_pingline_re = re.compile("icmp_seq=(\d+)\s+\S+=(\d+)\s+time=([\d\.]+)\s+ms")

_ping4cmd = "ping"
_ping6cmd = "ping6"
_pingopts = ["-n"]
_pingopt_period = "-i"
_pingopt_count = "-c"
_pingopt_source = "-S"

LOOP4 = "127.0.0.1"
LOOP6 = "::1"

PingValue = collections.namedtuple("PingValue", ["time", "seq", "ttl", "usec"])

_tcpslaline_re = re.compile("[+\s+\d+]\s+\d.+\d+-\s+(\d.+\d)\s+sec\s+(\d.+\d+)\s+MBytes\s+(\d+\d.+\d+)\s+Mbits/sec")

_tcpsla4cmd = "iperf"
_tcpsla6cmd = "iperf"
_tcpslaopts = ["-n"]
_tcpslaopt_period = "-i"
_tcpslaopt_count = "-t"
_tcpslaopt_source = "-c"

tcpslaValue = collections.namedtuple("tcpslaValue", ["time", "interval", "transfer", "bandwidth"])

_udpslaline_re = re.compile("[+\s+\d+]\s+\d.+\d+-\s+(\d.+\d)\s+sec\s+(\d.+\d+)\s+MBytes\s+(\d+\d.+\d+)\s+Mbits/sec")

_udpsla4cmd = "iperf"
_udpsla6cmd = "iperf"
_udpslaopts = ["-n"]
_udpslaopt_period = "-i"
_udpslaopt_count = "-t"
_udpslaopt_source = "-c"
_udpslaopt_band = "-b 1000m"
_udpslaopt_port = "-p 5002"
_udpslaopt_testudp = "-u"


udpslaValue = collections.namedtuple("udpslaValue", ["time", "interval", "transfer", "bandwidth"])

def _parse_ping_line(line):
    m = _pingline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()
    return PingValue(datetime.utcnow(), int(mg[0]), int(mg[1]), int(float(mg[2]) * 1000))

def _ping_process(progname, sipaddr, dipaddr, period=None, count=None):
    ping_argv = [progname]
    if period is not None:
        ping_argv += [_pingopt_period, str(period)]
    if count is not None:
        ping_argv += [_pingopt_count, str(count)]
    ping_argv += [_pingopt_source, str(sipaddr)]
    ping_argv += [str(dipaddr)]

    print("running " + " ".join(ping_argv))

    return subprocess.Popen(ping_argv, stdout=subprocess.PIPE)

def _ping4_process(sipaddr, dipaddr, period=None, count=None):
    return _ping_process(_ping4cmd, sipaddr, dipaddr, period, count)

def _ping6_process(sipaddr, dipaddr, period=None, count=None):
    return _ping_process(_ping6cmd, sipaddr, dipaddr, period, count)

def pings_min_delay(pings):
    return min(map(lambda x: x.usec, pings))

def pings_mean_delay(pings):
    return int(sum(map(lambda x: x.usec, pings)) / len(pings))

def pings_median_delay(pings):
    return sorted(map(lambda x: x.usec, pings))[int(len(pings) / 2)]

def pings_max_delay(pings):
    return max(map(lambda x: x.usec, pings))

def pings_start_time(pings):
    return pings[0].time

def pings_end_time(pings):
    return pings[-1].time

def ping4_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="ping-average-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("delay.twoway.icmp.us.min")
    cap.add_result_column("delay.twoway.icmp.us.mean")
    cap.add_result_column("delay.twoway.icmp.us.max")
    cap.add_result_column("delay.twoway.icmp.us.count")
    return cap

def ping4_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="ping-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("delay.twoway.icmp.us")
    return cap

def ping6_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="ping-average-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("delay.twoway.icmp.us.min")
    cap.add_result_column("delay.twoway.icmp.us.mean")
    cap.add_result_column("delay.twoway.icmp.us.max")
    cap.add_result_column("delay.twoway.icmp.us.count")
    return cap

def ping6_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="ping-detail-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("time")
    cap.add_result_column("delay.twoway.icmp.us")
    return cap

def _parse_tcpsla_line(line):
    m = _tcpslaline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()
    return tcpslaValue(datetime.utcnow(), int(float(mg[0])), int(float(mg[1])), int(float(mg[2])))

def _tcpsla_process(progname, sipaddr, dipaddr, period=None, count=None):
    tcpsla_argv = [progname]
    if period is not None:
        tcpsla_argv += [_tcpslaopt_period, str(period)]
    if count is not None:
        tcpsla_argv += [_tcpslaopt_count, str(count)]
    tcpsla_argv += [_tcpslaopt_source, str(dipaddr)]
    tcpsla_argv += [str(sipaddr)]

    print("running " + " ".join(tcpsla_argv))

    return subprocess.Popen(tcpsla_argv, stdout=subprocess.PIPE)

def _tcpsla4_process(sipaddr, dipaddr, period=None, count=None):
    return _tcpsla_process(_tcpsla4cmd, sipaddr, dipaddr, period, count)

def _tcpsla6_process(sipaddr, dipaddr, period=None, count=None):
    return _tcpsla_process(_tcpsla6cmd, sipaddr, dipaddr, period, count)

def tcpslas_min_tcpBandwidth(tcpslas):
    return min(map(lambda x: x.bandwidth, tcpslas))

def tcpslas_mean_tcpBandwidth(tcpslas):
    return int(sum(map(lambda x: x.bandwidth, tcpslas)) / len(tcpslas))

def tcpslas_median_tcpBandwidth(tcpslas):
    return sorted(map(lambda x: x.bandwidth, tcpslas))[int(len(tcpslas) / 2)]

def tcpslas_max_tcpBandwidth(tcpslas):
    return max(map(lambda x: x.bandwidth, tcpslas))

def tcpslas_start_time(tcpslas):
    return tcpslas[0].time

def tcpslas_end_time(tcpslas):
    return tcpslas[-1].time

def tcpsla4_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-average-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.min")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.mean")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.max")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.timecountseconds")
    return cap

def tcpsla4_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf")
    return cap

def tcpsla6_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-average-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.min")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.mean")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.max")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.timecountseconds")
    return cap

def tcpsla6_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-detail-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("time")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf")
    return cap
    

def _parse_udpsla_line(line):
    m = _udpslaline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()

    return udpslaValue(datetime.utcnow(), int(float(mg[0])), int(float(mg[1])), int(float(mg[2])))

def _udpsla_process(progname, sipaddr, dipaddr, period=None, count=None, testudp=None, band=None, port=None):
    udpsla_argv = [progname]
    udpsla_argv += [_udpslaopt_testudp, str(testudp)]
    udpsla_argv += [_udpslaopt_source, str(dipaddr)]
    if period is not None:
        udpsla_argv += [_udpslaopt_period, str(period)]
    if count is not None:
        udpsla_argv += [_udpslaopt_count, str(count)]
    udpsla_argv += [_udpslaopt_band, str(band)]
    udpsla_argv += [_udpslaopt_port, str(port)]


    print("running " + " ".join(udpsla_argv))

    return subprocess.Popen(udpsla_argv, stdout=subprocess.PIPE)

def _udpsla4_process(sipaddr, dipaddr, period=None, count=None, testudp=None, band=None, port=None):
    return _udpsla_process(_udpsla4cmd, testudp, dipaddr, period, count, band, port)

def _udpsla6_process(sipaddr, dipaddr, period=None, count=None, testudp=None, band=None, port=None):
    return _udpsla_process(_udpsla6cmd, testudp, dipaddr, period, count, band, port)

def udpslas_min_udpCapacity(udpslas):
    return min(map(lambda x: x.bandwidth, udpslas))

def udpslas_mean_udpCapacity(udpslas):
    return int(sum(map(lambda x: x.bandwidth, udpslas)) / len(udpslas))

def udpslas_median_udpCapacity(udpslas):
    return sorted(map(lambda x: x.bandwidth, udpslas))[int(len(udpslas) / 2)]

def udpslas_max_udpCapacity(udpslas):
    return max(map(lambda x: x.bandwidth, udpslas))

def udpslas_start_time(udpslas):
    return udpslas[0].time

def udpslas_end_time(udpslas):
    return udpslas[-1].time

def udpsla4_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="udpsla-average-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.min")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.mean")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.max")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.timecountseconds")
    return cap

def udpsla4_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="udpsla-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("delay.twoway.icmp.us")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf")
    cap.add_result_column("mSLA.udpCapacity.download.iperf")
    return cap

def udpsla6_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="udpsla-average-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.min")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.mean")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.max")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.timecountseconds")
    return cap

def udpsla6_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="udpsla-detail-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("time")
    cap.add_result_column("delay.twoway.icmp.us")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf")
    cap.add_result_column("mSLA.udpCapacity.download.iperf")
    return cap

#definition of SLA field keys
"""   
def msla4_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="msla-average-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("delay.twoway.icmp.us.min")
    cap.add_result_column("delay.twoway.icmp.us.mean")
    cap.add_result_column("delay.twoway.icmp.us.max")
    cap.add_result_column("delay.twoway.icmp.us.count")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.min")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.mean")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.max")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.timecountseconds")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.min")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.mean")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.max")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.timecountseconds")
    return cap

def msla4_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="msla-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("mSLA.udpCapacity.download.iperf")
    return cap

def msla6_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="msla-average-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("delay.twoway.icmp.us.min")
    cap.add_result_column("delay.twoway.icmp.us.mean")
    cap.add_result_column("delay.twoway.icmp.us.max")
    cap.add_result_column("delay.twoway.icmp.us.count")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.min")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.mean")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.max")
    cap.add_result_column("mSLA.tcpBandwidth.download.iperf.timecountseconds")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.min")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.mean")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.max")
    cap.add_result_column("mSLA.udpCapacity.download.iperf.timecountseconds")
    return cap

def msla6_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="msla-detail-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("time")
    cap.add_result_column("mSLA.udpCapacity.download.iperf")
    return cap

(capability push, specification pull)

"""
        
class PingService(mplane.scheduler.Service):
    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or 
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or 
                 cap.has_parameter("destination.ip6")) and
                (cap.has_result_column("delay.twoway.icmp.us") or
                 cap.has_result_column("delay.twoway.icmp.us.min") or
                 cap.has_result_column("delay.twoway.icmp.us.mean") or                
                 cap.has_result_column("delay.twoway.icmp.us.max") or
                 cap.has_result_column("delay.twoway.icmp.us.count"))):
            raise ValueError("capability not acceptable")
        super(PingService, self).__init__(cap)

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
            ping_process = _ping4_process(sipaddr, dipaddr, period, count)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            ping_process = _ping6_process(sipaddr, dipaddr, period, count)
        else:
            raise ValueError("Missing destination")

        # read output from ping
        pings = []
        for line in ping_process.stdout:
            if check_interrupt():
                break
            oneping = _parse_ping_line(line.decode("utf-8"))
            if oneping is not None:
                print("ping "+repr(oneping))
                pings.append(oneping)
 
        # shut down and reap
        try:
            ping_process.kill()
        except OSError:
            pass
        ping_process.wait()

        # derive a result from the specification
        res = mplane.model.Result(specification=spec)
        out_file = open("./pingtest.txt","w")
        # put actual start and end time into result
        res.set_when(mplane.model.When(a = pings_start_time(pings), b = pings_end_time(pings)))

        # are we returning aggregates or raw numbers?
        if res.has_result_column("delay.twoway.icmp.us"):
            # raw numbers
            for i, oneping in enumerate(pings):
                res.set_result_value("delay.twoway.icmp.us", oneping.usec, i)
                out_file.write("microsec.delay.twoway.icmp" + "    " + "usec=" + repr(oneping.usec) + "    " + repr(i) + '\n')
            if res.has_result_column("time"):
                for i, oneping in enumerate(pings):
                    res.set_result_value("time", oneping.time, i)
                    out_file.write("time" + "    " + "usec=" + repr(oneping.time) + "    " + repr(i) + '\n')
        else:
            # aggregates. single row.
            if res.has_result_column("delay.twoway.icmp.us.min"):
                res.set_result_value("delay.twoway.icmp.us.min", pings_min_delay(pings))
                out_file.write("microsec.delay.twoway.icmp.min" + "    " + repr(pings_min_delay(pings)) + '\n')
            if res.has_result_column("delay.twoway.icmp.us.mean"):
                res.set_result_value("delay.twoway.icmp.us.mean", pings_mean_delay(pings))
                out_file.write("microsec.delay.twoway.icmp.mean" + "    " + repr(pings_mean_delay(pings)) + '\n')
            if res.has_result_column("delay.twoway.icmp.us.median"):
                res.set_result_value("delay.twoway.icmp.us.median", pings_median_delay(pings))
                out_file.write("microsec.delay.twoway.icmp.median" + "    " + repr(pings_median_delay(pings)) + '\n')
            if res.has_result_column("delay.twoway.icmp.us.max"):
                res.set_result_value("delay.twoway.icmp.us.max", pings_max_delay(pings))
                out_file.write("microsec.delay.twoway.icmp.max" + "    " + repr(pings_max_delay(pings)) + '\n')
            if res.has_result_column("delay.twoway.icmp.us.count"):
                res.set_result_value("delay.twoway.icmp.us.count", len(pings))
                out_file.write("microsec.delay.twoway.icmp.count" + "    " + repr(len(pings)) + '\n')
                
                out_file.close()
                #os.system("scp ./pingtest.txt USER@Repository:/repository/temp/")
        return res
        
class tcpslaService(mplane.scheduler.Service):
    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or 
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or 
                 cap.has_parameter("destination.ip6")) and
                (cap.has_result_column("mSLA.tcpBandwidth.download.iperf") or
                 cap.has_result_column("mSLA.tcpBandwidth.download.iperf.min") or
                 cap.has_result_column("mSLA.tcpBandwidth.download.iperf.mean") or                
                 cap.has_result_column("mSLA.tcpBandwidth.download.iperf.max") or
                 cap.has_result_column("mSLA.tcpBandwidth.download.iperf.timecountseconds"))):
            raise ValueError("capability not acceptable")
        super(tcpslaService, self).__init__(cap)

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
            tcpsla_process = _tcpsla4_process(sipaddr, dipaddr, period, count)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            tcpsla_process = _tcpsla6_process(sipaddr, dipaddr, period, count)
        else:
            raise ValueError("Missing destination")

        # read output from tcpsla
        tcpslas = []
        for line in tcpsla_process.stdout:
            if check_interrupt():
                break
            onetcpsla = _parse_tcpsla_line(line.decode("utf-8"))
            if onetcpsla is not None:
                print("tcpsla "+repr(onetcpsla))
                tcpslas.append(onetcpsla)
 
        # shut down and reap
        try:
            tcpsla_process.kill()
        except OSError:
            pass
        tcpsla_process.wait()

        # derive a result from the specification
        res = mplane.model.Result(specification=spec)
        out_file = open("./TCPtest.txt","w")
        # put actual start and end time into result
        res.set_when(mplane.model.When(a = tcpslas_start_time(tcpslas), b = tcpslas_end_time(tcpslas)))

        # are we returning aggregates or raw numbers?
        if res.has_result_column("mSLA.tcpBandwidth.download.iperf"):
            # raw numbers
            for i, onetcpsla in enumerate(tcpslas):
                res.set_result_value("mSLA.tcpBandwidth.download.iperf", onetcpsla.bandwidth, i)
                out_file.write("mSLA.tcpBandwidth.download.iperf" + "    " + "TCP-Bandwidth=" + repr(onetcpsla.bandwidth) + "    " + repr(i) + '\n')
            if res.has_result_column("time"):
                for i, onetcpsla in enumerate(tcpslas):
                    res.set_result_value("time", onetcpsla.time, i)
                    out_file.write("time" + "    " + repr(onetcpsla.time) + "    " + repr(i) + '\n')
        else:
            # aggregates. single row.
            if res.has_result_column("mSLA.tcpBandwidth.download.iperf.min"):
                res.set_result_value("mSLA.tcpBandwidth.download.iperf.min", tcpslas_min_tcpBandwidth(tcpslas))
                out_file.write("mSLA.tcpBandwidth.download.iperf.min" + "    " + repr(tcpslas_min_tcpBandwidth(tcpslas)) + '\n')
            if res.has_result_column("mSLA.tcpBandwidth.download.iperf.mean"):
                res.set_result_value("mSLA.tcpBandwidth.download.iperf.mean", tcpslas_mean_tcpBandwidth(tcpslas))
                out_file.write("mSLA.tcpBandwidth.download.iperf.mean" + "    " + repr(tcpslas_mean_tcpBandwidth(tcpslas)) + '\n')
            if res.has_result_column("mSLA.tcpBandwidth.download.iperf.median"):
                res.set_result_value("mSLA.tcpBandwidth.download.iperf.median", tcpslas_median_tcpBandwidth(tcpslas))
                out_file.write("mSLA.tcpBandwidth.download.iperf.median" + "    " + repr(tcpslas_median_tcpBandwidth(tcpslas)) + '\n')
            if res.has_result_column("mSLA.tcpBandwidth.download.iperf.max"):
                res.set_result_value("mSLA.tcpBandwidth.download.iperf.max", tcpslas_max_tcpBandwidth(tcpslas))
                out_file.write("mSLA.tcpBandwidth.download.iperf.max" + "    " + repr(tcpslas_max_tcpBandwidth(tcpslas)) + '\n')
            if res.has_result_column("mSLA.tcpBandwidth.download.iperf.timecountseconds"):
                res.set_result_value("mSLA.tcpBandwidth.download.iperf.timecountseconds", len(tcpslas))
                out_file.write("mSLA.tcpBandwidth.download.iperf.timecountseconds" + "    " + repr(len(tcpslas)) + '\n')
                #os.system("scp ./TCPtest.txt USER@Repository:/repository/temp/")
                out_file.close()
        return res
        
class udpslaService(mplane.scheduler.Service):
    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or 
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or 
                 cap.has_parameter("destination.ip6")) and
                (cap.has_result_column("mSLA.udpCapacity.download.iperf") or
                 cap.has_result_column("mSLA.udpCapacity.download.iperf.min") or
                 cap.has_result_column("mSLA.udpCapacity.download.iperf.mean") or                
                 cap.has_result_column("mSLA.udpCapacity.download.iperf.max") or
                 cap.has_result_column("mSLA.udpCapacity.download.iperf.timecountseconds"))):
            raise ValueError("capability not acceptable")
        super(udpslaService, self).__init__(cap)

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
            udpsla_process = _udpsla4_process(sipaddr, dipaddr, period, count)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            udpsla_process = _udpsla6_process(sipaddr, dipaddr, period, count)
        else:
            raise ValueError("Missing destination")

        # read output from udpsla
        udpslas = []
        for line in udpsla_process.stdout:
            if check_interrupt():
                break
            oneudpsla = _parse_udpsla_line(line.decode("utf-8"))
            if oneudpsla is not None:
                print("udpsla "+repr(oneudpsla))
                udpslas.append(oneudpsla)
 
        # shut down and reap
        try:
            udpsla_process.kill()
        except OSError:
            pass
        udpsla_process.wait()

        # derive a result from the specification
        res = mplane.model.Result(specification=spec)
        out_file = open("./UDPtest.txt","w")

        # put actual start and end time into result
        res.set_when(mplane.model.When(a = udpslas_start_time(udpslas), b = udpslas_end_time(udpslas)))

        # are we returning aggregates or raw numbers?
        if res.has_result_column("mSLA.udpCapacity.download.iperf"):
            # raw numbers
            for i, oneudpsla in enumerate(udpslas):
                res.set_result_value("mSLA.udpCapacity.download.iperf", oneudpsla.bandwidth, i)
                out_file.write("mSLA.udpCapacity.download.iperf" + "    " + "UDP-Bandwidth=" + repr(oneudpsla.bandwidth) + "    " + repr(i) + '\n')
            if res.has_result_column("time"):
                for i, oneudpsla in enumerate(udpslas):
                    res.set_result_value("time", oneudpsla.time, i)
                    out_file.write("time" + "    " + repr(oneudsla.time) + "    " + repr(i) + '\n')
        else:
            # aggregates. single row.
            if res.has_result_column("mSLA.udpCapacity.download.iperf.min"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.min", udpslas_min_udpCapacity(udpslas))
                out_file.write("mSLA.udpCapacity.download.iperf.min" + "    " + repr(udpslas_min_udpCapacity(udpslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.mean"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.mean", udpslas_mean_udpCapacity(udpslas))
                out_file.write("mSLA.udpCapacity.download.iperf.mean" + "    " + repr(udpslas_mean_udpCapacity(udpslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.median"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.median", udpslas_median_udpCapacity(udpslas))
                out_file.write("mSLA.udpCapacity.download.iperf.median" + "    " + repr(udpslas_median_udpCapacity(udpslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.max"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.max", udpslas_max_udpCapacity(udpslas))
                out_file.write("mSLA.udpCapacity.download.iperf.max" + "    " + repr(udpslas_max_udpCapacity(udpslas)) + '\n')
            if res.has_result_column("mSLA.udpCapacity.download.iperf.timecountseconds"):
                res.set_result_value("mSLA.udpCapacity.download.iperf.timecountseconds", len(udpslas))
                out_file.write("mSLA.udpCapacity.download.iperf.timecountseconds" + "    " + repr(len(udpslas)) + '\n')
                #os.system("scp ./UDPtest.txt USER@Repository:/repository/temp/")
                out_file.close()
        return res



def parse_args():
    global args
    parser = argparse.ArgumentParser(description="Run an mPlane mSLAcert probe server")
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
    parser.add_argument('--disable-sec', action='store_true', default=False, dest='DISABLE_SEC',
                        help='Disable secure communication')
    parser.add_argument('-c', '--certfile', metavar="path-of-cert-file", dest='CERTFILE', default = None,
                        help="Location of the configuration file for certificates")
    args = parser.parse_args()

def manually_test_ping():
    svc = PingService(ping4_aggregate_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = PingService(ping4_singleton_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = PingService(ping6_aggregate_capability(LOOP6))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip6", LOOP6)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = PingService(ping6_singleton_capability(LOOP6))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip6", LOOP6)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))
	

def manually_test_udpsla():
    svc = udpslaService(udpsla4_aggregate_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = udpslaService(udpsla4_singleton_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = udpslaService(udpsla6_aggregate_capability(LOOP6))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip6", LOOP6)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = udpslaService(udpsla6_singleton_capability(LOOP6))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip6", LOOP6)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))


def manually_test_tcpsla():
    svc = tcpslaService(tcpsla4_aggregate_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = tcpslaService(tcpsla4_singleton_capability(LOOP4))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip4", LOOP4)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = tcpslaService(tcpsla6_aggregate_capability(LOOP6))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip6", LOOP6)
    spec.set_when("now + 5s / 1s")

    res = svc.run(spec, lambda: False)
    print(repr(res))
    print(mplane.model.unparse_yaml(res))

    svc = tcpslaService(tcpsla6_singleton_capability(LOOP6))
    spec = mplane.model.Specification(capability=svc.capability())
    spec.set_parameter_value("destination.ip6", LOOP6)
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
        ip4addr = None
        ip6addr = None  
        # check if security is enabled, if so read certificate files
        #security = not args.DISABLE_SEC
        security = False
        if security:
            mplane.utils.check_file(args.CERTFILE)
            cert = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "cert"))
            key = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "key"))
            ca = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "ca-chain"))
            mplane.utils.check_file(cert)
            mplane.utils.check_file(key)
            mplane.utils.check_file(ca)
            self.pool = HTTPSConnectionPool(args.SUPERVISOR_IP4, args.SUPERVISOR_PORT, key_file=key, cert_file=cert, ca_certs=ca)
        else: 
            self.pool = HTTPConnectionPool(args.SUPERVISOR_IP4, args.SUPERVISOR_PORT)
         
        # generate a Service for each capability
        self.immediate_ms = immediate_ms
        self.scheduler = mplane.scheduler.Scheduler()
        self.scheduler.add_service(PingService(ping4_aggregate_capability(ip4addr)))
        self.scheduler.add_service(PingService(ping4_singleton_capability(ip4addr)))
        self.scheduler.add_service(PingService(ping6_aggregate_capability(ip6addr)))
        self.scheduler.add_service(PingService(ping6_singleton_capability(ip6addr)))
        self.scheduler.add_service(tcpslaService(tcpsla4_aggregate_capability(ip4addr)))
        self.scheduler.add_service(tcpslaService(tcpsla4_singleton_capability(ip4addr)))
        self.scheduler.add_service(tcpslaService(tcpsla6_aggregate_capability(ip6addr)))
        self.scheduler.add_service(tcpslaService(tcpsla6_singleton_capability(ip6addr)))
        self.scheduler.add_service(udpslaService(udpsla4_aggregate_capability(ip4addr)))
        self.scheduler.add_service(udpslaService(udpsla4_singleton_capability(ip4addr)))
        self.scheduler.add_service(udpslaService(udpsla6_aggregate_capability(ip6addr)))
        self.scheduler.add_service(udpslaService(udpsla6_singleton_capability(ip6addr)))

          
    def register_to_supervisor(self):
        """
        Sends a list of capabilities to the Supervisor, in order to register them
        
        """
        url = "/" + REGISTRATION_PATH
        print ("URL: %s" % url)
        
        # generate the capability list
        caps_list = ""
        for key in self.scheduler.capability_keys():  
            cap = self.scheduler.capability_for_key(key)
            caps_list = caps_list + mplane.model.unparse_json(cap) + ","
        caps_list = "[" + caps_list[:-1].replace("\n","") + "]"
        connected = False
        
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
                reply = self.scheduler.receive_message(spec)
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
