#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
# mPlane Protocol Reference Implementation
# ICMP Ping probe component code
#
# (c) 2013-2014 mPlane Consortium (http://www.ict-mplane.eu)
#               Author: Brian Trammell <brian@trammell.ch>
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

"""
Implementation of mSLAcert probe (msla.downstream.iperf) 
for integration into the mPlane reference implementation.
"""

import re
import ipaddress
import threading
import subprocess
import collections
from datetime import datetime, timedelta
from ipaddress import ip_address
import mplane.model
import mplane.scheduler
import mplane.httpsrv
import tornado.web
import tornado.ioloop
import argparse

mslacertline_re = re.compile ("iperf_seq = ()")

"""
_pingline_re = re.compile("icmp_seq=(\d+)\s+\S+=(\d+)\s+time=([\d\.]+)\s+ms")
____________________________________________________________________________________________________
Ipef Command
----------------------------------------------------------------------------------------------------
iperf -c iperf-Server-IP-address -P 1 -i 1 -p 5001 -f k -t 30
iperf -c iperf-Server-IP-address -u -P 1 -i 1 -p 5002 -f k -t 30 -T 6 -b 1000m
_____________________________________________________________________________________________________
Iperf options
----------------------------------------------------------------------------------------------------
Usage: iperf [-s|-c host] [options]
       iperf [-h|--help] [-v|--version]

Client/Server:
  -f, --format    [kmKM]   format to report: Kbits, Mbits, KBytes, MBytes
  -i, --interval  #        seconds between periodic bandwidth reports
  -l, --len       #[KM]    length of buffer to read or write (default 8 KB)
  -m, --print_mss          print TCP maximum segment size (MTU - TCP/IP header)
  -o, --output    <filename> output the report or error message to this specified file
  -p, --port      #        server port to listen on/connect to
  -u, --udp                use UDP rather than TCP
  -w, --window    #[KM]    TCP window size (socket buffer size)
  -B, --bind      <host>   bind to <host>, an interface or multicast address
  -C, --compatibility      for use with older versions does not sent extra msgs
  -M, --mss       #        set TCP maximum segment size (MTU - 40 bytes)
  -N, --nodelay            set TCP no delay, disabling Nagle's Algorithm
  -V, --IPv6Version        Set the domain to IPv6

Server specific:
  -s, --server             run in server mode
  -U, --single_udp         run in single threaded UDP mode
  -D, --daemon             run the server as a daemon

Client specific:
  -b, --bandwidth #[KM]    for UDP, bandwidth to send at in bits/sec
                           (default 1 Mbit/sec, implies -u)
  -c, --client    <host>   run in client mode, connecting to <host>
  -d, --dualtest           Do a bidirectional test simultaneously
  -n, --num       #[KM]    number of bytes to transmit (instead of -t)
  -r, --tradeoff           Do a bidirectional test individually
  -t, --time      #        time in seconds to transmit for (default 10 secs)
  -F, --fileinput <name>   input the data to be transmitted from a file
  -I, --stdin              input the data to be transmitted from stdin
  -L, --listenport #       port to receive bidirectional tests back on
  -P, --parallel  #        number of parallel client threads to run
  -T, --ttl       #        time-to-live, for multicast (default 1)
  -Z, --linux-congestion <algo>  set TCP congestion control algorithm (Linux only)

Miscellaneous:
  -x, --reportexclude [CDMSV]   exclude C(connection) D(data) M(multicast) S(settings) V(server) reports
  -y, --reportstyle C      report as a Comma-Separated Values
  -h, --help               print this message and quit
  -v, --version            print version information and quit

[KM] Indicates options that support a K or M suffix for kilo- or mega-

The TCP window size option can be set by the environment variable
TCP_WINDOW_SIZE. Most other options can be set by an environment variable
IPERF_<long option name>, such as IPERF_BANDWIDTH.

Report bugs to <iperf-users@lists.sourceforge.net>
https://iperf.fr/
----------------------------------------------------------------------------------------------------------------------
"""
"""---------------------------TCP--------------------------------"""
_iperf4tcp_cmd = "iperf -P 1 -i 1 -p 5001 -f k -t 30 -c"
_iperf6tcp_cmd = "iperf -V -P 1 -i 1 -p 5001 -f k -t 30 -c"

"""---------------------------UDP--------------------------------"""
_iperf4udp_cmd = "iperf -u -P 1 -i 1 -p 5002 -f k -t 30 -T 6 -b 1000m -c"
_iperf6udp_cmd = "iperf -V -P 1 -i 1 -p 5002 -f k -t 30 -T 6 -b 1000m -c"

"""
_ping4cmd = "ping"
_ping6cmd = "ping6"
_pingopts = ["-n"]
_pingopt_period = "-i"
_pingopt_count = "-c"
_pingopt_source = "-S"
"""
"""TCP"""
_mslatcpopt_report = "-i"
_mslatcpopt_count = "-t"

"""UDP"""
_mslaudpopt_report = "-i"
_mslaudpopt_count = "-t"

LOOP4 = "127.0.0.1"
LOOP6 = "::1"

mslatcpvalue = collections.namedtuple("TCPvalue", ["ID","Interval","Transfer","Bandwidth"])
mslaudpvalue = collections.namedtuple("UDPvalue", ["ID","Interval","Transfer","Bandwidth"])
"""PingValue = collections.namedtuple("PingValue", ["time", "seq", "ttl", "usec"])"""

def _parse_slatcp_line(line):
	m = _mslacertline_re.search(line)
	if m is None:
		print(line)
		return None
	mg = m.groups()
	return mslatcpvalue(datetime.utcnow(), int(mg[0]), int(mg[1]), int(mg[2]), int(mg[3]))
	
def _parse_slaudp_line(line):
	m = _mslacertline_re.search(line)
	if m is None:
		print(line)
		return None
	mg = m.groups()
	return mslaudpvalue(datetime.utcnow(), int(mg[0]), int(mg[1]), int(mg[2]), int(mg[3]))
"""
def _parse_ping_line(line):
    m = _pingline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()
    return PingValue(datetime.utcnow(), int(mg[0]), int(mg[1]), int(float(mg[2]) * 1000))"""

	
def _mslatcp_process(progname, sipaddr, dipaddr, report=None, coun=None):
    mslatcp_argv = [progname]
    if report is not None:
        mslatcp_argv += [_mslatcpopt_report, str(period)]
    if count is not None:
        mslatcp_argv += [_mslatcpopt_count, str(count)]
    mslatcp_argv += [_pingopt_source, str(sipaddr)]
    mslatcp_argv += [str(dipaddr)]

    print("running " + " ".join(mslatcp_argv))

    return subprocess.Popen(mslatcp_argv, stdout=subprocess.PIPE)

def _mslaudp_process(progname, sipaddr, dipaddr, report=None, count=None):
    mslaudp_argv = [progname]
    if report is not None:
        mslaudp_argv += [_mslaudpopt_report, str(period)]
    if count is not None:
        mslaudp_argv += [_mslaudpopt_count, str(count)]

    mslaudp_argv += [_pingopt_source, str(sipaddr)]
    mslaudp_argv += [str(dipaddr)]

    print("running " + " ".join(mslaudp_argv))

    return subprocess.Popen(mslaudp_argv, stdout=subprocess.PIPE)
	
"""	
def _ping_process(progname, sipaddr, dipaddr, period=None, count=None): 
    ping_argv = [progname]
    if period is not None:
        ping_argv += [_pingopt_period, str(period)]
    if count is not None:
        ping_argv += [_pingopt_count, str(count)]
    ping_argv += [_pingopt_source, str(sipaddr)]
    ping_argv += [str(dipaddr)]

    print("running " + " ".join(ping_argv))

    return subprocess.Popen(ping_argv, stdout=subprocess.PIPE)"""

	
def _iperf4tcp_process(sipaddr, dipaddr, period=None, count=None):
    return _iperftcp_process(_iperf4tcp_cmd, sipaddr, dipaddr, period, count)
	
def _iperf6tcp_process(sipaddr, dipaddr, period=None, count=None):
    return _iperftcp_process(_iperf6tcp_cmd, sipaddr, dipaddr, period, count)

def _iperf4udp_process(sipaddr, dipaddr, period=None, count=None):
    return _iperfudp_process(_iperf4udp_cmd, sipaddr, dipaddr, period, count)
	
def _iperf6udp_process(sipaddr, dipaddr, period=None, count=None):
    return _iperfudp_process(_iperf6udp_cmd, sipaddr, dipaddr, period, count)
"""	
def _ping4_process(sipaddr, dipaddr, period=None, count=None):
    return _ping_process(_ping4cmd, sipaddr, dipaddr, period, count)

def _ping6_process(sipaddr, dipaddr, period=None, count=None):
    return _ping_process(_ping6cmd, sipaddr, dipaddr, period, count)"""


def mslacert_min_band(mslacert):
    return min(map(lambda x: x.usec, mslacert))
	

def mslacert_mean_band(mslacert):
    return int(sum(map(lambda x: x.usec, mslaudp)) / len(mslacert))
	

def mslacert_max_band(mslacert):
    return max(map(lambda x: x.usec, mslacert))

def mslacert_start_time(mslacert):
    return mslaudp[0].time

def mslacert_end_time(mslacert):
    return mslaudp[-1].time
"""
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
    return pings[-1].time"""
def msla4tcp_aggregate_capability (ipaddr):
	cap = mplane.model.Capability(label="mSLAcert-tcp-average-ip4", when ="now ... future / 1s")
	cap.add_parameter("source.ip4",ipaddr)
	cap.add_parameter("description.ip4")
	cap.add_result_column("value.downstream.iperf.us.min")
	cap.add_result_column("value.downstream.iperf.us.mean")
	cap.add_result_column("value.downstream.iperf.us.max")
	cap.add_result_column("value.downstream.iperf.us.count")
	return cap
def msla4tcp_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="mSLAcert-tcp-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("value.downstream.iperf.us")
    return cap
def msla4udp_aggregate_capability (ipaddr):
	cap = mplane.model.Capability(label="mSLAcert-udp-average-ip4", when ="now ... future / 1s")
	cap.add_parameter("source.ip4",ipaddr)
	cap.add_parameter("description.ip4")
	cap.add_result_column("value.downstream.iperf.us.min")
	cap.add_result_column("value.downstream.iperf.us.mean")
	cap.add_result_column("value.downstream.iperf.us.max")
	cap.add_result_column("value.downstream.iperf.us.count")
	return cap
def msla4udp_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="mSLAcert-udp-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("value.downstream.iperf.us")
    return cap
def msla6tcp_aggregate_capability (ipaddr):
	cap = mplane.model.Capability(label="mSLAcert-tcp-average-ip4", when ="now ... future / 1s")
	cap.add_parameter("source.ip4",ipaddr)
	cap.add_parameter("description.ip4")
	cap.add_result_column("value.downstream.iperf.us.min")
	cap.add_result_column("value.downstream.iperf.us.mean")
	cap.add_result_column("value.downstream.iperf.us.max")
	cap.add_result_column("value.downstream.iperf.us.count")
	return cap
def msla6tcp_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="mSLAcert-tcp-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("value.downstream.iperf.us")
    return cap
def msla6udp_aggregate_capability (ipaddr):
	cap = mplane.model.Capability(label="mSLAcert-udp-average-ip4", when ="now ... future / 1s")
	cap.add_parameter("source.ip4",ipaddr)
	cap.add_parameter("description.ip4")
	cap.add_result_column("value.downstream.iperf.us.min")
	cap.add_result_column("value.downstream.iperf.us.mean")
	cap.add_result_column("value.downstream.iperf.us.max")
	cap.add_result_column("value.downstream.iperf.us.count")
	return cap
def msla6udp_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="mSLAcert-udp-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("value.downstream.iperftcp.us")
    return cap
"""
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
"""

class mSLAcertService(mplane.scheduler.Service):

	def __init__(self, cap):
		# verify the capability is acceptable
		if not ((cap.has_parameter("source.ip4") or 
				cap.has_parameter("source.ip6")) and
				(cap.has_parameter("destination.ip4") or 
				cap.has_parameter("destination.ip6")) and
				(cap.has_result_column("value.downstream.iperf.us") or
				cap.has_result_column("value.downstream.iperf.us.min") or
				cap.has_result_column("value.downstream.iperf.us.mean") or                
				cap.has_result_column("value.downstream.iperf.us.max") or
				cap.has_result_column("value.downstream.iperf.count"))):
			raise ValueError("capability not acceptable")
		super(mSLAcertService, self).__init__(cap)

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
			iperf_process = _iperftcp_process(_iperf4tcp_cmd, sipaddr, dipaddr, period, count)
						
		elif spec.has_parameter("destination.ip6"):
			sipaddr = spec.get_parameter_value("source.ip6")
			dipaddr = spec.get_parameter_value("destination.ip6")
			iperf_process = _iperftcp_process(_iperf6tcp_cmd, sipaddr, dipaddr, period, count)
		else:
			raise ValueError("Missing destination, please insert you public address")

# read output from iperf
		mslacert = []
		for line in iperf_process.stdout:
			if check_interrupt():
				break
			oneiperf = _parse_iperf_line(line.decode("utf-8"))
			if oneiperf is not None:
				print("iperf "+repr(oneiperf))
				mslacert.append(oneiperf)

        # shut down and reap
		try:
			iperf_process.kill()
		except OSError:
			pass
		iperf_process.wait()

		# derive a result from the specification
		res = mplane.model.Result(specification=spec)

		# put actual start and end time into result
		res.set_when(mplane.model.When(a = mslacert_start_time(mslacert), b = mslacert_end_time(mslacert)))

		# are we returning aggregates or raw numbers?
		if res.has_result_column("value.downstream.iperf.us"):
			# raw numbers
			for i, oneiperf in enumerate(mslacert):
				res.set_result_value("value.downstream.iperf.us", oneiperf.usec, i)
			if res.has_result_column("time"):
				for i, oneiperf in enumerate(mslacert):
					res.set_result_value("time", oneiperf.time, i)
		else:
		# aggregates. single row.
			if res.has_result_column("value.downstream.iperf.us.min"):
				res.set_result_value("value.downstream.iperf.us.min", mslacert_min_delay(mslacert))
			if res.has_result_column("value.downstream.iperf.us.mean"):
				res.set_result_value("value.downstream.iperf.us.mean", mslacert_mean_delay(mslacert))
			if res.has_result_column("value.downstream.iperf.us.median"):
				res.set_result_value("value.downstream.iperf.us.median", mslacert_median_delay(mslacert))
			if res.has_result_column("value.downstream.iperf.us.max"):
				res.set_result_value("value.downstream.iperf.us.max", mslacert_max_delay(mslacert))
			if res.has_result_column("value.downstream.iperf.us.count"):
				res.set_result_value("value.downstream.iperf.us.count", len(mslacert))


		return res
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

        # put actual start and end time into result
        res.set_when(mplane.model.When(a = pings_start_time(pings), b = pings_end_time(pings)))

        # are we returning aggregates or raw numbers?
        if res.has_result_column("delay.twoway.icmp.us"):
            # raw numbers
            for i, oneping in enumerate(pings):
                res.set_result_value("delay.twoway.icmp.us", oneping.usec, i)
            if res.has_result_column("time"):
                for i, oneping in enumerate(pings):
                    res.set_result_value("time", oneping.time, i)
        else:
            # aggregates. single row.
            if res.has_result_column("delay.twoway.icmp.us.min"):
                res.set_result_value("delay.twoway.icmp.us.min", pings_min_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.mean"):
                res.set_result_value("delay.twoway.icmp.us.mean", pings_mean_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.median"):
                res.set_result_value("delay.twoway.icmp.us.median", pings_median_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.max"):
                res.set_result_value("delay.twoway.icmp.us.max", pings_max_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.count"):
                res.set_result_value("delay.twoway.icmp.us.count", len(pings))


        return res
"""

def parse_args():
	global args
	parser = argparse.ArgumentParser(description="Run an mPlane mSLAcert probe server")
	parser.add_argument('--ip4addr', '-4', metavar="source-v4-address",
						help="mSLAcert from the given IPv4 address")
	parser.add_argument('--ip6addr', '-6', metavar="source-v6-address",
						help="mSLAcert from the given IPv6 address")
	parser.add_argument('--sec', metavar="security-on-off",
						help="Toggle security on/off. Values: 0=on,1=off")
	parser.add_argument('--certfile', metavar="cert-file-location",
						help="Location of the configuration file for certificates")
	args = parser.parse_args()
"""
def parse_args():
    global args
    parser = argparse.ArgumentParser(description="Run an mPlane ping probe server")
    parser.add_argument('--ip4addr', '-4', metavar="source-v4-address",
                        help="Ping from the given IPv4 address")
    parser.add_argument('--ip6addr', '-6', metavar="source-v6-address",
                        help="Ping from the given IPv6 address")
    parser.add_argument('--sec', metavar="security-on-off",
                        help="Toggle security on/off. Values: 0=on,1=off")
    parser.add_argument('--certfile', metavar="cert-file-location",
                        help="Location of the configuration file for certificates")
    args = parser.parse_args()
"""

def manually_test_mslacert():
	svc = mSLAcertService(msla4_aggregate_capability(LOOP4))
	spec = mplane.model.Specification(capability=svc.capability())
	spec.set_parameter_value("destination.ip4", LOOP4)
	spec.set_when("now + 5s / 1s")

	res = svc.run(spec, lambda: False)
	print(repr(res))
	print(mplane.model.unparse_yaml(res))

	svc = mSLAcertService(msla4_singleton_capability(LOOP4))
	spec = mplane.model.Specification(capability=svc.capability())
	spec.set_parameter_value("destination.ip4", LOOP4)
	spec.set_when("now + 5s / 1s")

	res = svc.run(spec, lambda: False)
	print(repr(res))
	print(mplane.model.unparse_yaml(res))

	svc = mSLAcertService(msla6_aggregate_capability(LOOP6))
	spec = mplane.model.Specification(capability=svc.capability())
	spec.set_parameter_value("destination.ip6", LOOP6)
	spec.set_when("now + 5s / 1s")

	res = svc.run(spec, lambda: False)
	print(repr(res))
	print(mplane.model.unparse_yaml(res))

	svc = mSLAcertService(msla6_singleton_capability(LOOP6))
	spec = mplane.model.Specification(capability=svc.capability())
	spec.set_parameter_value("destination.ip6", LOOP6)
	spec.set_when("now + 5s / 1s")

	res = svc.run(spec, lambda: False)
	print(repr(res))
	print(mplane.model.unparse_yaml(res))
""""
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
"""
# For right now, start a Tornado-based ping server
if __name__ == "__main__":
	global args

	mplane.model.initialize_registry()
	parse_args()

	ip4addr = None
	ip6addr = None

	if args.ip4addr:
		ip4addr = ip_address(args.ip4addr)
		if ip4addr.version != 4:
			raise ValueError("invalid IPv4 address")
	if args.ip6addr:
		ip6addr = ip_address(args.ip6addr)
		if ip6addr.version != 6:
			raise ValueError("invalid IPv6 address")
	if ip4addr is None and ip6addr is None:
		raise ValueError("need at least one source address to run")

	if args.sec is None:
		raise ValueError("need --sec parameter (0=True,1=False)")
	else:
		if args.sec == '0':
			if args.certfile is None:
				raise ValueError("if --sec=0, need to specify cert file")
			else:
				security = True
				mplane.utils.check_file(args.certfile)
				certfile = args.certfile
		else:
			security = False
			certfile = None

	scheduler = mplane.scheduler.Scheduler(security)
	if ip4addr is not None:
		scheduler.add_service(mSLAcertService(msla4tcp_aggregate_capability(ip4addr)))
		scheduler.add_service(mSLAcertService(msla4tcp_singleton_capability(ip4addr)))
		scheduler.add_service(mSLAcertService(msla4udp_aggregate_capability(ip4addr)))
		scheduler.add_service(mSLAcertService(msla4udp_singleton_capability(ip4addr)))
	if ip6addr is not None:
		scheduler.add_service(mSLAcertService(msla6tcp_aggregate_capability(ip6addr)))
		scheduler.add_service(mSLAcertService(msla6tcp_singleton_capability(ip6addr)))
		scheduler.add_service(mSLAcertService(msla6udp_aggregate_capability(ip6addr)))
		scheduler.add_service(mSLAcertService(msla6udp_singleton_capability(ip6addr)))

	mplane.httpsrv.runloop(scheduler, security, certfile)
