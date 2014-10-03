#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
# mPlane Protocol Reference Implementation
# iperf tcpsla probe component code
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
Implements iperf tcpsla (tcpBandwidth.download.iperf) for integration into 
the mPlane reference implementation.

"""

import re
import os
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

_tcpslaline_re = re.compile("[+\s+\d+]\s+\d.+\d+-\s+(\d.+\d)\s+sec\s+(\d.+\d+)\s+MBytes\s+(\d+\d.+\d+)\s+Mbits/sec")

_tcpsla4cmd = "iperf"
_tcpsla6cmd = "iperf"
_tcpslaopts = ["-n"]
_tcpslaopt_period = "-i"
_tcpslaopt_count = "-t"
_tcpslaopt_source = "-c"

LOOP4 = "127.0.0.1"
LOOP6 = "::1"

tcpslaValue = collections.namedtuple("tcpslaValue", ["time", "interval", "transfer", "bandwidth"])

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
    cap.add_result_column("tcpBandwidth.download.iperf.us.min")
    cap.add_result_column("tcpBandwidth.download.iperf.us.mean")
    cap.add_result_column("tcpBandwidth.download.iperf.us.max")
    cap.add_result_column("tcpBandwidth.download.iperf.us.timecountseconds")
    return cap

def tcpsla4_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-detail-ip4", when = "now ... future / 1s")
    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")
    cap.add_result_column("time")
    cap.add_result_column("tcpBandwidth.download.iperf.us")
    return cap

def tcpsla6_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-average-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("tcpBandwidth.download.iperf.us.min")
    cap.add_result_column("tcpBandwidth.download.iperf.us.mean")
    cap.add_result_column("tcpBandwidth.download.iperf.us.max")
    cap.add_result_column("tcpBandwidth.download.iperf.us.timecountseconds")
    return cap

def tcpsla6_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="tcpsla-detail-ip6", when = "now ... future / 1s")
    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")
    cap.add_result_column("time")
    cap.add_result_column("tcpBandwidth.download.iperf.us")
    return cap

class tcpslaService(mplane.scheduler.Service):
    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or 
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or 
                 cap.has_parameter("destination.ip6")) and
                (cap.has_result_column("tcpBandwidth.download.iperf.us") or
                 cap.has_result_column("tcpBandwidth.download.iperf.us.min") or
                 cap.has_result_column("tcpBandwidth.download.iperf.us.mean") or                
                 cap.has_result_column("tcpBandwidth.download.iperf.us.max") or
                 cap.has_result_column("tcpBandwidth.download.iperf.us.timecountseconds"))):
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

        # put actual start and end time into result
        res.set_when(mplane.model.When(a = tcpslas_start_time(tcpslas), b = tcpslas_end_time(tcpslas)))

        # are we returning aggregates or raw numbers?
        if res.has_result_column("tcpBandwidth.download.iperf.us"):
            # raw numbers
            for i, onetcpsla in enumerate(tcpslas):
                res.set_result_value("tcpBandwidth.download.iperf.us", onetcpsla.bandwidth, i)
            if res.has_result_column("time"):
                for i, onetcpsla in enumerate(tcpslas):
                    res.set_result_value("time", onetcpsla.time, i)
        else:
            # aggregates. single row.
            if res.has_result_column("tcpBandwidth.download.iperf.us.min"):
                res.set_result_value("tcpBandwidth.download.iperf.us.min", tcpslas_min_tcpBandwidth(tcpslas))
            if res.has_result_column("tcpBandwidth.download.iperf.us.mean"):
                res.set_result_value("tcpBandwidth.download.iperf.us.mean", tcpslas_mean_tcpBandwidth(tcpslas))
            if res.has_result_column("tcpBandwidth.download.iperf.us.median"):
                res.set_result_value("tcpBandwidth.download.iperf.us.median", tcpslas_median_tcpBandwidth(tcpslas))
            if res.has_result_column("tcpBandwidth.download.iperf.us.max"):
                res.set_result_value("tcpBandwidth.download.iperf.us.max", tcpslas_max_tcpBandwidth(tcpslas))
            if res.has_result_column("tcpBandwidth.download.iperf.us.timecountseconds"):
                res.set_result_value("tcpBandwidth.download.iperf.us.timecountseconds", len(tcpslas))


        return res

def parse_args():
    global args
    parser = argparse.ArgumentParser(description="Run an mPlane tcpsla probe server")
    parser.add_argument('--ip4addr', '-4', metavar="source-v4-address",
                        help="tcpsla from the given IPv4 address")
    parser.add_argument('--ip6addr', '-6', metavar="source-v6-address",
                        help="tcpsla from the given IPv6 address")
    parser.add_argument('--sec', metavar="security-on-off",
                        help="Toggle security on/off. Values: 0=on,1=off")
    parser.add_argument('--certfile', metavar="cert-file-location",
                        help="Location of the configuration file for certificates")
    args = parser.parse_args()

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

# For right now, start a Tornado-based tcpsla server
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
        scheduler.add_service(tcpslaService(tcpsla4_aggregate_capability(ip4addr)))
        scheduler.add_service(tcpslaService(tcpsla4_singleton_capability(ip4addr)))
    if ip6addr is not None:
        scheduler.add_service(tcpslaService(tcpsla6_aggregate_capability(ip6addr)))
        scheduler.add_service(tcpslaService(tcpsla6_singleton_capability(ip6addr)))

    mplane.httpsrv.runloop(scheduler, security, certfile)
