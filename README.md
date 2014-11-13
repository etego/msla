### How to run mplane architecture with msla probe.
________________________________________________________________________________________________________________________________________________________________________________________
1. Requisites:
        1. Python version >=3
        2. Yalm, Tornado
        3. Iperf, you need to have it installed on two different PCs
        4. Minimum two linux PCs, (it can also be applyed all on the same PC, there are needed a few changes on the probe)

________________________________________________________________________________________________________________________________________________________________________________________
2. Install, Yalm, Iperf and Tornado
     1. sudo apt-get install iperf
     2. apt-get install python3-yaml
     3. apt-get install python3-tornado
     4. Download mSLAcert_2.0.1 files
     5. Configure the configuration file for the certificates .conf/component-certs.conf and ./conf/supervisor-certs.conf, also .conf/client-certs.conf, if you will be using the client.
        --You can either use the certificated that are on the PKI folder, or generate new one (Personaly i had an error with ssl so i had to disable security)
______________________________________________________________________________________________________________________________________________________________________________________  
3. The scenario is the sequent one:

               ___________________________________________________________________
              |  _______                      ___                       _______   |                                              ______
              | | PC 1  |____________________/   \_____________________| PC 2  |__|_____________________________________________| PC 3 |
              | |Sprvs  |-------------------(Ntwrk)--------------------|Probe  |_>_>_>_>_Download_>__>__>_>__>_>_>_>>_______>_>_|Iperf |
              | |Clien  |                    \___/                     |mSLA   |  |                                             |Server|
              | |_______|                                              |_______|  |                                             |______|        
              |  :::::::        It can also be the same PC              :::::::   |                                              ::::::
              |   '''''                                                  '''''    |                                               ''''
              |___________________________________________________________________|      

________________________________________________________________________________________________________________________________________________________________________________________
4. Run mPlane
        1. First you need to launch the supervisor (run these commands from inside the mSLAcert-RI folder)
                export MPLANE_CONF_DIR=./conf
                python3 -m mplane.supervisor -c ./conf/supervisor-certs.conf -s 127.0.0.1 -p 8888   (-s 127.0.0.1 -p 8888, it the IP adress of the supervisor and the port)
        2. Then you can launch the probe, on the same PC or on a different PC, in this case we tested them on the same PC.
                python3 -m mplane.mSLA_main_service -c ./conf/component-certs.conf  -d 127.0.0.1 -p 8888
                
        3. You also can launch the client with
                python3 -m mplane.client -c ./conf/client-certs.conf -d 127.0.0.1 -p 8888
                
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\This part is temporal, we are developing an agent probe that will register at the supervisor as such\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
        4. Aditional comands, on a separate PC, you need to run two iperf servers
           Open two separate terminals and enter the sequent comands:
                iperf -s -p 5001 -i 1 (on one terminal)
                iperf -s -p 5002 -1 1 (on the other terminal)               
________________________________________________________________________________________________________________________________________________________________________________________
5. To confirm a successful registration of the probe to the supervisor you will see the sequent/similar message on the probe:
        URL: /register/capability

        Capability registration outcome:
        tcpsla-detail-ip4: Ok
        udpsla-detail-ip6: Ok
        ping-average-ip4: Ok
        udpsla-average-ip4: Ok
        udpsla-average-ip6: Ok
        tcpsla-average-ip4: Ok
        udpsla-detail-ip4: Ok
        ping-detail-ip6: Ok
        ping-detail-ip4: Ok
        tcpsla-average-ip6: Ok
        tcpsla-detail-ip6: Ok
        ping-average-ip6: Ok
        
        Checking for Specifications...
        
While on the supervisor:
        Capability ping-average-ip4 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability ping-detail-ip4 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability ping-average-ip6 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability ping-detail-ip6 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability tcpsla-average-ip4 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability tcpsla-detail-ip4 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability tcpsla-average-ip6 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability tcpsla-detail-ip6 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability udpsla-average-ip4 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability udpsla-detail-ip4 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability udpsla-average-ip6 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| register
        Capability udpsla-detail-ip6 received from org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane|
________________________________________________________________________________________________________________________________________________________________________________________
6. Display, run and show results of the registered capabilities.
6.1. On the supervisor you can view the registered capabilities with "listcap":

        |mplane| listcap
        do_listcap
        1 - ping-average-ip4 from 127.0.0.1
        2 - ping-detail-ip4 from 127.0.0.1
        3 - ping-average-ip6 from 127.0.0.1
        4 - ping-detail-ip6 from 127.0.0.1
        5 - tcpsla-average-ip4 from 127.0.0.1
        6 - tcpsla-detail-ip4 from 127.0.0.1
        7 - tcpsla-average-ip6 from 127.0.0.1
        8 - tcpsla-detail-ip6 from 127.0.0.1
        9 - udpsla-average-ip4 from 127.0.0.1
        10 - udpsla-detail-ip4 from 127.0.0.1
        11 - udpsla-average-ip6 from 127.0.0.1
        12 - udpsla-detail-ip6 from 127.0.0.1
        |mplane| 

6.2. You can run a capability at the supervisor with "runcap NUMBER-OF-CAP":
        |mplane| runcap 5 (We are runing capability number 5, that would be 5 - tcpsla-average-ip4 from 127.0.0.1)
        |when| = now + 10s / 1s (Runing now for 10 seconds)
        |param| source.ip4 = 192.168.208.137 (The source IP address)
        |param| destination.ip4 = 192.168.208.104 (The IP address where is launched the Iperf server)
        |mplane| Specification tcpsla-average-ip4 successfully pulled by org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| Result received by org.mplane.Test PKI.Test Clients.mPlane-Client
        |mplane| 
------------------
While this test is run, on the probe will be displayed the sequent message:

        <Service for <capability: measure (tcpsla-average-ip4) when now ... future / 1s token 60321cc2 schema daa302a4 p/m/r 2/0/4>> matches <specification: measure (tcpsla-average-ip4) when now +    10s / 1s token e5186d82 schema daa302a4 p(v)/m/r 2(2)/0/4>
        Will interrupt <Job for <specification: measure (tcpsla-average-ip4) when now + 10s / 1s token e5186d82 schema daa302a4 p(v)/m/r 2(2)/0/4>> after 10.0 sec
        Scheduling <Job for <specification: measure (tcpsla-average-ip4) when now + 10s / 1s token e5186d82 schema daa302a4 p(v)/m/r 2(2)/0/4>> immediately
        running iperf -i 1.0 -t 10 -c 192.168.208.104 192.168.208.137
        Returning <receipt:  (tcpsla-average-ip4)e5186d8207f7aab0db52e08bd4caf585>
        iperf: ignoring extra argument -- 192.168.208.137
        ------------------------------------------------------------

        Client connecting to 192.168.208.104, TCP port 5001

        TCP window size: 85.0 KByte (default)

        ------------------------------------------------------------

        [  3] local 192.168.208.137 port 49737 connected with 192.168.208.104 port 5001

        [ ID] Interval       Transfer     Bandwidth

        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 14, 512671), interval=1, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 14, 512671), interval=2, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 15, 509674), interval=3, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 16, 507897), interval=4, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 17, 537925), interval=5, transfer=11, bandwidth=96)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 18, 527502), interval=6, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 19, 527509), interval=7, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 20, 517022), interval=8, transfer=11, bandwidth=93)
        tcpsla tcpslaValue(time=datetime.datetime(2014, 11, 13, 9, 11, 21, 512617), interval=9, transfer=11, bandwidth=93)
        Result for tcpsla-average-ip4 successfully returned!

6.3. Show results, the results are also printed on a txt file on ./ directory of mSLA-RI, 
     we can view the results on the supervisor of the test that are done with the comand "showmeas":

        |mplane| showmeas
        label: tcpsla-average-ip4
        parameters:
            destination.ip4: 192.168.208.104
            source.ip4: 192.168.208.137
        result: measure
        results:
        - mSLA.tcpBandwidth.download.iperf.min
        - mSLA.tcpBandwidth.download.iperf.mean
        - mSLA.tcpBandwidth.download.iperf.max
        - mSLA.tcpBandwidth.download.iperf.timecountseconds
        resultvalues:
        -   - '93'
            - '93'
            - '96'
            - '9'
        token: e5186d8207f7aab0db52e08bd4caf585
        version: 0
        when: 2014-11-13 09:11:14.512671 ... 2014-11-13 09:11:21.512617

        |mplane| 

- You can also view the capability that were run with "listmeas":

        |mplane| listmeas
        1 - <result: measure (tcpsla-average-ip4) when 2014-11-13 09:11:14.512671 ... 2014-11-13 09:11:21.512617 token e5186d82 schema daa302a4 p/m/r(r) 2/0/4(1)>

________________________________________________________________________________________________________________________________________________________________________________________
7. Problems with SSL. In case you have problems with ssl or certificates:

        Backup the originals and rename the seuqent files files:
        sv_handlers_2.py --to-->> sv_handlers.py
        supervisor_2.py  --to-->> supervisor.py
        
        And then launch:
        Supervisor: python3 -m mplane.supervisor -c ./conf/supervisor-certs.conf -s 127.0.0.1 -p 8888
        Probe: python3 -m mplane.mSLA_main_service_2 --disab  -d 127.0.0.1 -p 8888
        
        With the clinet, i havent work, so if you have any errors with SSL just work with the Supervisor and the Probe.
________________________________________________________________________________________________________________________________________________________________________________________

##\\\\\\\\\\\\\___END___//////////////

########################################################################################
#ORIGINAL README
########################################################################################

# mPlane (almost) full architecture implementation

This repository contains a fully working Client-Supervisor-Probe architecture.

This implementation is based on the "official" python Reference Implementation, but is gone through heavy modifications (mostly for the interface parts, while the internals -scheduler and model- are pretty much the same). The main changes made to the code are the following:
* Conversion from capability pull, specification push, to capability push, specification pull
* Implementation of Supervisor, that works as an HTTP server. Now, all the components interact only through it
* The whole system works on HTTPS

# Usage
After cloning this repository and installing all the libraries needed, you can run the code this way (run these commands from inside the RI folder):

```
Supervisor:
export MPLANE_CONF_DIR=./conf
python3 -m mplane.supervisor -c ./conf/supervisor-certs.conf -s 127.0.0.1 -p 8888

Probe (tStat proxy, that for now works without running tStat, returning fictitious results):
python3 -m mplane.tstat_proxy -T ./conf/runtime.conf -c ./conf/component-certs.conf -d 127.0.0.1 -p 8888


Client:
python3 -m mplane.client -c ./conf/client-certs.conf -d 127.0.0.1 -p 8888
```

There are more options available, you can show them using `-h`. The commands within the supervisor and the client are the same of the original RI, you can see a list of those using the `help` command

# Misc Informations
* The interactions between the Probe and the Supervisor, and between the Supervisor and the Client are compliant to [these directives](https://github.com/finvernizzi/mplane_http_transport)
* The configuration files are not changed from the original RI: you can set certificate paths from `conf/supervisor-certs.conf`, `conf/component-certs.conf` and `client-certs.conf`; and user-role-capability authorizations from `conf/users.conf` and `conf/caps.conf`
* Since we are still in develop and test phases, all the PKI keys are publicly available. That, of course, will be fixed as soon as this phase ends
* The scripts in the PKI folder allow you to generate your own certificate. It is strongly recommended to use the provided root-ca, and only generate your own client, component and supervisor certificates, so that we avoid several self-signed certificates that cannot cooperate.
* You will need the root-ca passphrase to generate certificates: send me a mail at stefano.pentassuglia@ssbprogetti.it and I'll tell you that.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
##Version 1.0.1
mSLACert Active probe

Description:

The ubiquity of Internet access, and the wide variety of Internet-enabled devices, have made the Internet a principal pillar of the Information Society. As the importance of the Internet to everyday life grows, reliability of the characteristics of Internet service (availability, throughput, delay, etc.) grows important as well. Service Level Agreements (SLAs) between providers and customers of Internet services regulate the minimum level of service provided in terms of one or more measurable parameters.

We have developed an algorithm that is capable to give mSLA certification, by making use of UDP and TCP protocols. Here we present an alpha version of our algorithm, which is implemented in bash script. To achieve the mSLA certification the algorithm makes use of the tool iperf (http://iperf.fr), and PING.

mSLAcert makes  the measurement and calculation to certify, the Goodput at layer seven, throughput at layer four and line capacity at layer 2 of OSI standard.


How to run the probe compliant with mplane protocol:

--------------------------------------------------------------
------------------General-------------------------------------
--------------------------------------------------------------
0. sudo apt-get install iperf
1. sudo apt-get install gnome-terminal (or modify client.py, to open instead of gnome-terminal -> xfce4-terminal, or -> Terminal, or -> the name of your terminal)
2. sudo apt-get install python3-yaml
3. sudo apt-get install python3-pip
4. sudo pip3 install tornado
---apt-get install python3-yaml
   apt-get install python3-tornado
5. PYTHONPATH="/home/...path.../sla"
6. export PYTHONPATH

--------------------------------------------------------------
-------------Server------PING---------------------------------
--------------------------------------------------------------

7. python3 /home/...path.../.py -4 "Server-IP-Address" --sec "0/1"

--------------------------------------------------------------
-------------Server------TCP----------------------------------
--------------------------------------------------------------

7. python3 /home/...path.../slatcp.py -4 "Server-IP-Address" --sec "0/1"

--------------------------------------------------------------
-------------Server------UDP----------------------------------
--------------------------------------------------------------

7. python3 /home/...path.../slaudp.py -4 "Server-IP-Address" --sec "0/1"

-------------------------------------------------------------
-------------Agent-General-----------------------------------
-------------------------------------------------------------
1. python3 /home/...path.../mplane/client.py 
2. |mplane| connect http://"Sever-IP-Adress":8888
3. |mplane| when now + 10s / 1s
4. |mplane| runcap 0
5. |param| source.ip4 = "Source-IP-Adress"
6. |param| destination.ip4 = "Destination-IP-Adress"
7. 


-------------------------------------------------------------

The results of the probe are, the minimum, mean and maximum value of RTT, TCP measured bandwidth and UDP measure!
