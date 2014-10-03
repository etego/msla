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
-------------------------------------------------------------

The results of the probe are, the minimum, mean and maximum value of RTT, TCP measured bandwidth and UDP measure!
