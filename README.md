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
