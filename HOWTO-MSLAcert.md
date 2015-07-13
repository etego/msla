## Prerequisites

The mPlane SDK requires Python 3.3 and the following additional packages:

- pyyaml
- tornado
- urllib3
$ sudo apt-get install expect

###The network scenario on which the files are currently configured:

PC1 - 192.168.1.1 <<<-------------------------------------------------------->>>> PC2 - 192.168.1.2

mSLAcert_main, Supervisor<<<-------------------------------------------------->>>mPlane Client, mSLAcert_Agent

In base of you network configuration you have to change the seguent files, for the Ip and certificates:

./conf/client.conf
		[TLS]
		cert = PKI/ca/certs/"client-certicate".crt
		key = PKI/ca/certs/"plaintext certificate.key
		ca-chain = PKI/ca/root-ca/root-ca.crt

		[client]
		# workflow may be 'component-initiated' or 'client-initiated'
		workflow = client-initiated / component-initiated (Type of workflow)
		# for component-initiated:
		listen-host = "IP of the machine where is launched the client"
		listen-port = 8891
		registration-path = register/capability
		specification-path = show/specification
		result-path = register/result
		# for client-initiated:
		capability-url: "IP supervisor":8890/
		
./conf/component*.conf
		[TLS]
		cert = PKI/ca/certs/"Components-certicate".crt
		key = PKI/ca/certs/"plaintext certificate.key
		ca-chain = PKI/ca/root-ca/root-ca.crt

		[Roles]
		org.mplane.FUB.Clients.CI-Client_FUB = guest,admin
		"add also the roles for all the other components, client, supervisor ect"

		[Authorizations]
		msla-AGENT-Probe-ip4 = guest,admin
		"add the capability of your probe"

		[module_mSLA_main]
		module = mplane.components."name of python file"
		ip4addr = 1.2.3.4

		[component]
		scheduler_max_results = 20
		# workflow may be 'component-initiated' or 'client-initiated'
		workflow = component-initiated / client-initiated (Type of workflow)
		# for component-initiated
		client_host = "IP of the supervisor"
		client_port = 8889
		registration_path = register/capability
		specification_path = show/specification
		result_path = register/result
		# for client-initiated
		listen-port = 8888

./conf/supervisor.conf
		[TLS]
		cert = PKI/ca/certs/"client-certicate".crt
		key = PKI/ca/certs/"plaintext certificate.key
		ca-chain = PKI/ca/root-ca/root-ca.crt

		[Roles]
		org.mplane.FUB.Clients.CI-Client_FUB = guest,admin
		"add also the roles for all the other components, client, supervisor ect"

		[Authorizations]
		msla-AGENT-Probe-ip4 = guest,admin
		"add the capability of your probe"

		[client]
		# workflow may be 'component-initiated' or 'client-initiated'
		workflow = component-initiated / client-initiated (Type of workflow)
		# for component-initiated:
		listen-host = "IP of the machine where is launched the supervisor"
		listen-port = 8889
		registration-path = register/capability
		specification-path = show/specification
		result-path = register/result
		# for client-initiated:
		component-urls: "IP of component 1":8888/,"IP of component 2":8888/


		[component]
		scheduler_max_results = 20
		# workflow may be 'component-initiated' or 'client-initiated'
		workflow = component-initiated / client-initiated (Type of workflow)
		# for component-initiated:
		client_host = "IP of the machine where is launched the client"
		client_port = 8891
		registration_path = register/capability
		specification_path = show/specification
		result_path = register/result
		# for client-initiated:
		listen-port = 8890

###To generate certificates use the scripts
./PKI/create_client_cert.sh
./PKI/create_component_cert.sh
./PKI/create_supervisor_cert.sh
"follow instruction on ./PKI/HOWTO.txt"

### HOWTO run for mSLAcert with component-initiated workflow, run in this order:

>>>To run the CI components (with SSL), from the protocol-ri directory, run:

>>>To run CI mSLAcert server:

```export PYTHONPATH=.```

```./scripts/mpcom --config ./conf/component.conf```



>>>To run CI mSLAcert Agent:

```export PYTHONPATH=.```

```./scripts/mpcom --config ./conf/component-agent.conf```



>>>To run mPlane client:

```export PYTHONPATH=.```

```./scripts/mpcli --config ./conf/client.conf```


>>>End the supoervisor in the end:

```export PYTHONPATH=.```

```./scripts/mpsup --config ./conf/supervisor.conf```


This will launch the supervisor. 
###Then from the client:
1. to view the cap to run
		listcap
2. Run capability
		runcap
3. set the period
		now + 40s / 1s
4. set a different time
		when now + 34s / 1s
5. do a new measurement for the same capability and destination
		set destination.ip4 x.x.x.x