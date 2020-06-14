This directory contains all the scripts used to gather the dataset:
- 5000_top_list.csv: Contains a list of popular websites
- client.py: & dns_clients.py: Are the entry proxies to tunnel HTTP and DNS traffic through our implementation of TLS
- server.py: & dns_server.py: Are the exit proxies that received the tunneled traffic. 
    server.py sends the traffic to a real http proxy on localhost
    dns_server.py sends the DNS traffic to the cloudflare resolver
- run_firefox.py: Use Selenium to access a website, we use a custom firefox profile that disable caching mechanism
- data_collector.py: Main script to collect the dataset, it will call run_firefox.py to access a website and stores tcpdump output in a new pcap directory

To reprodude the gathering of the dataset, two virtual machines are needed. You must run dns_server.py on one of them and data_collector.py on the other.
