This directory contains all the scripts used to gather the dataset:
- short_list_1500: Contains a list of popular websites
- client.py: & dns_clients.py: Are the entry proxies to tunnel HTTP and DNS traffic through our implementation of TLS
- server.py: & dns_server.py: Are the exit proxies that received the tunneled traffic. 
    server.py sends the traffic to a real http proxy on localhost
    dns_server.py sends the DNS traffic to the cloudflare resolver
- run_firefox.py: Use Selenium to access a website, we use a custom firefox profile that disable caching mechanism
- data_collector.py: Main script to collect the dataset, it will call run_firefox.py to access a website and stores tcpdump output in a new pcap directory

To reprodude the gathering of the dataset, two virtual machines are needed. You must run dns_server.py on one of them and data_collector.py on the other.

The machine that runs the data_collector must be configured to use the local dns resolver.
To do so, add the following line at the beginning of resolv.conf
```
nameserver 127.0.0.1
```
Captures can be found on [Onedrive](https://uclouvain-my.sharepoint.com/personal/arime_oasis_uclouvain_be/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Farime%5Foasis%5Fuclouvain%5Fbe%2FDocuments%2Fdataset&originalPath=aHR0cHM6Ly91Y2xvdXZhaW4tbXkuc2hhcmVwb2ludC5jb20vOmY6L2cvcGVyc29uYWwvYXJpbWVfb2FzaXNfdWNsb3V2YWluX2JlL0VwLVJsNVU1WjFKS3RheFNVMXYzT3ZBQm9xQTk1SWtvVDJocnFIN1FULUVaOFE_cnRpbWU9a2VxV254b1IyRWc)
