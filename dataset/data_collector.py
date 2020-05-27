import getopt
import subprocess
import os
import sys
import time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import glob

TCPDUMP = "/usr/sbin/tcpdump"
# TODO
TCP_PKT_CNT = "500"
OVH_IP = "51.210.10.45"


def collect_data(padding, log_file, count, website_domain, i):
    current_path = os.path.dirname(os.path.abspath(__file__))
    if padding:
        pcap_path = "pcap/padded_%s_%d.pcap"
        dns_res_args = [current_path+"/dns_client.py", "--padding", OVH_IP, "8443"]
    else:
        pcap_path = "pcap/non_padded_%s_%d.pcap"
        dns_res_args = [current_path+"/dns_client.py", OVH_IP, "8443"]
    success = False
    while not success:
        log_file.write("Collecting trace %d/%d\n" % (i, count))
        log_file.flush()
        tcpdump_args = [TCPDUMP, "-i", "ens3", "-w", current_path+'/'+pcap_path % (website_domain, i), "host", OVH_IP, "and", "port", "8443"]
        tcpdump = subprocess.Popen(tcpdump_args, stderr=log_file)
        dns_resolver = subprocess.Popen(dns_res_args, stderr=log_file)
        selenium = subprocess.Popen([current_path+"/run_firefox.py", website_domain], stderr=log_file)
        selenium.wait()
        tcpdump.terminate()
        dns_resolver.terminate()
        if selenium.returncode != 0:
            log_file.write("Error with selenium, regoing sample")
            os.remove(current_path+'/'+pcap_path %(website_domain, i))
        else:
            success = True
        # Wait for the other to notice the end on the connection
        time.sleep(30)
        os.system("kill $(ps aux | awk '/firefox/ {print $2}')")

def demote(user_uid, user_gid):
    def result():
        os.setgid(user_gid)
        os.setuid(user_uid)
    return result

def main():
    """
    """
    # Default value if no arg specified
    count = 40
    padding = False
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["count=", "padding"])
    except getopt.GetoptError as err:
        print(err)
        sys.exit(2)
    for o, a in opts:
        if o in "--count":
            count = a
        elif o in "--padding":
            padding = True
    if len(args) != 1:
        exit('Please specify a website lists to get data from')
    top_lists = args[0]

    # Log file
    current_path = os.path.dirname(os.path.abspath(__file__))
    fd = open(current_path + "/collector_log", "w")
    website_list = open(current_path + "/" + top_lists, "r")
    line = website_list.readline()
    site_range = 200
    for i in range(0, count):
        for j in range(0, site_range):
            line = website_list.readline()
            line = line.split(",")
            website_domain = line[2]
            if padding:
                fd.write("Start collecting padded DOT trace for %s, %d/%d\n" % (website_domain, j, site_range))
                fd.flush()
                collect_data(True, fd, count, website_domain, i)
            else:
                fd.write("Start collecting non-padded DOT trace for %s, %d/%d\n" % (website_domain, j, site_range))
                fd.flush()
                collect_data(False, fd, count, website_domain, i)
        tmp_list = glob.glob('/tmp/tmp*/**/*', recursive = True)
        for file in tmp_list:
            try:
                os.remove(file)
            except:
                pass
        tmp_list = glob.glob('/tmp/rust*/**/*', recursive = True)
        for file in tmp_list:
            try:
                os.remove(file)
            except:
                pass
    fd.close()
    return


if __name__ == '__main__':
    main()
