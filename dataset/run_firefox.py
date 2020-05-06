#!/usr/bin/env python3

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.expected_conditions import presence_of_element_located
from selenium.webdriver.firefox.options import Options

import time
import sys
import os


website_domain = sys.argv[1]
FirefoxProfile = "/home/antoine/.mozilla/firefox/cvawzhyn.selenium"
options = Options()
options.headless = True
profile = webdriver.FirefoxProfile(FirefoxProfile)
current_path = os.path.dirname(os.path.abspath(__file__))
filename = current_path + "/time/%s" % website_domain
if os.path.exists(filename):
    mode = 'a' # append if already exists
else:
    mode = 'w' # make a new file if not
fd = open(filename, mode)

driver = webdriver.Firefox(options=options, firefox_profile=profile)
start = time.time()
driver.get("https://"+website_domain)
finish = time.time()
fd.write("%d\n" % (finish - start))
driver.close()
fd.close()
wait = (10 - finish + start) if (10 - finish + start) > 0 else 0
time.sleep(wait)
