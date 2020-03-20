# ZAP and GO
                    
  ______           _____                   _   _____   ____  
 |___  /    /\    |  __ \                 | | / ____| / __ \ 
    / /    /  \   | |__) |__ _  _ __    __| || |  __ | |  | |
   / /    / /\ \  |  ___// _` || '_ \  / _` || | |_ || |  | |
  / /__  / ____ \ | |   | (_| || | | || (_| || |__| || |__| |
 /_____|/_/    \_\|_|    \__,_||_| |_| \__,_| \_____| \____/ 
        
               "Scanning with style since 1894"

By: Cenard
Collaborators: Mr. Anderson & Max Power
ZAP and GO is a simple tool that execute 4 functions by using API from ZAP (OWASP project)


  With this tool you can make 4 differents types of scans:
    1. Crawler (ZAP Spider)
    2. Ajax Crawler (Ajax Spider)
    3. Passive Scan
    4. Active Scan

We used the official documentation to make the request directly to the API ZAP endpoint.

https://www.zaproxy.org/docs/api/?python#introduction

You will need some libraries like:

import sys
import time
import argparse
import requests
import pandas as pd
from pprint import pprint
from zapv2 import ZAPv2

The only uncommon one you might not have is zapv2, to install please use pip or pip3 [pip install python-owasp-zap-v2.4] depends on you.
I strongly recommend use pip and run this with python 2, although is available in Python3 aswell.

Another thing you must know is that you will need the "API key", you can see it in the UI ZAP going directly to Tools/Options/API, is a large string that contains numbers and letters.


***
I am not responsible for the normal and private use of this tool, please do not use in domains where you do not have explicit authorization to audit or scan. This could be an instrusive tool.
***

usage: ZAG.py [-h] -u  URL -k  KEY [-s] [-a] [-P] [-A] [-o OUTPUT] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -u  URL, --url URL    specify the url, like the following example:
                        http(s)://domain
  -k  KEY, --key KEY    specify the Api key, you can find it in your UI ZAP
                        [Tool/Options/API]
  -s, --spider          Web Spider against your target
  -a, --ajaxspider      Web Ajax Spider against your target
  -P, --passive         Passive Scan against your target
  -A, --active          Active Scan against your target
  -o OUTPUT, --output OUTPUT
                        Generate CSV file, you must specified the name
  -v, --verbose         Add verbosity
