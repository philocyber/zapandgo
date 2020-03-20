#!/usr/bin/env python
__author__ = 'Cenard'
__collaborators__ = 'Mr. Anderson & Max Power'
__description__ = '''ZAP and GO is a simple tool that execute some normal functions by using API from ZAP (OWASP project)
'''


import sys
import time
import argparse
import requests
import pandas as pd
from pprint import pprint
from zapv2 import ZAPv2


def banner():
    ascii_art = '''                    
  ______           _____                   _   _____   ____  
 |___  /    /\    |  __ \                 | | / ____| / __ \ 
    / /    /  \   | |__) |__ _  _ __    __| || |  __ | |  | |
   / /    / /\ \  |  ___// _` || '_ \  / _` || | |_ || |  | |
  / /__  / ____ \ | |   | (_| || | | || (_| || |__| || |__| |
 /_____|/_/    \_\|_|    \__,_||_| |_| \__,_| \_____| \____/ 
        
               "Scanning with style since 1894"
'''
    return ascii_art


finishMsg = "The scan has been completed"

print(banner())
print('By: {}'.format(__author__))
print('Collaborators: {}'.format(__collaborators__))
print(__description__)


def spider(url, key):
    zap = ZAPv2(apikey=key)
    print('Spidering target {}'.format(url))
    # The scan returns a scan id to support concurrent scanning
    scan_id = zap.spider.scan(url)
    while int(zap.spider.status(scan_id)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scan_id)))
        time.sleep(1)

    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    print('\n'.join(map(str, zap.spider.results(scan_id))))
    # If required post process the spider results
    return


def ajaxspider(url, key):
    zap = ZAPv2(apikey=key)
    print('Spidering target {}'.format(url))
    # The scan returns a scan id to support concurrent scanning
    scan_id = zap.spider.scan(url)
    while int(zap.spider.status(scan_id)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scan_id)))
        time.sleep(1)

    print('Spider has completed!')
    print('\n'.join(map(str, zap.spider.results(scan_id))))
    return


def passive(url, key):
    zap = ZAPv2(apikey=key)
    if not args.output:
        print('Passive Scanning target {}'.format(url))
        st = 0
        pg = 5000
        alert_count = 0
        alerts = zap.alert.alerts(baseurl=url, start=st, count=pg)
        blacklist = [1, 2]
        while len(alerts) > 0:
            print('Reading ' + str(pg) + ' alerts from ' + str(st))
            alert_count += len(alerts)
            for alert in alerts:
                plugin_id = alert.get('pluginId')
                if plugin_id in blacklist:
                    continue
                if alert.get('risk') == 'High':
                    continue
                if alert.get('risk') == 'Informational':
                    continue
            st += pg
            alerts = zap.alert.alerts(start=st, count=pg)
        print('Hosts: {}'.format(', '.join(zap.core.hosts)))
        print('Alerts: ')
        print(zap.core.alerts())
        print('\n Passive Scan completed \n')
        print('Total number of alerts: ' + str(alert_count))

    elif args.output:
        print('Passive Scanning target {}'.format(url))
        st = 0
        pg = 5000
        alert_count = 0
        alerts = zap.alert.alerts(baseurl=url, start=st, count=pg)
        blacklist = [1, 2]
        while len(alerts) > 0:
            print('Reading ' + str(pg) + ' alerts from ' + str(st))
            alert_count += len(alerts)
            for alert in alerts:
                plugin_id = alert.get('pluginId')
                if plugin_id in blacklist:
                    continue
                if alert.get('risk') == 'High':
                    continue
                if alert.get('risk') == 'Informational':
                    continue
            st += pg
            alerts = zap.alert.alerts(start=st, count=pg)
        print('Total number of alerts: ' + str(alert_count))
        alerts = zap.core.alerts(baseurl=url)
        print(output(alerts))

    else:
        print('Oops, Houston we have a problem here, please see Help options and retry this again')
        sys.exit()
    return


def active(url, key):
    zap = ZAPv2(apikey=key)
    if not args.output:
        print('Active Scanning target {}'.format(url))
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            print('Scan progress %: {}'.format(zap.ascan.status(scan_id)))
            time.sleep(5)

        # Print vulnerabilities found by the scanning
        print('Hosts: {}'.format(', '.join(zap.core.hosts)))
        print('Alerts: ')
        print(zap.core.alerts(baseurl=url))
        print('Active Scan completed')

    elif args.output:
        print('Active Scanning target {}'.format(url))
        scan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(scan_id)) < 100:
            print('Scan progress %: {}'.format(zap.ascan.status(scan_id)))
            time.sleep(5)

        alerts = zap.core.alerts(baseurl=url)
        print(output(alerts))

    else:
        print('Oops, Houston we have a problem here, please see Help options and retry this again')
        sys.exit()
    return


def output(alerts):
    if args.active:
        output = list()
        for alert in alerts:
            output_alert = [alert['method'], alert['confidence'], alert['description'],
                            alert['url'], alert['reference'], alert['solution'], alert['alert'], alert['name'],
                            alert['risk']]
            output.append(output_alert)

        df = pd.DataFrame(output, columns=['Method', 'Confidence', 'Description', 'URL', 'Reference',
                                           'Solution', 'Alert', 'Name', 'Risk'])
        df.to_csv(args.output)
        print('Active Scan completed, you already have your new CSV file')
    elif args.passive:
        output = list()
        for alert in alerts:
            output_alert = [alert['method'], alert['confidence'], alert['description'],
                            alert['url'], alert['reference'], alert['solution'], alert['alert'], alert['name'],
                            alert['risk']]
            output.append(output_alert)

        df = pd.DataFrame(output, columns=['Method', 'Confidence', 'Description', 'URL', 'Reference',
                                           'Solution', 'Alert', 'Name', 'Risk'])
        df.to_csv(args.output)
        print('Passive Scan completed, your CSV file is ready to go')
    else:
        print("There was a problem, please try again changing your syntax command")
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u ', '--url',
                        help="specify the url, like the following example: http(s)://domain ",
                        required=True)
    parser.add_argument('-k ', '--key',
                        help="specify the Api key, you can find it in your UI ZAP [Tool/Options/API]",
                        required=True)
    parser.add_argument('-s', '--spider',
                        action="store_true",
                        help="Web Spider against your target",)
    parser.add_argument('-a', '--ajaxspider',
                        action="store_true",
                        help="Web Ajax Spider against your target",)
    parser.add_argument('-P', '--passive',
                        action="store_true",
                        help="Passive Scan against your target",)
    parser.add_argument('-A', '--active',
                        action="store_true",
                        help="Active Scan against your target",)
    parser.add_argument('-o', '--output',
                        action="store",
                        help="Generate CSV file, you must specified the name")
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help="Add verbosity")
    args = parser.parse_args()

    if not args.url:
        print("The argument -u [URL] is invalid: The example is -u http://example.com or -u https://example.com")
        sys.exit()
    if args.url and not args.key:
        print("\nYou need a KEY value and another option besides your target, like -s (spider)\n")
        print("For example python ZAG.py -s -u https://example.com -k v5u0ed833e3i2upbqv9npapd2g")
        parser.print_help()
    if args.url and args.spider:
        if args.key:
            url = [args.url]
            key = str(args.key)
            spider(url, key)
        elif not args.key:
            print('\nYou need to specify an API key, please read help details or README file')
            print("Or try something like this: python ZAG.py -s -u https://example.com -k v5u0ed833e3i2upbqv9npapd2g")
        else:
            print('Oops, Houston we have a problem here, please see Help options and retry this again')
            sys.exit()
    if args.url and args.ajaxspider:
        if args.key:
            url = [args.url]
            key = str(args.key)
            ajaxspider(url, key)
        elif not args.key:
            print('\nYou need to specify an API key, please read help details or README file')
            print("Or try something like this: python ZAG.py -s -u https://example.com -k v5u0ed833e3i2upbqv9npapd2g")
        else:
            print('Oops, Houston we have a problem here, please see Help options and retry this again')
            sys.exit()
    if args.url and args.passive:
        if args.key:
            key = str(args.key)
            url = [args.url]
            passive(url, key)
        elif not args.key:
            print('\nYou need to specify an API key, please read help details or README file')
        else:
            print('Oops, Houston we have a problem here, please see Help options and retry this again')
            sys.exit()
    if args.url and args.active:
        if args.key:
            key = str(args.key)
            url = [args.url]
            active(url, key)
        elif not args.key:
            print('\nYou need to specify an API key, please read help details or README file')
            print("Or try something like this: python ZAG.py -s -u https://example.com -k v5u0ed833e3i2upbqv9npapd2g")
        else:
            print('Oops, Houston we have a problem here, please see Help options and retry this again')
            sys.exit()


