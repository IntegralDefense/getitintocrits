#!/usr/bin/env python3
import requests
import argparse
import os, sys
import csv
import datetime
import re

from configparser import ConfigParser

PARENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

if os.path.exists(os.path.join('/etc', 'getitintocrits')):
    CONFIG_PATH = os.path.join('/etc', 'getitintocrits', 'config.ini')
else:
    CONFIG_PATH = os.path.join(PARENT_DIR, 'etc', 'local', 'config.ini')

# Remove any proxy environment variables.
os.environ['http_proxy'] = ''
os.environ['https_proxy'] = ''

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning, SNIMissingWarning, InsecurePlatformWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    requests.packages.urllib3.disable_warnings()
except:
    pass

def submit_csv(csvfile):
    with open(csvfile, 'r') as fin:
        csvdata = csv.reader(fin, delimiter=',')

        #pudb.set_trace()
        num_rows = 0
        for row in csvdata:
            num_rows += 1
            if num_rows == 1:
                continue
            if len(row) < 8:
                continue
            left_id = row[0]
            left_type = row[1]
            right_id = row[2]
            right_type = row[3]
            rel_type = row[4]
            if row[5] != '':
                try:
                    rel_date = datetime.datetime.strptime(row[5], '%Y-%m-%d %H:%M:%S')
                except ValueError as e:
                    print('Incorrect format for rel_date column. Must be: %Y-%m-%d %H:%M:%S')
                    continue
            else:
                rel_date = datetime.datetime.now()

            rel_confidence = row[6]
            if rel_confidence not in ('unknown', 'low', 'medium', 'high'):
                print('Invalid rel_confidence. Must be one of: unknown, low, medium, high')
                continue

            rel_reason = row[7]
            rel_reason = re.sub(r' // .*', '', rel_reason)

            submit_relationship(left_type, left_id, right_type, right_id, rel_type, rel_date, rel_confidence, rel_reason)


def type_translation(str_type):
    if str_type == 'Indicator':
        return 'indicators'
    if str_type == 'Domain':
        return 'domains'
    if str_type == 'IP':
        return 'ips'
    if str_type == 'Sample':
        return 'samples'
    if str_type == 'Event':
        return 'events'
    if str_type == 'Actor':
        return 'actors'
    if str_type == 'Email':
        return 'emails'
    if str_type == 'Backdoor':
        return 'backdoors'

    return 'fail'

def submit_relationship(left_type, left_id, right_type, right_id, rel_type, rel_date, rel_confidence, rel_reason):
    type_trans = type_translation(left_type)
    submit_url = '{}/{}/{}/'.format(url, type_trans, left_id)
    headers = {
        'Content-Type' : 'application/json',
        }

    params = {
        'api_key' : api_key,
        'username' : analyst,
        }

    data = {
        'action' : 'forge_relationship',
        'right_type' : right_type,
        'right_id' : right_id,
        'rel_type' : rel_type,
        'rel_date' : rel_date,
        'rel_confidence' : rel_confidence,
        'rel_reason' : rel_reason
    }

    r = requests.patch(submit_url, params=params, data=data, verify=False)
    if r.status_code == 200:
        print('Relationship built successfully: {0} <-> {1}'.format(left_id, right_id))
        print(r.text)
        return True
    else:
        print('Error with status code {0} and message {1} between these indicators: {2} <-> {3}'.format(r.status_code, r.text, left_id, right_id))
        return False


argparser = argparse.ArgumentParser()
argparser.add_argument('CSV', action='store', help='The CSV file containing the relationships to build.')
argparser.add_argument('--dev', dest='dev', action='store_true', default=False)
args = argparser.parse_args()

config = ConfigParser()
config.read(CONFIG_PATH)

crits_url_prod = config.get('crits', 'prod_url')
crits_api_prod = config.get('crits', 'prod_key')
crits_url_dev = config.get('crits', 'dev_url')
crits_api_dev = config.get('crits', 'dev_key')
crits_username = config.get('crits', 'user')

if args.dev:
    url = crits_url_dev
    api_key = crits_api_dev
    if len(api_key) != 40:
        print('Dev API key is the wrong length! Must be 40 characters.')
        sys.exit(1)
else:
    url = crits_url_prod
    api_key = crits_api_prod
    if len(api_key) != 40:
        print('Prod API key is the wrong length! Must be 40 characters.')
        sys.exit(1)

analyst = crits_username

if not os.path.exists(args.CSV):
    SystemExit('{0} does not exist!'.format(args.CSV))

submit_csv(args.CSV)
