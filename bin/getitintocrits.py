#!/usr/bin/env python3
import requests
import argparse
import os, sys
import json
import re
import datetime
import csv
import pprint
import logging
import logging.config
import hashlib

from configparser import ConfigParser

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning, SNIMissingWarning, InsecurePlatformWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    requests.packages.urllib3.disable_warnings()
except:
    pass

PARENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

logging.config.fileConfig(os.path.join(PARENT_DIR, 'etc', 'local', 'logging.ini'))
log = logging.getLogger()

config = ConfigParser()
config.read(os.path.join(PARENT_DIR, 'etc', 'local', 'config.ini'))

# Read the settings from the config file.
sources = list(set(config.get('getitintocrits', 'sources').split(',')))
available_event_types = list(set(config.get('getitintocrits', 'available_event_types').split(',')))
valid_tlos = list(set(config.get('getitintocrits', 'valid_tlos').split(',')))
ignore_list = list(set(config.get('getitintocrits', 'ignore_list').split(',')))

# Remove any proxy environment variables.
os.environ['http_proxy'] = ''
os.environ['https_proxy'] = ''

verify = ''

def _get_unused_relationship_name():
    count = 0
    filename = 'relationships.txt'
    basename = 'relationships'
    extensions = '.txt'
    index = 1
    while os.path.exists(filename):
        filename = '{}_{}{}'.format(basename, count, extensions)
        count += 1
    return filename

# Create an event and return the event id
def create_event(args, tags='', campaign='', confidence=''):
    source = args.source
    reference = args.reference
    event_name = args.event

    assert source is not None
    assert source != ''
    assert reference is not None
    assert reference != ''
    assert event_name is not None
    assert event_name != ''

    r = requests.get("{0}/events/?api_key={1}&username={2}&c-title={3}".format(url, api_key, analyst, event_name), verify=verify)

    if r.status_code == 200:
        e_json = json.loads(r.text)
        if len(e_json['objects']) > 1:
            log.error('Error, received too many events back from the server.')
            return False
        elif len(e_json['objects']) == 1:
            # One response, one event. It's the one we want.
            event_id = e_json['objects'][0]['_id']
            log.info('Found id of {} for the event'.format(event_id))
            return event_id
        elif len(e_json['objects']) == 0:
            # Check if --no-prompt was given (i.e.: event2wiki automation).
            if args.no_prompt:
                # These are the mandatory parameters.
                description = args.event_description
                event_type = args.event_type
                rel_date = args.event_date
                tags = args.event_bucket_list
                assert description != ''
                assert event_type != ''
                assert rel_date != ''
                assert tags != ''

                # These are optional parameters.
                campaign = args.event_campaign
                confidence = args.event_campaign_conf
            else:
                # Now we need to create this event.
                description = input('Please enter a description for the event {} >> '.format(event_name))
                etok = False
                while not etok:
                    event_type = input('Please enter the type of event (type \'list\' for available options) >> ')
                    if event_type == 'list':
                        print('----------')
                        for e in available_event_types:
                            print(e)
                        print('----------')
                    else:
                        if event_type in available_event_types:
                            etok = True
                        else:
                            print('Provide a real event type, noob.')
                rel_date = None
                # If it is a DSIE post, the thread title will have an accurate date for us
                try:
                    rel_date = datetime.datetime.strptime(event_name, '%Y%m%d-%H%M%S')
                except ValueError as e:
                    pass
                edok = False
                while not edok:
                    if rel_date is not None:
                        yn = input('Date detected as {}, is this correct? (y/n) >> '.format(datetime.datetime.strftime(rel_date, '%Y-%m-%d %H:%M:%S')))
                        if yn == 'y':
                            edok = True
                            continue
                    dtstr = input('Please provide a date in the following format YYYY-MM-DD HH:MM:SS >> ')
                    try:
                        rel_date = datetime.datetime.strptime(dtstr, '%Y-%m-%d %H:%M:%S')
                        edok = True
                    except ValueError as e:
                        if dtstr.lower() == "now":
                            rel_date = datetime.datetime.now()
                            edok = True
                            pass
                        else:
                            print('Incorrect format.')
                            edok = False
                            pass

                        #break
                cok = False
                while not cok:
                    yn = input('Campaign detected as {} with confidence of {}, is this correct? (y/n) >> '.format(campaign, confidence))
                    if yn == 'y':
                        cok = True
                        continue
                    campaign = input('Please provide a campaign name >> ')
                    confidence = input('What is the confidence for this campaign? >> ')

                tok = False
                while not tok:
                    yn = input('Bucket List detected as {}, is this correct? (y/n) >> '.format(tags))
                    if yn == 'y':
                        tok = True
                        continue
                    tags = input('Please provide a comma separated list of bucket list items (tags) >> ')

            # Now we can create the event
            data = {
                'api_key' : api_key,
                'username' : analyst,
                'source' : source,
                'reference' : reference,
                'method' : '',
                'campaign' : campaign,
                'confidence' : confidence,
                'description' : description,
                'event_type' : event_type,
                'date' : rel_date,
                'title' : event_name,
                'bucket_list' : tags,
            }

            r = requests.post('{}/events/'.format(url), data=data, verify=verify)
            if r.status_code == 200:
                log.debug('Event created')
                print(r.text)
                r_json = json.loads(r.text)
                if not 'id' in r_json:
                    log.error('Error uploading event.')
                    return False
                event_id = r_json['id']
                return event_id
            else:
                log.error('Status code of {} returned when creating event!'.format(r.status_code))
                return False

        else:
            log.error('Error! Number of event objects returned by crits was negative!')
            return False
    elif r.status_code == 401:
        log.warning("401 - Not Authorized code received.")
        log.warning("Is your API key in ~/.crits_api correct?")
        return False
    else:
        log.error('Status code of {} returned!'.format(r.status_code))
    return False


def submit_indicators_csv(source, reference, csvfile):
    # Load regexes so we can determine when we come across a domain or IP.
    patterns = load_patterns(os.path.join(PARENT_DIR, 'etc', 'local', 'patterns.ini'))
    return_data = { 'indicators' : [], 'domains' : [], 'ips' : [] }

    fin = open(csvfile, 'r')
    csvreader = csv.DictReader(fin)

    rowcount = 0
    for row in csvreader:
        rowcount += 1
        # First we need to collect all the lovely data
        # Current CSV format for CRITS is:
        # Indicator, Type, Threat Type, Attack Type, Description, Campaign, Campaign Confidence, Confidence, Impact, Bucket List, Ticket, Action
        # TODO: No native handling of action in the indicators API call. Must use the action patch call.
        # Indicator
        if not 'Indicator' in row:
            log.error('No Indicator header in row {0} of csv file {1}. Continuing...'.format(rowcount, csvfile))
            continue
        indicator_value = row['Indicator']
        # Type
        if not 'Type' in row:
            log.error('No Type header in row {0} of csv file {1}. Continuing...'.format(rowcount, csvfile))
            continue
        indicator_type = row['Type']
        # Threat Type
        indicator_threat_type = 'Unknown'
        if 'Threat Type' in row:
            indicator_threat_type = row['Threat Type']
        if indicator_threat_type == '':
            indicator_threat_type = 'Unknown'
        # Attack Type
        indicator_attack_type = 'Unknown'
        if 'Attack Type' in row:
            indicator_attack_type = row['Attack Type']
        if indicator_attack_type == '':
            indicator_attack_type = 'Unknown'
        # Description
        indicator_description = ''
        if 'Description' in row:
            indicator_description = row['Description']
        # Campaign
        indicator_campaign = ''
        if 'Campaign' in row:
            indicator_campaign = row['Campaign']
        # Campaign Confidence
        indicator_campaign_confidence = ''
        if 'Campaign Confidence' in row:
            indicator_campaign_confidence = row['Campaign Confidence']
        # Confidence
        indicator_confidence = 'unknown'
        if 'Confidence' in row:
            indicator_confidence = row['Confidence']
        # Impact
        indicator_impact = 'unknown'
        if 'Impact' in row:
            indicator_impact = row['Impact']
        # Bucket List
        indicator_bucket_list = ''
        if 'Bucket List' in row:
            indicator_bucket_list = row['Bucket List']
        # Ticket
        indicator_ticket = ''
        if 'Ticket' in row:
            indicator_ticket = row['Ticket']
        # Action
        indicator_action = ''
        if 'Action' in row:
            indicator_action = row['Action']

        # Time to upload these indicators
        data = {
            'api_key' : api_key,
            'username' : analyst,
            'source' : source,
            'reference' : reference,
            'method' : '',
            'campaign' : indicator_campaign,
            'confidence' : indicator_campaign_confidence,
            'bucket_list' : indicator_bucket_list,
            'ticket' : indicator_ticket,
            'add_domain' : True,
            'add_relationship' : True,
            'indicator_confidence' : indicator_confidence,
            'indicator_impact' : indicator_impact,
            'type' : indicator_type,
            'threat_type' : indicator_threat_type,
            'attack_type' : indicator_attack_type,
            'value' : indicator_value,
            'description' : indicator_description,
            }

        r = requests.post("{0}/indicators/".format(url), data=data, verify=verify)
        if r.status_code == 200:
            log.debug("Indicator uploaded successfully - {}".format(indicator_value))
            ind = json.loads(r.text)
            print('{0}'.format(r.text))
            if ind['return_code'] == 1:
                continue
            ip_relationship_list = []
            domain_relationship_list = []
            ind_list = []

            # Now we will gather IP and Domain objects if they were added
            matches_ip = patterns['IP'].match(indicator_value)
            matches_domain = patterns['Host'].match(indicator_value)
            return_data['indicators'].append( { 'id' : ind['id'], 'value' : indicator_value } )

            # Add IP objects
            if matches_ip:
                # Get the actual IP object - If it exists
                rip = requests.get('{0}/ips/?c-ip={1}&username={2}&api_key={3}&format=json'.format(url, indicator_value, analyst, api_key), verify=verify)
                if rip.status_code == 200:
                    ip_object = json.loads(rip.text)
                    if ip_object['meta']['total_count'] > 0:
                        for ip in ip_object['objects']:
                            return_data['ips'].append( { 'id' : ip['_id'], 'ip' : ip['ip'] })

            # Add domain objects
            if matches_domain:
                # Get the actual Domain object - if it exists
                rip = requests.get('{0}/domains/?c-domain={1}&username={2}&api_key={3}&format=json'.format(url, indicator_value, analyst, api_key), verify=verify)
                if rip.status_code == 200:
                    domain_object = json.loads(rip.text)
                    if domain_object['meta']['total_count'] > 0:
                        for domain in domain_object['objects']:
                            return_data['domains'].append( { 'id' : domain['_id'], 'domain' : domain['domain'] } )

            if indicator_confidence == 'benign' and indicator_impact == 'benign':
                patch_url = "{0}/indicators/{1}/".format(url, ind['id'])
                params = {
                    'api_key' : api_key,
                    'username' : analyst,
                }

                data = {
                    'action' : 'status_update',
                    'value' : 'Informational',
                }
                r = requests.patch(patch_url, params=params, data=data, verify=verify)
                if r.status_code == 200:
                    log.debug('Indicator {} set to Informational'.format(indicator_value))
                else:
                    log.error('Attempted to set indicator {} to Informational, but did not receive a 200'.format(indicator_value))
                    log.error('Error message was: {}'.format(r.text))

            if 'whitelist' in indicator_bucket_list.split(','):
                patch_url = "{0}/indicators/{1}/".format(url, ind['id'])
                params = {
                    'api_key' : api_key,
                    'username' : analyst,
                }

                data = {
                    'action' : 'status_update',
                    'value' : 'Deprecated',
                }
                r = requests.patch(patch_url, params=params, data=data, verify=verify)
                if r.status_code == 200:
                    log.debug('Indicator {} set to Deprecated due to '
                              'whitelist tag'.format(indicator_value))
                else:
                    log.error('Attempted to set indicator {} to Deprecated, '
                              'but did not receive a 200'.format(indicator_value))
                    log.error('Error message was: {}'.format(r.text))

        elif r.status_code == 401:
            print("401 - Not Authorized code received.")
            print("Is your API key in ~/.crits_api correct?")
            return return_data
        else:
            print("Error with status code {0} and message {1}".format(r.status_code, r.text))

    fin.close()
    return return_data


def submit_sample(filepath, source, reference, campaign, campaign_confidence, tags):
    # This will check and see if the file is already in CRITS and if not, upload it.
    filetype = 'raw'
    upload_type = 'file'
    crits_data = False
    log.debug('Doing file {}'.format(filepath))
    if os.path.isfile(filepath):
        with open(filepath, 'rb') as fdata:
            sha256sum = hashlib.sha256(fdata.read()).hexdigest()
            params = { 'api_key' : api_key, 'username' : analyst }
            r = requests.get("{0}/samples/?c-sha256={1}".format(url, sha256sum), params=params, verify=verify)
            if r.status_code == 200:
                result_data = json.loads(r.text)
                if 'meta' in result_data:
                    if 'total_count' in result_data['meta']:
                        if result_data['meta']['total_count'] > 0:
                            # TODO: Make this less lazy
                            log.debug('Found sample already in CRITS with sha256 {}. Returning that!'.format(sha256sum))
                            crits_data = { 'id' : result_data['objects'][0]['_id'], 'filename' : result_data['objects'][0]['filename'] }
                            return crits_data
            else:
                log.error('Wrong status code returned for sample {}'.format(sha256sum))
        with open(filepath, 'rb') as fdata:
            data = {
                'api_key' : api_key,
                'username' : analyst,
                'source' : source,
                'reference' : reference,
                'method' : '',
                'filetype' : filetype,
                'upload_type' : upload_type,
                'campaign' : campaign,
                'confidence' : campaign_confidence,
                'bucket_list' : tags,
            }
            r = requests.post("{0}/samples/".format(url), data=data, files = {'filedata' : fdata }, verify=verify)
            if r.status_code == 200:
                result_data = json.loads(r.text)
                sample_data = get_sample_object(result_data['id'])
                crits_data = { 'id' : result_data['id'], 'filename' : sample_data['filename'] }
                log.debug('Sample data looks like: {}'.format(crits_data))
            elif r.status_code == 401:
                log.warning("401 - Not Authorized code received.")
                log.warning("Is your API key in ~/.crits_api correct?")
            else:
                log.error("Error with status code {0} and message {1}".format(r.status_code, r.text))

    return crits_data


def submit_email(smtp_stream_path, source, reference, campaign, campaign_confidence, tags):
    filetype = 'raw'
    upload_type = 'raw'
    crits_data = False
    if os.path.isfile(smtp_stream_path):
        with open(smtp_stream_path, 'rb') as fdata:
            data = {
                'api_key' : api_key,
                'username' : analyst,
                'source' : source,
                'reference' : reference,
                'method' : '',
                'filetype' : filetype,
                'upload_type' : upload_type,
                'campaign' : campaign,
                'confidence' : campaign_confidence,
                'bucket_list' : tags,
            }
            r = requests.post("{0}/emails/".format(url), data=data, files = {'filedata' : fdata }, verify=verify)
            if r.status_code == 200:
                result_data = json.loads(r.text)
                email_data = get_email_object(result_data['id'])
                subject = 'Unknown subject'
                if 'subject' in email_data:
                    subject = email_data['subject']
                crits_data = { 'id' : result_data['id'], 'subject' : subject }
            elif r.status_code == 401:
                print("401 - Not Authorized code received.")
                print("Is your API key in ~/.crits_api correct?")
                return crits_data
            else:
                print("Error with status code {0} and message {1}".format(r.status_code, r.text))

    return crits_data


def submit_backdoor(backdoor_dir, source, reference, campaign, campaign_confidence, tags):
    crits_data = False
    backdoor_txt = os.path.join(backdoor_dir, 'backdoor.txt')
    version_txt = os.path.join(backdoor_dir, 'version.txt')
    description_txt = os.path.join(backdoor_dir, 'description.txt')
    if not os.path.exists(backdoor_txt):
        log.error('File does not exist: {}'.format(filepath))
        return False
    backdoor = ''
    with open(backdoor_txt) as fp:
        backdoor = fp.readline()
    backdoor = backdoor.strip()
    crits_result = get_http_request('{}/backdoors/?or=1&c-name={}&c-aliases__in={}'.format(url, backdoor, backdoor))

    # Need to check and see if the version is new or if it matches up
    version = ''
    if os.path.exists(version_txt):
        with open(version_txt) as fp:
            version = fp.readline()
            version = version.strip()

    create_backdoor = False
    backdoor_data = False

    # Check and see if we need to add this backdoor
    if len(crits_result['objects']) > 0:
        for obj in crits_result['objects']:
            if 'version' in obj:
                backdoor_data = obj
                break

    # We were unable to find the backdoor data listed
    if not backdoor_data:
        description = ''
        if os.path.exists(description_txt):
            with open(description_txt) as fp:
                description = fp.readline()
                description = description.strip()
        data = {
            'api_key' : api_key,
            'username' : analyst,
            'source' : source,
            'reference' : reference,
            'method' : '',
            'campaign' : campaign,
            'confidence' : campaign_confidence,
            'bucket_list' : tags,
            'name' : backdoor,
            'aliases' : '',
            'version' : version,
            'description' : description,
        }
        r = requests.post("{0}/backdoors/".format(url), data=data, verify=verify)
        if r.status_code == 200:
            result_data = json.loads(r.text)
            backdoor_data = get_http_request('{}/backdoors/{}/'.format(url, result_data['id']))
            crits_data = { 'id' : backdoor_data['_id'], 'name' : backdoor_data['name'] }
            log.debug('Backdoor data looks like: {}'.format(crits_data))
        elif r.status_code == 401:
            log.warning("401 - Not Authorized code received.")
            log.warning("Is your API key in ~/.crits_api correct?")
        else:
            log.error("Error with status code {0} and message {1}".format(r.status_code, r.text))
    # We were able to find the backdoor, so we will return that data
    else:
        crits_data = { 'id' : backdoor_data['_id'], 'name' : backdoor_data['name'] }

    return crits_data


def get_email_object(crits_id):
    return get_http_request('{}/emails/{}/'.format(url, crits_id))


def get_sample_object(crits_id):
    return get_http_request('{}/samples/{}/'.format(url, crits_id))


# I was going to use this, but then I didn't. I'm leaving it for now because it's cool
def get_backdoor_list():
    backdoors = []
    limit = 0
    offset = 0
    total_count = 20
    while limit + offset > total_count:
        json_data = get_http_request('{}/backdoors/?only='.format(url))
        if not json_data:
            log.error('Error getting backdoor list.')
            return backdoors
        for backdoor in json_data['objects']:
            backdoors.append(backdoor['name'])
        limit = json_data['meta']['limit']
        osset = json_data['meta']['offset']
        total_count = json_data['meta']['total_count']
    return backdoors


def get_http_request(url):
    default_return = { 'objects' : [] }
    params = {
        'api_key' : api_key,
        'username' : analyst,
    }
    r = requests.get(url, params=params, verify=verify)
    if r.status_code == 200:
        return json.loads(r.text)
    elif r.status_code == 401:
        print("401 - Not Authorized code received.")
        print("Is your API key in ~/.crits_api correct?")
    else:
        print("Error with status code {0} and message {1}".format(r.status_code, r.text))
    return default_return


def load_patterns(fpath):
    patterns = {}
    config = ConfigParser()
    with open(fpath) as f:
        config.readfp(f)

    for ind_type in config.sections():
        try:
            ind_pattern = config.get(ind_type, 'pattern')
        except:
            continue

        if ind_pattern:
            ind_regex = re.compile(ind_pattern)
            patterns[ind_type] = ind_regex

    return patterns


def write_header(fhandle):
    print('left_id,left_type,right_id,right_type,rel_type,rel_date,rel_confidence,rel_reason')
    if not args.no_write:
        fhandle.write('left_id,left_type,right_id,right_type,rel_type,rel_date,rel_confidence,rel_reason\n')


def write_tlo(tlo_id, tlo_type, tlo_name, fhandle):
    print("{},{}, // {}".format(tlo_id, tlo_type, tlo_name))
    if not args.no_write:
        fhandle.write("{},{}, // {}\n".format(tlo_id, tlo_type, tlo_name))


def write_relationship(tlo1_id, tlo1_type, tlo1_name, tlo2_id, tlo2_type, tlo2_name, rel_type, fhandle):
    relationship_date = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
    print("{},{},{},{},{},{},high,Related during automated import // {} to {}".format(tlo1_id, tlo1_type, tlo2_id, tlo2_type, rel_type, relationship_date, tlo1_name, tlo2_name))
    if not args.no_write:
        fhandle.write("{},{},{},{},{},{},high,Related during automated import // {} to {}\n".format(tlo1_id, tlo1_type, tlo2_id, tlo2_type, rel_type, relationship_date, tlo1_name, tlo2_name))


# Little helper function
def add_relationship_data(relationship_data, returned_data):
    for cid in returned_data:
        if cid in relationship_data:
            if not 'relationships' in returned_data[cid]:
                log.warning('No relationships found for a duplicate ID when adding relationship data: {}'.format(cid))
                continue
            for relationship in returned_data[cid]['relationships']:
                if relationship['id'] in relationship_data[cid]['relationships']:
                    log.warning('Duplicate relationship for id {} found in object {}'.format(relationship['id'], cid))
                    continue
                relationship_data[cid]['relationships'].append(relationship)
        else:
            relationship_data[cid] = returned_data[cid]
    return relationship_data


def process_directory(path, type, parent_id, parent_type, parent_description):
    # First check and see if an indicators.csv file exists in this dir
    indicators_file = os.path.join(path, 'indicators.csv')
    indicators_data = {}
    if os.path.exists(os.path.join(path, 'indicators.csv')):
        # Parent is None
        # type is Event
        # Directory is cwd
        indicators_data = submit_indicators_csv(args.source, args.reference, os.path.join(path, 'indicators.csv'))
        if indicators_data is False:
            log.error('Error returned from indicators upload. Quiting...')
            sys.exit(0)

    # Second, check to see if a custom .relationships file exist, and if so process that
    if os.path.exists(os.path.join(path, '.relationships')):
        with open(os.path.join(path, '.relationships'), 'r') as fp:
            rel_csv = csv.reader(fp)
            rcount = 1
            try:
                for row in rel_csv:
                    if len(row) == 2:
                        if 'custom_relationships' not in indicators_data:
                            indicators_data['custom_relationships'] = []
                        indicators_data['custom_relationships'].append([row[0], row[1]])
                    rcount += 1
            except Exception as e:
                log.warning('Exception caught on CSV row {} in file'
                            '{}.'.format(os.path.join(path, '.relationships'),
                                         rcount))

    # This is the CRITS id of the object in our current directory
    crits_id = ''
    # This is a description (for help in identifying in relationships.txt)
    crits_description = ''
    # This is where we are going to store all the relationship data
    relationship_data = {}
    # If we need to relate a backdoor to the TLO, this data will be populated
    backdoors_data = []
    # Other variables
    campaign = ''
    confidence = ''
    tags = ''

    if type == 'Event':
        event_id = ''
        # First, create the overall event
        if args.event != '':
            tags = []
            if os.path.exists('indicators.csv'):
                with open('indicators.csv') as cfile:
                    csvreader = csv.DictReader(cfile)
                    for row in csvreader:
                        campaign = row['Campaign']
                        confidence = row['Campaign Confidence']
                        tags = row['Bucket List']
                        break
            event_id = create_event(args, tags, campaign, confidence)
            if event_id is False:
                log.error('Error creating the event. Aborting...')
                sys.exit(0)
            crits_id = event_id
            crits_description = args.event

    if type == 'Sample':
        listing = os.listdir(path)
        for sample in listing:
            if sample in ignore_list:
                continue
            if sample.endswith('.analysis'):
                # Ignore our own mwzoo analysis directories
                continue
            if os.path.isdir(os.path.join(path, sample)):
                continue
            if os.path.exists(os.path.join(path, 'indicators.csv')):
                with open(os.path.join(path, 'indicators.csv')) as cfile:
                    csvreader = csv.DictReader(cfile)
                    for row in csvreader:
                        campaign = row['Campaign']
                        confidence = row['Campaign Confidence']
                        tags = row['Bucket List']
                        break

            sample_data = submit_sample(os.path.join(path, sample), args.source, args.reference, campaign, confidence, tags)
            if not sample_data:
                log.error('Bad sample data returned, aborting...')
                return relationship_data
            crits_id = sample_data['id']
            crits_description = sample_data['filename']


    if type == 'Email':
        # We are looking for an smtp.stream file
        # First we have to find the bro stream
        bro_id_pattern = re.compile(r'^C[a-z0-9A-Z]{14,20}$')
        local_dir_listing = os.listdir(path)
        stream_dir = ''
        smtp_headers = False
        smtp_stream = False
        for obj in local_dir_listing:
            if re.match(bro_id_pattern, obj):
                stream_dir = obj
            if obj == 'smtp.headers':
                smtp_headers = True
            if obj == 'smtp.stream':
                smtp_stream = True

        if stream_dir != '' and (smtp_headers or smtp_stream):
            # We found both a bro stream id AND an smtp.headers file
            # This should not happen
            log.error('Found both a bro stream id AND smtp.headers in the same email directory in {}. This should not happen. Aborting email...'.format(path))
            return relationship_data

        # This is the file we will send to CRITS via the API
        email_upload_file = ''

        if stream_dir != '':
            # bro_smtp streams should contain a "message_X" directory
            message_path = os.listdir(os.path.join(path, stream_dir))
            bro_message_pattern = re.compile(r'^message_[0-9]+$')
            message_dir = ''
            message_count = 0
            for obj in message_path:
                if re.match(bro_message_pattern, obj):
                    message_count += 1
                    message_dir = obj
            if message_count > 1:
                log.error('More than one message stream found in {}. Aborting. Tell Nate'.format(message_path))
                return relationship_data
            if message_count < 1:
                log.error('No message_X directory found in {}. Aborting.'.format(message_path))

            # Now we can look for the smtp.stream file
            stream_dir = os.path.join(path, stream_dir, message_dir)
            stream_list = os.listdir(stream_dir)
            if 'smtp.stream' not in stream_list:
                log.error('Unable to find smtp.stream in email and bro stream. Aborting this directory: {}'.format(stream_dir))
                return relationship_data
            email_upload_file = os.path.join(stream_dir, 'smtp.stream')

        if smtp_headers:
            email_upload_file = os.path.join(path, 'smtp.headers')

        if smtp_stream:
            email_upload_file = os.path.join(path, 'smtp.stream')

        # Okay, we found it so time to upload it to CRITS
        if os.path.exists(os.path.join(path, 'indicators.csv')):
            with open(os.path.join(path, 'indicators.csv')) as cfile:
                csvreader = csv.DictReader(cfile)
                for row in csvreader:
                    campaign = row['Campaign']
                    confidence = row['Campaign Confidence']
                    tags = row['Bucket List']
                    break

        log.debug("Submitting email: {}".format(email_upload_file))
        email_data = submit_email(email_upload_file, args.source, args.reference, campaign, confidence, tags)
        if not email_data:
            log.error('Bad email data returned, aborting...')
            log.error('Email data was: {}'.format(repr(email_data)))
            return relationship_data
        crits_id = email_data['id']
        crits_description = email_data['subject']

    if type == 'Backdoor':
        listing = os.listdir(path)
        if 'backdoor.txt' not in listing:
            log.error('A backdoor.txt file must exist in your backdoor directory. Not found in {}'.format(path))
            return relationship_data

        if os.path.exists(os.path.join(path, 'indicators.csv')):
            with open(os.path.join(path, 'indicators.csv')) as cfile:
                csvreader = csv.DictReader(cfile)
                for row in csvreader:
                    campaign = row['Campaign']
                    confidence = row['Campaign Confidence']
                    tags = row['Bucket List']
                    break

        backdoor_data = submit_backdoor(path, args.source, args.reference, campaign, confidence, tags)
        if not backdoor_data:
            log.error('Bad backdoor data returned, aborting...')
            return relationship_data
        crits_id = backdoor_data['id']
        crits_description = backdoor_data['name']

    # Build a relationship with our parent if we have one
    if parent_id != '' and parent_type != '':
        relationship_data[parent_id] = { 'relationships' : [], 'type' : parent_type, 'description' : parent_description }
        relationship_data[parent_id]['relationships'].append( { 'id' : crits_id, 'type' : type, 'description' : crits_description, 'rel_type' : 'Related To' } )
    # Now we build the relationships from the id of the object we received
    relationship_data[crits_id] = { 'relationships' : [], 'type' : type, 'description' : crits_description }
    # Indicator data (returned from submit_indicators_csv) can contain 3 types:
    # - Indicators
    # - Domains
    # - IPs
    if indicators_data is not False:
        if 'indicators' in indicators_data:
            for ind in indicators_data['indicators']:
                relationship_data[crits_id]['relationships'].append( { 'id' : ind['id'], 'type' : 'Indicator', 'description' : ind['value'], 'rel_type' : 'Related To' } )
        # Removing domains and ips from the relationship building. These
        # should be related to their associated indicators, and can be
        # accessed by walking the relationships that way.
        '''
        if 'domains' in indicators_data:
            for ind in indicators_data['domains']:
                relationship_data[crits_id]['relationships'].append( { 'id' : ind['id'], 'type' : 'Domain', 'description' : ind['domain'], 'rel_type' : 'Related To' } )
        if 'ips' in indicators_data:
            for ind in indicators_data['ips']:
                relationship_data[crits_id]['relationships'].append( { 'id' : ind['id'], 'type' : 'IP', 'description' : ind['ip'], 'rel_type' : 'Related To' } )
        '''
        if 'custom_relationships' in indicators_data:
            for rel in indicators_data['custom_relationships']:
                id0 = ''
                id1 = ''
                val0 = rel[0]
                val1 = rel[1]
                if 'indicators' not in indicators_data:
                    log.warning('.relationships file found with no indicators.csv in a subdirectory'.format())
                    break
                for ind in indicators_data['indicators']:
                    if ind['value'] == rel[0]:
                        id0 = ind['id']
                    if ind['value'] == rel[1]:
                        id1 = ind['id']
                if id0 != '' and id1 != '':
                    if id0 not in relationship_data:
                        relationship_data[id0] = { 'relationships' : [], 'type' : 'Indicator', 'description' : val0 }
                    relationship_data[id0]['relationships'].append( { 'id' : id1, 'type' : 'Indicator', 'description' : val1, 'rel_type' : 'Related To' } )

    # Recurse!
    # Sample directories match: sample#
    sample_pattern = re.compile(r'^sample[0-9]+$')
    # Backdoor directories match: backdoor#
    backdoor_pattern = re.compile(r'^backdoor[0-9]+$')
    # Email directories match: 986726c0-ed3a-49e6-9ccf-78d1deb17e85
    email_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    # Email directories can also match: emailX
    email_pattern2 = re.compile(r'email[0-9]+$')

    listing = os.listdir(path)
    for obj in listing:
        if not os.path.isdir(os.path.join(path, obj)):
            continue
        if re.match(email_pattern, obj):
            log.debug('Going deeper...')
            returned_data = process_directory(os.path.join(path, obj), 'Email', crits_id, type, crits_description)
            relationship_data = add_relationship_data(relationship_data, returned_data)
        if re.match(email_pattern2, obj):
            log.debug('Going deeper...')
            returned_data = process_directory(os.path.join(path, obj), 'Email', crits_id, type, crits_description)
            relationship_data = add_relationship_data(relationship_data, returned_data)
        if re.match(sample_pattern, obj):
            log.debug('Going deeper...')
            returned_data = process_directory(os.path.join(path, obj), 'Sample', crits_id, type, crits_description)
            relationship_data = add_relationship_data(relationship_data, returned_data)
        if re.match(backdoor_pattern, obj):
            log.debug('Going deeper...')
            returned_data = process_directory(os.path.join(path, obj), 'Backdoor', crits_id, type, crits_description)
            relationship_data = add_relationship_data(relationship_data, returned_data)

    # We are finished and we return the data
    return relationship_data

argparser = argparse.ArgumentParser()
argparser.add_argument('-s', dest='source', required=True, help='This can be one of: {0}'.format("\n".join(sources)))
argparser.add_argument('-r', dest='reference', required=True, help='This is a description of where you obtained the indicators.')
argparser.add_argument('-e', dest='event', default='', help='Automatically build relationships to attach each indicator to an event.')
argparser.add_argument('--nw', dest='no_write', action='store_true', default=False, help='Do not write a relationships.txt file.')
argparser.add_argument('--dev', dest='dev', action='store_true', default=False, help='Build relationships in dev CRITS. For science.')

# event2wiki automation parameters
argparser.add_argument('--no-prompt', dest='no_prompt', action='store_true', default=False, help='Used for event2wiki automation.')
argparser.add_argument('--description', dest='event_description', action='store', default="", help='Short description of the event.')
argparser.add_argument('--type', dest='event_type', action='store', default="", help='Type of event (Phishing/Malicious Code/etc.')
argparser.add_argument('--date', dest='event_date', action='store', default="", help='Date/time of the event.')
argparser.add_argument('--campaign', dest='event_campaign', action='store', default="", help='Campaign of the event.')
argparser.add_argument('--campaign-conf', dest='event_campaign_conf', action='store', default="", help='Confidence level of the campaign.')
argparser.add_argument('--bucket-list', dest='event_bucket_list', action='store', default="", help='Bucket list/tags for the event.')
args = argparser.parse_args()

pprint = pprint.PrettyPrinter(indent=2)

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

# Check if our source exists or if it is in the shortcut mapping
if args.source not in sources:
    print('{0} is not a valid source!'.format(args.source))
    print('Valid types are:\n{0}'.format('\n'.join(sorted(sources))))
    sys.exit(1)

relationship_data = {}
# We start the recursion with an event
relationship_data = process_directory('.', 'Event', '', '', '')

relationship_out = None
if not args.no_write:
    relationships_name = _get_unused_relationship_name()
    relationship_out = open(relationships_name, 'w')

# Write everything
write_header(relationship_out)
# Make relationships with all the TLOs and the event
print(relationship_data)
for cid in relationship_data:
    for rel_item in relationship_data[cid]['relationships']:
        write_relationship(cid, relationship_data[cid]['type'], relationship_data[cid]['description'], rel_item['id'], rel_item['type'], rel_item['description'], rel_item['rel_type'], relationship_out)

if not args.no_write:
    relationship_out.close()
