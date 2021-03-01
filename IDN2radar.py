# encoding = utf-8

import os
import sys
import time
import datetime
import requests
from requests.exceptions import HTTPError
import json
import re
from builtins import object
import logging
import logging.handlers
import configparser
import boto3
import socket

config = configparser.ConfigParser()
config.read('./config.ini')

ACCESS_KEY = config.get("aws-parameter-store", "ACCESS_KEY")
SECRET_KEY = config.get("aws-parameter-store", "SECRET_KEY")

syslog_server_address = config.get("qradar-syslog-server", "host")
syslog_server_port = config.getint("qradar-syslog-server", "port")

client_id = config.get("sailpoint.com","client_id")
client_secret = config.get("sailpoint.com","client_secret")
org_name = config.get("sailpoint.com","tenant")

sysLogger = logging.getLogger('QRADARSYSLOG')
sysLogger.setLevel(logging.INFO)
syslog_handler = logging.handlers.SysLogHandler( address=(syslog_server_address, syslog_server_port), facility=logging.handlers.SysLogHandler.LOG_LOCAL1, socktype=socket.SOCK_STREAM)
sysLogger.addHandler(syslog_handler)

class EC2ParameterStore:
    def __init__(self, **client_kwargs):
        self.client = boto3.client('ssm', **client_kwargs)
        self.path_delimiter = '/'

    def extract_parameter(self, parameter, strip_path=True):
        key = parameter['Name']
        if strip_path:
            key_parts = key.split(self.path_delimiter)
            key = key_parts[-1]
        value = parameter['Value']
        if parameter['Type'] == 'StringList':
            value = value.split(',')
        return (key, value)

    def set_parameter(self, name, value, type="String", overwrite=True):
        result = self.client.put_parameter(Name=name, Value=value, Type=type, Overwrite=overwrite)
        return result

    def get_parameter(self, name, decrypt=True, strip_path=True):
        result = self.client.get_parameter(Name=name, WithDecryption=decrypt)
        p = result['Parameter']
        param = dict([self.extract_parameter(p, strip_path=strip_path)])
        return param[name]

class Helper(object):
    def __init__(self, logger=None):
        self.logger = logger
        self.http_session = None
        self.requests_proxy = None
        self.store = EC2ParameterStore(
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            region_name='eu-west-1'
        )


    def log_error(self, msg):
        print(msg)
        if self.logger:
            self.logger.error(msg)

    def log_info(self, msg):
        print(msg)
        if self.logger:
            self.logger.info(msg)

    def log_debug(self, msg):
        print(msg)
        if self.__logger:
            self.__logger.debug(msg)

    def _init_request_session(self, proxy_uri=None):
        self.http_session = requests.Session()
        self.http_session.mount(
            'http://', requests.adapters.HTTPAdapter(max_retries=3))
        self.http_session.mount(
            'https://', requests.adapters.HTTPAdapter(max_retries=3))
        if proxy_uri:
            self.requests_proxy = {'http': proxy_uri, 'https': proxy_uri}

    def send_http_request(self, url, method, parameters=None, payload=None, headers=None, cookies=None, verify=True,
                          cert=None, timeout=None, proxy_uri=None, use_proxy=False):
        if self.http_session is None:
            self._init_request_session(proxy_uri)
        # connect and read timeouts in tuple
        requests_args = {'timeout': (5.0, 25.0), 'verify': verify}
        if parameters:
            requests_args['params'] = parameters
        if payload:
            if isinstance(payload, (dict, list)):
                requests_args['json'] = payload
            else:
                requests_args['data'] = str(payload)
        if headers:
            requests_args['headers'] = headers
        if cookies:
            requests_args['cookies'] = cookies
        if cert:
            requests_args['cert'] = cert
        if timeout is not None:
            requests_args['timeout'] = timeout
            
        if self.requests_proxy:
            requests_args['proxies'] = self.requests_proxy

        req = self.http_session.request(method, url, **requests_args)
        return req

#This method will determine if the current timestamp should be used instead of the value stored in the checkpoint file. Will return 'true' if the checkpoint time is 1 or more days in the past

def use_current(now, old):
    ret = False
    
    try:
        a = datetime.datetime.strptime(now, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        a = datetime.datetime.strptime(now, '%Y-%m-%dT%H:%M:%SZ')
        
    try:
        b = datetime.datetime.strptime(old, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        b = datetime.datetime.strptime(old, '%Y-%m-%dT%H:%M:%SZ')
        
    diff = a - b
    delta_days = diff.days
    
    if(int(delta_days) > 0):
        ret = True
        
    return ret

def collect_events(helper):
    
    # Get information about IdentityNow from the input configuration
    # Information on how to attain these values can be found on community.sailpoint.com
    base_url = 'https://{}.api.identitynow.com'.format(org_name)
    tenant = {
        "url" : base_url, 
        "client_id" : client_id,
        "client_secret" : client_secret
    }
    
    if not tenant["url"].startswith("https"):
       helper.log_error("Requires communication over TLS/SSL, check IdentityNow API Gateway URL")
       return 0
       
    # Read the timestamp from the checkpoint variable in AWS System Manager Parameter Store
    # - The checkpoint contains the ISO datetime of the 'created' field of the last event seen in the
    #   previous execution of the script. If the checkpoint time was greater than a day in the past, use current datetime to avoid massive load if search disabled for long period of time
    
   
    new_checkpoint_time = (datetime.datetime.utcnow() - datetime.timedelta(minutes=60)).isoformat() + "Z"
    #Set checkpoint time to either the current timestamp, or what was saved in the checkpoint

    checkpoint = helper.store.get_parameter('sailpoint-checkpoint', decrypt=True)

    if checkpoint:
        checkpoint_time = checkpoint
        if use_current(new_checkpoint_time, checkpoint_time):
            checkpoint_time = new_checkpoint_time
    else:
        checkpoint_time = new_checkpoint_time
    
    # JWT RETRIEVAL    
    # The following request is responsible for retrieving a valid JWT token from the IdentityNow tenant
    tokenparams = {
        "grant_type": "client_credentials",
        "client_id": tenant["client_id"],
        "client_secret": tenant["client_secret"]
    }
        
    token_url = tenant["url"] + "/oauth/token"

    access_token = ""
    
    token_response = helper.send_http_request(token_url, "POST", parameters=tokenparams, payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None)

    if token_response is not None:
        try:
            token_response.raise_for_status()
            
            access_token = token_response.json()["access_token"]
            headers = {
                'Content-Type' : 'application/json', 
                'Authorization' : "Bearer " + access_token
            }
        except HTTPError as http_err:
            helper.log_error("Error getting token: " + str(token_response.status_code))
            return 0
        except KeyError:
            helper.log_error("Access token not granted...")
        except ValueError:
            helper.log_error("No json response received...")

    # END GET JWT LOGIC

    partial_set = False
    count_returned = 0
    audit_events = []
    
    #Search API results are slightly delayed, allow for 5 minutes though in reality
    #this time will be much shorter. Cap query at checkpoint time to 5 minutes ago
    search_delay_time = (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat() + "Z"


    #Number of Events to return per call to the search API
    limit = 10000
    
    while True:

        if partial_set == True:
            break
        
        #Standard query params, but include limit for result set size
        queryparams = {
            "count": "true",
            "offset": "0",
            "limit": limit
        }
        
        helper.log_error(f'checkpoint_time {checkpoint_time} search_delay_time {search_delay_time}')
        query_checkpoint_time = checkpoint_time.replace('-', '\\-').replace('.', '\\.').replace(':', '\\:')
        query_search_delay_time = search_delay_time.replace('-', '\\-').replace('.', '\\.').replace(':', '\\:')

        
        #Search criteria - retrieve all audit events since the checkpoint time, sorted by created date
        searchpayload = {
            "queryType": "SAILPOINT",
            "query": {
                "query": f"created:>{query_checkpoint_time} AND created:<{query_search_delay_time}" 
                # "query": f"created:>=2021-02-28" 
            },
            "queryResultFilter": {},
            "sort": ["created"],
            "searchAfter": []
        }
           
        audit_url = tenant["url"] + "/beta/search/events"

        #Initiate request        
        response = helper.send_http_request(audit_url, "POST", parameters=queryparams, payload=searchpayload, headers=headers, cookies=None, verify=True, cert=None, timeout=None)
        
        # API Gateway saturated / rate limit encountered.  Delay and try again. Delay will either be dictated by IdentiyNow server response or 5 seconds
        if response.status_code == 429:
            
            retryDelay = 5
            retryAfter = response.headers['Retry-After']
            if retryAfter is not None:
                retryDelay = 1000 * int(retryAfter)
                
            helper.log_warning("429 - Rate Limit Exceeded, retrying in " + str(retryDelay))
            time.sleep(retryDelay)
            
        elif response.ok:    
            
            # Check response headers to get toal number of search results - if this value is 0 there is nothing to parse, if it is less than the limit value then we are caught up to most recent, and can exit the query loop
            x_total_count = int(response.headers['X-Total-Count'])
            if x_total_count > 0:
                if response.json() is not None:
                    try:
                        if x_total_count < limit:
                            #less than limit returned, caught up so exit
                            partial_set = True
    
                        results = response.json()
                        #Add this set of results to the audit events array
                        audit_events.extend(results)
                        current_last_event = audit_events[-1]
                        checkpoint_time = current_last_event['created']
                    except KeyError:
                        helper.log_error("Response does not contain items")
                        break
            else:
                #Set partial_set to True to exit loop (no results)
                partial_set = True
        else:
            helper.log_error("Failure from server" + str(response.status_code))
            #hard exit
            return 0

    #Iterate the audit events array and create events for each one

    if len(audit_events) > 0:
        for audit_event in audit_events:
            sysLogger.info(json.dumps(audit_event))
            # print(audit_event)
        print("sent {} events to {} {}".format(len(audit_events), syslog_server_address, syslog_server_port))
        #Get the created date of the last AuditEvent in this run and save it as the checkpoint time AWS parameter
        last_event = audit_events[-1]
        new_checkpoint_time = last_event['created']
        helper.store.set_parameter('sailpoint-checkpoint', new_checkpoint_time)
 

if __name__ == "__main__":
    helper = Helper()
    collect_events(helper)

