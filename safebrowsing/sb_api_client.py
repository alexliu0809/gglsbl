"""
Reference: 

https://github.com/afilipovich/gglsbl
https://developers.google.com/safe-browsing/v4/update-api

The logic is like this:
* First update threat lists
* For each list, Download the entire prefix database
* For each list, Download the entire full length database
* Save

"""
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from functools import wraps
import socket
import logging
log = logging.getLogger('safebrowsing')
log.addHandler(logging.NullHandler())

API_KEY = "AIzaSyBDz_GjiWtahZPpNku1Y6iS9EXps3eHxrw"


def autoretry(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _fail_count
        while True:
            try:
                r = func(*args, **kwargs)
                _fail_count = 0
                return r
            except HttpError as e:
                if not (hasattr(e, 'resp') and 'status' in e.resp
                        and e.resp['status'].isdigit and int(e.resp['status']) >= 500):
                    raise  # we do not want to retry auth errors etc.
                _fail_count += 1
                wait_for = min(2 ** (_fail_count - 1) * 15 * 60 * (1 + random.random()), 24 * 60 * 60)
                log.exception('Call Failed for %s time(s). Retrying in %s seconds: %s',
                              _fail_count, wait_for, str(e))
                time.sleep(wait_for)
            except socket.error:
                transient_error_wait = 2
                log.exception('Socket error, retrying in {} seconds.'.format(transient_error_wait))
                time.sleep(transient_error_wait)
    return wrapper

class SafeBrowsingAPIClient(object):
    """Interface for Google Safe Browsing API

    dump the whole database from google
    API Docs:
    https://developers.google.com/safe-browsing/v4/
    Google API Client Docs:
    google-api-python-client-master/docs/dyn/safebrowsing_v4.html
    """
    def __init__(self, api_key, client_id = "ucsd_sysnet_group", client_version = "1.0"):
        """ Iniialialize the API Client

        :param api_key: Google API key
        :param client_id: the name of your client
        :param client_version: the version of your client
        :param next_request_no_sooner_than: has to wait for this amount of time before sending another request
        """
        self.client_id = client_id
        self.client_version = client_version
        # Google API client
        # https://googleapis.github.io/google-api-python-client/docs/epy/googleapiclient.discovery-module.html
        self.service = build('safebrowsing', 'v4', developerKey=api_key, cache_discovery=False)
        self.next_request_no_sooner_than = None



    @autoretry
    def get_threats_lists(self):
        """Retrieve all available threat lists"""
        # response is googleapiclient.discovery.Resource object
        response = self.service.threatLists()
        
        # response is googleapiclient.http.HttpRequest object
        response = response.list()
        
        # response is a dict file
        response = response.execute()
        
        return response['threatLists']

    @autoretry
    def get_hash_prefix_cache(self):
        """ Fetech 

    def fair_use_delay(self):
        """ Delay the program to obey google fair use policy"""
        if self.next_request_no_sooner_than is not None and type(self.next_request_no_sooner_than) == int:
            sleep_time = max(0, self.next_request_no_sooner_than - time.time())
            log.info('Sleeping for {} seconds until next request.'.format(sleep_time))
            time.sleep(sleep_time)



""" Example Response of Get Threats List
{
'threatLists': [
    {'threatType': 'MALWARE', 'platformType': 'ANY_PLATFORM',
     'threatEntryType': 'URL'},
    {'threatType': 'MALWARE', 'platformType': 'WINDOWS',
     'threatEntryType': 'URL'},
    ]
}
"""
