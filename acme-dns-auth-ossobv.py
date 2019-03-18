#!/usr/bin/env python3
# acme-dns-auth-ossobv -- certbot authentication hook for (ossobv) acme-dns
# Multi-domain ready version of acme-dns-certbot, by Walter Doekes OSSO B.V.
#
# See: https://github.com/ossobv/acme-dns [acme-dns-auth-ossobv]
# Original: https://github.com/joohoi/acme-dns-certbot-joohoi
# Copyright (c) 2018 Joona Hoikkala
#
# Usage, after configuring /etc/acme-dns-ossobv/config.json and
# /etc/acme-dns-ossobv/accounts.json:
#
#     certbot certonly --manual \
#       --manual-auth-hook /usr/local/bin/acme-dns-auth-ossobv.py \
#       --preferred-challenges dns --debug-challenges \
#       -d example.com -d *.example.com
#
import json
import os
import requests
import sys
from requests.auth import HTTPBasicAuth

# {"acmedns_url": "https://[BASIC_AUTH@]YOUR_ACME_DNS"}
CONFIG_PATH = '/etc/acme-dns-ossobv/config.json'
# {"example.com": {"username": "aa...", password": "abc.."},
#  "*.whatever.nl": {"username": "bb...", password": "abc.."},
#  "*": {"username": "cc...", password": "abc.."}}
ACCOUNTS_PATH = '/etc/acme-dns-ossobv/accounts.json'


class AcmeDnsClient(object):
    """
    Handles the communication with ACME-DNS API
    """
    def __init__(self, acmedns_url, basic_auth):
        self.acmedns_url = acmedns_url
        self.basic_auth = basic_auth

    def update_txt_record(self, account, subdomain, txt):
        """Updates the TXT challenge record to ACME-DNS subdomain."""
        update = {'subdomain': subdomain, 'txt': txt}
        headers = {'X-Api-User': account['username'],
                   'X-Api-Key': account['password'],
                   'Content-Type': 'application/json'}
        res = requests.post(
            '{}/update'.format(self.acmedns_url),
            headers=headers,
            data=json.dumps(update),
            auth=self.basic_auth)
        if res.status_code == 200:
            # Successful update
            return

        msg = ('Encountered an error while trying to update TXT record in '
               'acme-dns. \n'
               '------- Request headers:\n{}\n'
               '------- Request body:\n{}\n'
               '------- Response HTTP status: {}\n'
               '------- Response body: {}')
        s_headers = json.dumps(headers, indent=2, sort_keys=True)
        s_update = json.dumps(update, indent=2, sort_keys=True)
        try:
            s_body = json.dumps(res.json(), indent=2, sort_keys=True)
        except ValueError:
            s_body = res.text
        print(msg.format(s_headers, s_update, res.status_code, s_body))
        sys.exit(1)


class Storage(object):
    def __init__(self, storagepath):
        self.storagepath = storagepath
        with open(self.storagepath) as fh:
            self._data = json.load(fh)

    def fetch(self, key):
        """Gets configuration value from storage. If the (sub)domain is not
        found, try parent domains"""
        # key = example.com matches 'example.com'
        if key in self._data:
            return self._data[key]

        # key = example.com matches '*.example.com'
        # key = example.com matches '*.com'
        # key = example.com matches '*'
        keyParts = key.split('.')
        for i in range(len(keyParts) + 1):
            domain = '.'.join(['*'] + keyParts[i:])
            try:
                return self._data[domain]
            except KeyError:
                pass
        return None


def main(config_path, accounts_path):
    # Get certbot params
    domain = os.environ['CERTBOT_DOMAIN']
    if domain.startswith('*.'):
        domain = domain[2:]
    validation_token = os.environ['CERTBOT_VALIDATION']

    # Open main config
    with open(config_path) as fp:
        _config = json.load(fp)
        acmedns_url = _config['acmedns_url']
        if '@' in acmedns_url:
            _tmp = acmedns_url.split('@', 1)
            acmedns_url = '{}/{}'.format(_tmp[0].rsplit('/', 1)[0], _tmp[1])
            basic_auth = _tmp[0].rsplit('/', 1)[1].split(':', 1)
            basic_auth = HTTPBasicAuth(
                *_tmp[0].rsplit('/', 1)[1].split(':', 1))
        else:
            basic_auth = None

    # Init
    client = AcmeDnsClient(acmedns_url, basic_auth)
    storage = Storage(accounts_path)

    # Check that an account already exists in storage
    account = storage.fetch(domain)
    assert account

    # Update the TXT record in acme-dns instance
    client.update_txt_record(account, domain, validation_token)


if __name__ == "__main__":
    # CERTBOT_DOMAIN=www.example.com \
    # CERTBOT_VALIDATION=$(python -c "print 43*'a'") \
    # acme-dns-auth-ossobv.py
    #
    # dig +short TXT _acme-challenge.www.example.com
    #  ^-- create CNAME to www.example.com.YOUR_ACME_CHALLENGE_DOMAIN
    main(CONFIG_PATH, ACCOUNTS_PATH)
