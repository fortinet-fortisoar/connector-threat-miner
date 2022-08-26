""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from connectors.core.connector import get_logger, ConnectorError
logger = get_logger('threatminer')


class ThreatMiner(object):

    def __init__(self, config):
        self.server_url = config.get('server').strip()
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://{0}/'.format(self.server_url)

    def make_api_call(self, endpoint=None, method='GET', health_check=False):
        url = self.server_url + endpoint
        logger.debug('Final url to make rest call is: {0}'.format(url))
        try:
            logger.debug('Making a request with {0} method.'.format(method))
            response = requests.request(method, url)
            if response.status_code in [200]:
                if health_check:
                    return response
                try:
                    logger.debug(
                        'Converting the response into JSON format after returning with status code: {0}'.format(
                            response.status_code))
                    response_data = response.json()
                    return {'status': response_data['status'] if 'status' in response_data else 'Success', 'data': response_data}
                except Exception as e:
                    response_data = response.content
                    logger.error('Failed with an error: {0}. The response details are: {1}'.format(e, response_data))
                    return {'status': 'Failure', 'data': response_data}
            else:
                logger.error('Failed with response {0}'.format(response))
                raise ConnectorError(
                    {'status': 'Failure', 'status_code': str(response.status_code), 'response': response})
        except Exception as e:
            logger.exception(str(e))
            raise ConnectorError(str(e))

    def get_domain_details(self, params):
        q_type = params.get('query_type')
        if q_type == 'WHOIS':
            rt = 1
        elif q_type == 'Passive DNS':
            rt = 2
        elif q_type == 'Example Query URI':
            rt = 3
        elif q_type == 'Related Samples (hash only)':
            rt = 4
        elif q_type == 'Subdomains':
            rt = 5
        else:
            rt = 6
        endpoint = '/v2/domain.php?q={0}&rt={1}'.format(params.get('domain_name'), rt)
        return self.make_api_call(endpoint=endpoint)

    def get_ip_details(self, params):
        q_type = params.get('query_type')
        if q_type == 'WHOIS':
            rt = 1
        elif q_type == 'Passive DNS':
            rt = 2
        elif q_type == 'Related Samples (Hash only)':
            rt = 4
        elif q_type == 'SSL Certificates (hash only)':
            rt = 5
        else:
            rt = 6
        endpoint = '/v2/host.php?q={0}&rt={1}'.format(params.get('ip_address'), rt)
        return self.make_api_call(endpoint=endpoint)

    def get_file_details(self, params):
        q_type = params.get('query_type')
        if q_type == 'Metadata':
            rt = 1
        elif q_type == 'HTTP Traffic':
            rt = 2
        elif q_type == 'Hosts (domains and IPs)':
            rt = 3
        elif q_type == 'Mutants':
            rt = 4
        elif q_type == 'AV detections':
            rt = 6
        else:
            rt = 7
        endpoint = '/v2/sample.php?q={0}&rt={1}'.format(params.get('file_hash'), rt)
        return self.make_api_call(endpoint=endpoint)

    def get_import_hash_details(self, params):
        q_type = params.get('query_type')
        if q_type == 'Samples':
            rt = 1
        endpoint = '/v2/imphash.php?q={0}&rt={1}'.format(params.get('imphash'), rt)
        return self.make_api_call(endpoint=endpoint)

    def get_ssdeep_details(self, params):
        q_type = params.get('query_type')
        if q_type == 'Samples':
            rt = 1
        endpoint = '/v2/ssdeep.php?q={0}&rt={1}'.format(params.get('ssdeep'), rt)
        return self.make_api_call(endpoint=endpoint)

    def get_email_details(self, params):
        endpoint = '/v2/email.php?q={0}&rt=1'.format(params.get('email'))
        return self.make_api_call(endpoint=endpoint)


def _run_operation(config, params):
    tm_obj = ThreatMiner(config)
    command = getattr(ThreatMiner, params['operation'])
    response = command(tm_obj, params)
    return response


def _check_health(config):
    try:
        tm_obj = ThreatMiner(config)
        tm_obj.make_api_call(endpoint='/v2/domain.php?q=vwrm.com', health_check=True)
        return True
    except Exception as err:
        logger.exception('Health check failed with: {0}'.format(err))
        raise ConnectorError('Health check failed with: {0}'.format(err))
