import logging
import os.path
import sys
import yaml

from impact_presidio.Logging import LOG, LOG_FORMAT, LOG_DATE_FORMAT
from impact_presidio.CredentialUtils import initialize_CA_store
from impact_presidio.CredentialUtils import generate_presidio_principal
from impact_presidio.CredentialUtils import _BAD_IDEA_set_use_unverified_jwt

_ConfFile = '/etc/impact_presidio/config.yaml'


def load_presidio_config():
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    presidio_config = None
    try:
        with open(_ConfFile, 'r') as cf:
            presidio_config = yaml.safe_load(cf)
    except EnvironmentError as enve:
        logging.error('FATAL ERROR: Could not read configuration file!')
        logging.error('Error message:')
        logging.error(enve)
        logging.error('Cannot proceed; exiting...')
        sys.exit(1)
    except yaml.YAMLError as ye:
        logging.error('FATAL ERROR: Could not load configuration file!')
        logging.error('Error message:')
        logging.error(ye)
        logging.error('Cannot proceed; exiting...')
        sys.exit(1)

    return presidio_config


def get_project_path(presidio_config):
    project_path = None
    try:
        project_path = os.path.abspath(presidio_config.get('project_path'))
    except:
        LOG.error('\"project_path\" entry not specified in configuration!')
        LOG.error('Cannot proceed; exiting...')
        sys.exit(1)

    return project_path


def get_web_root(presidio_config):
    default_web_root = '/datasets'
    web_root = presidio_config.get('web_root')

    if type(web_root) is not str:
        LOG.info('\"web_root\" configuration entry missing or invalid.')
        LOG.info(('Proceeding with default value of: %s' % default_web_root))
        web_root = default_web_root

    # Ensure we begin with /
    if (web_root[0] != '/'):
        web_root = ('/' + web_root)

    # Ensure we don't end with /
    if (web_root[-1] == '/'):
        web_root = web_root[:-1]

    return web_root


def get_presidio_principal(presidio_config):
    key_file = presidio_config.get('key_file')

    presidio_principal = None
    if key_file:
        try:
            presidio_principal = generate_presidio_principal(key_file)
        except:
            LOG.error('Error loading key file!')
            LOG.error('Please ensure that the key_file config entry points')
            LOG.error('to the correct file, that the file has the correct')
            LOG.error('format, and that it contains the data that you expect.')
            LOG.error('Cannot proceed; exiting...')
            sys.exit(1)
    else:
        LOG.error('\"key_file\" entry not specified in configuration!')
        LOG.error('Cannot proceed; exiting...')
        sys.exit(1)

    return presidio_principal


def get_safe_server_list(presidio_config):
    safe_servers = presidio_config.get('safe_servers')

    safe_server_list = []
    if safe_servers:
        if type(safe_servers) is str:
            safe_server_list.append(safe_servers)
        elif type(safe_servers) is list:
            safe_server_list += safe_servers
        else:
            LOG.error(('\"safe_servers\" entry incorrectly specified ' +
                       'in configuration!'))
            LOG.error('Cannot proceed; exiting...')
            sys.exit(1)
    else:
        LOG.error('\"safe_servers\" entry not specified in configuration!')
        LOG.error('Cannot proceed; exiting...')
        sys.exit(1)

    return safe_server_list


def configure_safe_result_cache_seconds(presidio_app):
    presidio_config = presidio_app.config['PRESIDIO_CONFIG']
    safe_result_cache_seconds = None

    if presidio_config is not None:
        safe_result_cache_seconds = (
            presidio_config.get('safe_result_cache_seconds')
        )
    else:
        LOG.warning('Presidio app object somehow does not have')
        LOG.warning('PRESIDIO_CONFIG set, when trying to configure:')
        LOG.warning('safe_result_cache_seconds')
        LOG.warning('Proceeding - but this suggests something weird')
        LOG.warning('is going on...')

    if safe_result_cache_seconds is not None:
        if (((type(safe_result_cache_seconds) is int) or
             (type(safe_result_cache_seconds) is float)) and
                (safe_result_cache_seconds >= 0)):
            presidio_app.config['SAFE_RESULT_CACHE_SECONDS'] = (
                safe_result_cache_seconds
            )
        else:
            LOG.warning(('\"safe_result_cache_seconds\" incorrectly ' +
                         'specified in configuration!'))


def configure_ca_store(presidio_config):
    ca_file = presidio_config.get('ca_file')
    if ca_file:
        try:
            initialize_CA_store(ca_file)
        except EnvironmentError:
            LOG.warning('Error loading CA roots!')
            LOG.warning('Please ensure that the ca_file config entry points')
            LOG.warning('to the correct file, that the file has the correct')
            LOG.warning(('format, and that it contains the data that you ' +
                         'expect.'))
            LOG.warning(('Continuing to run - ' +
                         'but presidio may behave unpredictably...'))
    else:
        LOG.warning('ca_file entry not specified in config file!')
        LOG.warning(('Continuing to run - ' +
                     'but presidio may behave unpredictably...'))


def configure_bad_ideas(presidio_config):
    # Please, please don't set any of the below, except for debugging.
    unverified_jwt = presidio_config.get('BAD_IDEA_use_unverified_jwt')
    if unverified_jwt:
        _BAD_IDEA_set_use_unverified_jwt()
