import logging
import logging.handlers
import os.path
import sys
import yaml

from .CredentialUtils import initialize_CA_store
from .CredentialUtils import generate_presidio_principal
from .CredentialUtils import _BAD_IDEA_set_use_unverified_jwt


LOGGER = 'impact_presidio_logger'
LOG = None

_ConfFile = '/etc/impact_presidio/config.yaml'

_LogFile = '/var/log/impact_presidio/app.log'
_LogLevel = 'INFO'
_LogFileRetain = '5'
_LogFileSize = '5000000'


def load_presidio_config():
    presidio_config = None
    try:
        with open(_ConfFile, 'r') as cf:
            presidio_config = yaml.safe_load(cf)
    except EnvironmentError as enve:
        print('FATAL ERROR: Could not read configuration file!')
        print('Error message:')
        print(enve)
        print('Cannot proceed; exiting...')
        sys.exit(1)
    except yaml.YAMLError as ye:
        print('FATAL ERROR: Could not load configuration file!')
        print('Error message:')
        print(ye)
        print('Cannot proceed; exiting...')
        sys.exit(1)

    return presidio_config


def configure_logging(presidio_config):
    global LOG
    global _LogFile
    global _LogLevel
    global _LogFileRetain
    global _LogFileSize
    conf_log_file = presidio_config.get('log_file')
    conf_log_level = presidio_config.get('log_level')
    conf_log_retain = presidio_config.get('log_file_retain')
    conf_log_size = presidio_config.get('log_file_size')

    if conf_log_file is not None:
        logfd = None
        try:
            logfd = open(conf_log_file, 'a')
        except EnvironmentError as enve:
            print('ERROR: Unable to open specified log_file:')
            print('%s' % conf_log_file)
            print('Error message:')
            print(enve)
            print('Attempting to proceed using the default...')
        else:
            logfd.close()
            _LogFile = conf_log_file

    try:
        logfd = open(_LogFile, 'a')
    except EnvironmentError as enve:
        print('FATAL ERROR: Unable to open log file:')
        print('%s' % _LogFile)
        print('Error message:')
        print(enve)
        print('Cannot proceed; exiting...')
        sys.exit(1)
    else:
        logfd.close()

    verified_log_level = None
    if conf_log_level is not None:
        try:
            verified_log_level = getattr(logging, conf_log_level)
        except:
            print('ERROR: Invalid value specified for log_level:')
            print('%s' % conf_log_level)
            print('Proceeding using the default')
    verified_log_level = getattr(logging, _LogLevel)
    _LogLevel = verified_log_level

    if (conf_log_retain and
            (type(conf_log_retain) is int)):
        _LogFileRetain = conf_log_retain
    else:
        print('ERROR: Invalid value specified for log_file_retain:')
        print('%s' % conf_log_retain)
        print('Proceeding using the default')

    if (conf_log_size and
            (type(conf_log_size) is int)):
        _LogFileSize = conf_log_size
    else:
        print('ERROR: Invalid value specified for log_file_size:')
        print('%s' % conf_log_size)
        print('Proceeding using the default')

    LOG = logging.getLogger(LOGGER)
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    handler = logging.handlers.RotatingFileHandler(
        _LogFile,
        backupCount=_LogFileRetain,
        maxBytes=_LogFileSize)
    handler.setLevel(_LogLevel)
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
    LOG.info('Logging Started')


def get_project_path(presidio_config):
    project_path = None
    try:
        project_path = os.path.abspath(presidio_config.get('project_path'))
    except:
        LOG.error('\"project_path\" entry not specified in configuration!')
        LOG.error('Cannot proceed; exiting...')
        sys.exit(1)

    return project_path


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
