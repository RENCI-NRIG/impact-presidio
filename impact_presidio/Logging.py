import logging
import logging.handlers
import sys

LOGGER = 'impact_presidio_logger'
LOG = logging.getLogger(LOGGER)

_LogFile = '/var/log/impact_presidio/app.log'
_LogLevel = 'INFO'
_LogFileRetain = '5'
_LogFileSize = '5000000'


def configure_logging(presidio_config):
    conf_log_file = presidio_config.get('log_file')
    conf_log_level = presidio_config.get('log_level')
    conf_log_retain = presidio_config.get('log_file_retain')
    conf_log_size = presidio_config.get('log_file_size')

    log_file = _LogFile
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
            log_file = conf_log_file

    if log_file == _LogFile:
        try:
            logfd = open(log_file, 'a')
        except EnvironmentError as enve:
            print('FATAL ERROR: Unable to open log file:')
            print('%s' % _LogFile)
            print('Error message:')
            print(enve)
            print('Cannot proceed; exiting...')
            sys.exit(1)
        else:
            logfd.close()

    log_level = None
    if conf_log_level is not None:
        try:
            log_level = getattr(logging, conf_log_level.upper())
        except:
            print('ERROR: Invalid value specified for log_level:')
            print('%s' % conf_log_level)
            print('Proceeding using the default')
            log_level = getattr(logging, _LogLevel)

    log_retain = _LogFileRetain
    if (conf_log_retain and
            (type(conf_log_retain) is int)):
        log_retain = conf_log_retain
    else:
        print('ERROR: Invalid value specified for log_file_retain:')
        print('%s' % conf_log_retain)
        print('Proceeding using the default')

    log_size = _LogFileSize
    if (conf_log_size and
            (type(conf_log_size) is int)):
        log_size = conf_log_size
    else:
        print('ERROR: Invalid value specified for log_file_size:')
        print('%s' % conf_log_size)
        print('Proceeding using the default')

    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    LOG.setLevel(log_level)
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        backupCount=log_retain,
        maxBytes=log_size)
    handler.setLevel(log_level)
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.info('Logging Started')
