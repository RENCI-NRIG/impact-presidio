import logging
import logging.handlers
import sys

LOGGER = 'impact_presidio_logger'
LOG = None

_LogFile = '/var/log/impact_presidio/app.log'
_LogLevel = 'INFO'
_LogFileRetain = '5'
_LogFileSize = '5000000'


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
