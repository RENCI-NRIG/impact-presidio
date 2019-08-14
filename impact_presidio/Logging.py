import logging
import logging.handlers
import sys

LOGGER = 'impact_presidio_logger'
LOG = logging.getLogger(LOGGER)
LOG_FORMAT = '%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S %z'

_LogFile = '/var/log/impact_presidio/app.log'
_LogLevel = 'INFO'
_LogFileRetain = '5'
_LogFileSize = '5000000'


def configure_logging(presidio_config):
    conf_log_file = presidio_config.get('log_file')
    conf_log_level = presidio_config.get('log_level')
    conf_log_retain = presidio_config.get('log_file_retain')
    conf_log_size = presidio_config.get('log_file_size')

    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    log_file = _LogFile
    if conf_log_file is not None:
        logfd = None
        try:
            logfd = open(conf_log_file, 'a')
        except EnvironmentError as enve:
            logging.warning('ERROR: Unable to open configured log_file:')
            logging.warning('%s' % conf_log_file)
            logging.warning('Error message:')
            logging.warning(enve)
            logging.warning('Attempting to proceed using the default...')
        else:
            logfd.close()
            log_file = conf_log_file

    if log_file == _LogFile:
        try:
            logfd = open(log_file, 'a')
        except EnvironmentError as enve:
            logging.error('FATAL ERROR: Unable to open log file:')
            logging.error('%s' % _LogFile)
            logging.error('Error message:')
            logging.error(enve)
            logging.error('Cannot proceed; exiting...')
            sys.exit(1)
        else:
            logfd.close()

    log_level = None
    if conf_log_level is not None:
        try:
            log_level = getattr(logging, conf_log_level.upper())
        except:
            logging.warning('ERROR: Invalid value specified for log_level:')
            logging.warning('%s' % conf_log_level)
            logging.warning('Proceeding using the default')
            log_level = getattr(logging, _LogLevel)

    log_retain = _LogFileRetain
    if (conf_log_retain and
            (type(conf_log_retain) is int)):
        log_retain = conf_log_retain
    else:
        logging.warning('ERROR: Invalid value specified for log_file_retain:')
        logging.warning('%s' % conf_log_retain)
        logging.warning('Proceeding using the default')

    log_size = _LogFileSize
    if (conf_log_size and
            (type(conf_log_size) is int)):
        log_size = conf_log_size
    else:
        logging.warning('ERROR: Invalid value specified for log_file_size:')
        logging.warning('%s' % conf_log_size)
        logging.warning('Proceeding using the default')

    LOG.setLevel(log_level)
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        backupCount=log_retain,
        maxBytes=log_size)
    handler.setLevel(log_level)
    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
    LOG.propagate = False
    LOG.info('Logging Started')
