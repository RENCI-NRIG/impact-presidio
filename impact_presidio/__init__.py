__version__ = '0.0.1'

import os.path
import sys
import flask_autoindex
import yaml

from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template
from flask_autoindex import AutoIndex

from .SafeAutoIndex import SafeAutoIndex
from .LabelMechs import configure_label_mech
from .CredentialUtils import process_credentials, initialize_CA_store
from .CredentialUtils import generate_presidio_principal
from .CredentialUtils import _BAD_IDEA_set_use_unverified_jwt

_ConfFile = '/etc/impact_presidio/config.yaml'

# Perform required monkey-patching
flask_autoindex.AutoIndexApplication = SafeAutoIndex

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

presidio_config = None
try:
    with open(_ConfFile, 'r') as cf:
        presidio_config = yaml.safe_load(cf)
except EnvironmentError as enve:
    print('Encountered error while attempting to read configuration file!')
    print('Backtrace follows:')
    print(enve)
    print('Cannot proceed; exiting...')
    sys.exit(1)
except yaml.YAMLError as ye:
    print('Encountered error loading configuration file!')
    print('Backtrace follows:')
    print(ye)
    print('Cannot proceed; exiting...')
    sys.exit(1)

app.config['PRESIDIO_CONFIG'] = presidio_config

try:
    project_path = os.path.abspath(presidio_config.get('project_path'))
except:
    print('\"project_path\" entry not specified in configuration!')
    print('Cannot proceed; exiting...')
    sys.exit(1)

key_file = presidio_config.get('key_file')
presidio_principal = None
if key_file:
    try:
        presidio_principal = generate_presidio_principal(key_file)
    except:
        print('Error loading key file!')
        print('Please ensure that the key_file config entry points to the')
        print('correct file, that the file has the correct format, and that')
        print('it contains the data that you expect.')
        print('Cannot proceed; exiting...')
        sys.exit(1)
else:
    print('\"key_file\" entry not specified in configuration!')
    print('Cannot proceed; exiting...')
    sys.exit(1)
app.config['PRESIDIO_PRINCIPAL'] = presidio_principal

safe_servers = presidio_config.get('safe_servers')
safe_server_list = []
if safe_servers:
    if type(safe_servers) is str:
        safe_server_list.append(safe_servers)
    elif type(safe_servers) is list:
        safe_server_list += safe_servers
    else:
        print('\"safe_servers\" entry incorrectly specified in configuration!')
        print('Cannot proceed; exiting...')
        sys.exit(1)
else:
    print('\"safe_servers\" entry not specified in configuration!')
    print('Cannot proceed; exiting...')
    sys.exit(1)
app.config['SAFE_SERVER_LIST'] = safe_server_list

ca_file = presidio_config.get('ca_file')
if ca_file:
    try:
        initialize_CA_store(ca_file)
    except EnvironmentError as enve:
        print('Error loading CA roots!')
        print('Please ensure that the ca_file config entry points to the')
        print('correct file, that the file has the correct format, and that')
        print('it contains the data that you expect.')
        print('Continuing to run - but presidio may behave unpredictably...')
else:
    print('ca_file entry not specified in config file!')
    print('Continuing to run - but presidio may behave unpredictably...')

label_mech = presidio_config.get('label_mech')
configure_label_mech(label_mech, presidio_config, project_path)

# Please, please don't use the below, except for debugging.
unverified_jwt = presidio_config.get('BAD_IDEA_use_unverified_jwt')
if unverified_jwt:
    _BAD_IDEA_set_use_unverified_jwt()

autoIndex = AutoIndex(app, browse_root=project_path, add_url_rules=False)

# Ensure that process_credentials is run before any request.
app.before_request(process_credentials)


@app.route('/', methods=['POST', 'GET', 'PUT'])
@app.route('/<path:path>', methods=['POST', 'GET', 'PUT'])
def autoindex(path='.'):
    return autoIndex.render_autoindex(path)


@app.errorhandler(401)
def handle_unauthorized(error):
    return (render_template('unauthorized.html', reason=error.description),
            401)


# We need to make clear that this needs to be wrapped by Gunicorn,
# in case someone decides they want to try running this directly via
# "flask run"
if __name__ == "__main__":
    print('This Flask application relies on being wrapped using Gunicorn.')
    print('Please examine the Dockerfile before proceeding.')
    sys.exit(0)
