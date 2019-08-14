__version__ = '0.0.1'

import sys
import flask_autoindex

from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template
from flask_autoindex import AutoIndex

from impact_presidio import Config
from impact_presidio.Logging import configure_logging
from impact_presidio.LabelMechs import configure_label_mech
from impact_presidio.CredentialUtils import process_credentials
from impact_presidio.SafeAutoIndex import SafeAutoIndex


# Perform required monkey-patching
flask_autoindex.AutoIndexApplication = SafeAutoIndex

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

presidio_config = Config.load_presidio_config()
configure_logging(presidio_config)

presidio_principal = Config.get_presidio_principal(presidio_config)
safe_server_list = Config.get_safe_server_list(presidio_config)
project_path = Config.get_project_path(presidio_config)

app.config['PRESIDIO_CONFIG'] = presidio_config
app.config['PRESIDIO_PRINCIPAL'] = presidio_principal
app.config['SAFE_SERVER_LIST'] = safe_server_list

Config.configure_ca_store(presidio_config)
Config.configure_safe_result_cache_seconds(app)
configure_label_mech(presidio_config, project_path)

# Sigh. Do we *have* to...?
Config.configure_bad_ideas(presidio_config)

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
