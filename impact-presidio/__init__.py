import os.path
import re
import sys
import flask_autoindex
import OpenSSL.crypto as crypto
import hashlib
import base64
import xattr
# import pprint

from flask import Flask, request, abort, render_template, send_file
from flask_autoindex import AutoIndex, RootDirectory, Directory, __autoindex__
from jinja2 import TemplateNotFound

__version__ = '0.0.1'

class SafeAutoIndex(AutoIndex):
    """A Flask AutoIndex application that checks SAFE
    for authorization decisions."""

    template_prefix = ''

    def __init__(self, app, browse_root=None, **silk_options):
        super(SafeAutoIndex, self).__init__(app, browse_root,
                                            **silk_options)
        self.app = app
        self._register_shared_autoindex(app=self.app)

    def is_it_safe(self, path):
        # Stub authorization method, which calls out to SAFE.
        # For now, we merely return the entry we were passed.
        # Todo:
        #
        # 1) Based on the config, choose whether to read the SCID
        # bound to a given path from a .safeaccess file or from an
        # extended attribute associated with the file.
        #
        # 2) Once we have the SCID, check against SAFE (with a pass
        # through an auth cache, potentially); part of what will
        # need to be passed to SAFE is information from the JWT that
        # we will have to fetch out of an Authorization header.
        #
        # For now, we stub this check out; we only show entries that
        # match both of the following conditions: they are labeled
        # with a SCID extended attribute, and that extended
        # attribute has a value of "okSCID"
        file_attrs = xattr.xattr(path)
        attr_key_list = set(file_attrs.list())

        # FIXME: make this extended attribute key configurable
        safe_scid_attr_key = 'user.us.cyberimpact.SAFE.SCID'
        if safe_scid_attr_key in attr_key_list:
            if file_attrs[safe_scid_attr_key] == b'okSCID':
                print("Granting access to %s" % path)
                return True
        print("Refusing access to %s" % path)
        return False

    def safe_entry_generator(self, entries):
        for e in entries:
            if self.is_it_safe(e.abspath):
                yield e

    def render_autoindex(self, path, browse_root=None, template=None,
                         template_context=None, endpoint='.autoindex',
                         show_hidden=None, sort_by='name',
                         mimetype=None):
        """Renders an autoindex with the given path.

        :param path: the relative path.
        :param browse_root: if it is specified, it used to a path which is
                            served by root address.
        :param template: the template name.
        :param template_context:
                             would be passed to the Jinja2 template when
                             rendering an AutoIndex page.
        :param endpoint: an endpoint which is a function.
        :param show_hidden:
                         whether to show hidden files (starting with '.')
        :param sort_by: the property to sort the entrys by.
        :param mimetype:
                     set static mime type for files (no auto detection).
        """
        if browse_root:
            rootdir = RootDirectory(browse_root, autoindex=self)
        else:
            rootdir = self.rootdir
        path = re.sub(r'\/*$', '', path)
        abspath = os.path.join(rootdir.abspath, path)

        if request.cert is None:
            return abort(401)
        print('Path is: %s' % abspath)
        req_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, request.cert)
        print('Client cert serial number is: %s' %
              req_x509.get_serial_number())

        dnStr = ""
        for k, v in req_x509.get_subject().get_components():
            dnStr = (dnStr +
                     "/" +
                     k.decode() +
                     "=" +
                     v.decode())
        print('Client cert distinguished name is: %s' % dnStr)

        req_x509_pub_key = req_x509.get_pubkey()
        print('Client cert public key (PEM) is:\n%s' %
              crypto.dump_publickey(crypto.FILETYPE_PEM,
                                    req_x509_pub_key))
        sha256Hasher = hashlib.sha256()
        sha256Hasher.update(crypto.dump_publickey(crypto.FILETYPE_ASN1,
                                                  req_x509_pub_key))
        safe_principal = base64.urlsafe_b64encode(sha256Hasher.digest())
        print('Client cert public key as SAFE principal ID: %s' %
              safe_principal)
        print('Client address:port is: %s:%s' %
              (request.environ['REMOTE_ADDR'],
               request.environ['REMOTE_PORT']))

        # print('All request information follows:\n%s' %
        #       pprint.pformat(request.__dict__, depth=5))

        if os.path.isdir(abspath):
            sort_by = request.args.get('sort_by', sort_by)
            order = {'asc': 1, 'desc': -1}[request.args.get('order', 'asc')]
            curdir = Directory(path, rootdir)
            if show_hidden is None:
                show_hidden = self.show_hidden
            entries = curdir.explore(sort_by=sort_by, order=order,
                                     show_hidden=show_hidden)

            # We wrap the "entries" generator here, with our own.
            # The "safe_entries" generator will call out to SAFE,
            # which will, in turn, make the decision of whether to display
            # a given entry.
            safe_entries = self.safe_entry_generator(entries)

            if callable(endpoint):
                endpoint = endpoint.__name__
            context = {}
            if template_context is not None:
                context.update(template_context)
            if self.template_context is not None:
                context.update(self.template_context)
            context.update(
                curdir=curdir, entries=safe_entries,
                sort_by=sort_by, order=order, endpoint=endpoint)
            if template:
                return render_template(template, **context)
            try:
                template = '{0}autoindex.html'.format(self.template_prefix)
                return render_template(template, **context)
            except TemplateNotFound:
                template = '{0}/autoindex.html'.format(__autoindex__)
                return render_template(template, **context)
        elif (os.path.isfile(abspath) and self.is_it_safe(abspath)):
            if mimetype:
                return send_file(abspath, mimetype=mimetype)
            else:
                return send_file(abspath)
        else:
            return abort(404)


# Monkey-patching the Flask AutoIndex application with our own,
# that calls SAFE to authorize access to files and directories.
flask_autoindex.AutoIndexApplication = SafeAutoIndex

app = Flask(__name__)
# FIXME: Make this configuration dynamic, using a config file.
app.config['PROJECT_PATH'] = "projects/"

project_path = os.path.abspath(app.config['PROJECT_PATH'])
autoIndex = AutoIndex(app, browse_root=project_path)


@app.before_request
def checkssl():
    try:
        sock = request.environ['gunicorn.socket']
    except KeyError:
        sock = None

    if sock:
        request.cert = sock.getpeercert(binary_form=True)
    else:
        request.cert = None


@app.errorhandler(401)
def handle_unauthorized(error):
    return render_template('unauthorized.html'), 401


# We need to make clear that this needs to be wrapped by Gunicorn,
# in case someone decides they want to try running this directly via
# "flask run"
if __name__ == "__main__":
    print('This Flask application relies on being wrapped using Gunicorn.')
    print('Please examine the example run script before proceeding.')
    sys.exit(0)
