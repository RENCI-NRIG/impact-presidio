import os.path
import re
import OpenSSL.crypto as crypto

from flask import request, abort, render_template, send_file
from flask_autoindex import AutoIndex, RootDirectory, Directory, __autoindex__
from jinja2 import TemplateNotFound

from .LabelMechs import check_labels
from .CredentialUtils import generate_safe_principal_id


class SafeAutoIndex(AutoIndex):
    """A Flask AutoIndex application that checks SAFE
    for authorization decisions."""

    template_prefix = ''

    def __init__(self, app, browse_root=None, **silk_options):
        super(SafeAutoIndex, self).__init__(app, browse_root,
                                            **silk_options)
        self.app = app
        self._register_shared_autoindex(app=self.app)

    def safe_check_access(self):
        # Stub, until we have all parameters ready.
        return True

    def is_it_safe(self, path, dataset_SCID):
        if check_labels(path, dataset_SCID):
            return self.safe_check_access()
        return False

    def safe_entry_generator(self, entries, dataset_SCID):
        for e in entries:
            if self.is_it_safe(e.abspath, dataset_SCID):
                yield e

    def render_autoindex(self, path, browse_root=None, template=None,
                         template_context=None, endpoint='.autoindex',
                         show_hidden=None, sort_by='name', order=1,
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
            return abort(401, "Client certificate not found.")
        if request.verified_jwt_claims is None:
            return abort(401, "Notary Service JWT not found.")

        print('Path is: %s' % abspath)
        req_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, request.cert)
        # print('Client cert serial number is: %s' %
        #       req_x509.get_serial_number())

        # dnStr = ""
        # for k, v in req_x509.get_subject().get_components():
        #     dnStr = (dnStr +
        #              "/" +
        #              k.decode() +
        #              "=" +
        #              v.decode())
        # print('Client cert distinguished name is: %s' % dnStr)

        req_x509_pub_key = req_x509.get_pubkey()
        safe_principal = generate_safe_principal_id(req_x509_pub_key)
        # print('Client cert public key (PEM) is:\n%s' %
        #       crypto.dump_publickey(crypto.FILETYPE_PEM,
        #                             req_x509_pub_key))
        print('Client cert public key as SAFE principal ID: %s' %
              safe_principal)
        print('Client address:port is: %s:%s' %
              (request.environ['REMOTE_ADDR'],
               request.environ['REMOTE_PORT']))

        dataset_SCID = request.verified_jwt_claims.get('data-set')
        if dataset_SCID is None:
            return abort(401, "Unable to find data-set in JWT claims.")

        if os.path.isdir(abspath):
            sort_by = request.args.get('sort_by', sort_by)
            if sort_by[0] in ['-', '+']:
                order = {'+': 1, '-': -1}[sort_by[0]]
                sort_by = sort_by[1::]
            else:
                order = (
                    {'asc': 1, 'desc': -1}[request.args.get('order', 'asc')])
            curdir = Directory(path, rootdir)
            if show_hidden is None:
                show_hidden = self.show_hidden
            entries = curdir.explore(sort_by=sort_by, order=order,
                                     show_hidden=show_hidden)

            # We wrap the "entries" generator here, with our own.
            # The "safe_entries" generator will call out to SAFE,
            # which will, in turn, make the decision of whether to display
            # a given entry.
            safe_entries = self.safe_entry_generator(entries, dataset_SCID)

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
