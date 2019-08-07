import os.path
import re
import requests

from flask import request, abort, render_template, send_file
from flask_autoindex import AutoIndex, RootDirectory, Directory, __autoindex__
from jinja2 import TemplateNotFound

from .LabelMechs import check_labels


class SafeAutoIndex(AutoIndex):
    """A Flask AutoIndex application that checks SAFE
    for authorization decisions."""

    template_prefix = ''

    def __init__(self, app, browse_root=None, **silk_options):
        super(SafeAutoIndex, self).__init__(app, browse_root,
                                            **silk_options)
        self.app = app
        self._register_shared_autoindex(app=self.app)

    def safe_check_access(self, dataset_SCID, user_DN,
                          ns_token, project_ID):
        pconf = self.app.config['PRESIDIO_CONFIG']
        bypass_safe = pconf.get('BAD_IDEA_bypass_safe_servers')
        if bypass_safe:
            print('BAD IDEA: Bypassing SAFE servers requested!')
            print('BAD IDEA: This option is for debugging ONLY!')
            print('BAD IDEA: Please, please don\'t use this in production!')
            print('BAD IDEA: You have been warned...')
            return True

        presidio_principal = self.app.config['PRESIDIO_PRINCIPAL']
        safe_server_list = self.app.config['SAFE_SERVER_LIST']
        for server in safe_server_list:
            url = ('http://' + server + '/access')
            payload = ('{ "principal": "' +
                       presidio_principal +
                       '", "methodParams": [ "' +
                       dataset_SCID +
                       '", "' +
                       user_DN +
                       '", "' +
                       ns_token +
                       '", "' +
                       project_ID +
                       '" ] }')
            headers = {'Content-Type': 'application/json',
                       'Accept-Charset': 'UTF-8'}
            print('Trying to query SAFE with following parameters: %s' %
                  payload)
            resp = requests.post(url, data=payload, headers=headers, timeout=4)
            status_code = resp.status_code
            safe_result = resp.json
            resp.close()

            print('Status code from SAFE is: %s' % status_code)
            if status_code == 200:
                if (safe_result.get('result') == 'succeed'):
                    print('SAFE permitted access for %s to dataset %s' %
                          (user_DN, dataset_SCID))
                    return True
            else:
                print('SAFE server %s returned status code %s' %
                      (server, status_code))
                print('Trying next SAFE server in list (if any)...')

        # None of the configured servers returned a successful result;
        # Log the failure, return False, and move on.
        return False

    def is_it_safe(self, path, dataset_SCID,
                   user_DN, ns_token, project_ID):
        if check_labels(path, dataset_SCID):
            return self.safe_check_access(dataset_SCID, user_DN,
                                          ns_token, project_ID)
        return False

    def safe_entry_generator(self, entries, dataset_SCID,
                             user_DN, ns_token, project_ID):
        for e in entries:
            if (self.is_it_safe(e.abspath, dataset_SCID,
                                user_DN, ns_token, project_ID)):
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

        dataset_SCID = request.verified_jwt_claims.get('data-set')
        if dataset_SCID is None:
            return abort(401, "Unable to find data-set in JWT claims.")
        user_DN = request.verified_jwt_claims.get('sub')
        if user_DN is None:
            return abort(401, "Unable to find sub in JWT claims.")
        ns_token = request.verified_jwt_claims.get('ns-token')
        if ns_token is None:
            return abort(401, "Unable to find ns-token in JWT claims.")
        project_ID = request.verified_jwt_claims.get('project-id')
        if project_ID is None:
            return abort(401, "Unable to find project-id in JWT claims.")

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
            safe_entries = self.safe_entry_generator(entries,
                                                     dataset_SCID,
                                                     user_DN,
                                                     ns_token,
                                                     project_ID)

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
