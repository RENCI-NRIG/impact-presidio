from datetime import datetime, timedelta
from flask import request, abort, render_template, send_file
from flask_autoindex import AutoIndex, RootDirectory, Directory, __autoindex__
from jinja2 import TemplateNotFound
from json import dumps as json_dumps
from os.path import isdir, isfile, join
from random import shuffle
from requests import post
from re import sub as re_sub
from timeit import default_timer as timer

from impact_presidio.Logging import LOG, METRICS_LOG
from impact_presidio.LabelMechs import check_labels

dt_now = datetime.now


class SafeAutoIndex(AutoIndex):
    """A Flask AutoIndex application that checks SAFE
    for authorization decisions."""

    template_prefix = ''
    safe_result_cache = dict()
    safe_result_cache_seconds = 2  # Seconds before results are stale

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
            LOG.warning('BAD IDEA: Bypassing SAFE servers requested!')
            LOG.warning('BAD IDEA: This option is for debugging ONLY!')
            LOG.warning(('BAD IDEA: Please, please don\'t ' +
                         'use this in production!'))
            LOG.warning('BAD IDEA: You have been warned...')
            return True

        presidio_principal = self.app.config['PRESIDIO_PRINCIPAL']
        presidio_principal = presidio_principal.decode('utf-8')
        methodParams = [dataset_SCID, user_DN, ns_token, project_ID]
        payload_dict = {'principal': presidio_principal,
                        'methodParams': methodParams}
        payload = json_dumps(payload_dict)
        headers = {'Content-Type': 'application/json',
                   'Accept-Charset': 'UTF-8'}

        safe_server_list = self.app.config['SAFE_SERVER_LIST']
        shuffle(safe_server_list)
        for server in safe_server_list:
            safe_result = None
            url = (f'http://{server}/access')

            # Check the cache first...
            safe_result = self.query_safe_result_cache(url, methodParams)
            if safe_result is not None:
                LOG.debug('Using cached SAFE query result')
                LOG.debug((f'Access decision for dataset {user_DN} '
                           f'by {dataset_SCID} was: {safe_result}'))
                return safe_result

            # Nothing in the cache? Time to ask SAFE.
            LOG.info((f'Trying to query SAFE with following '
                      f'parameters: {payload}'))

            resp = None
            try:
                resp = post(url, data=payload,
                            headers=headers, timeout=4)
            except Exception as e:
                LOG.warning((f'Error occurred while trying to '
                             f'query SAFE server: {server}'))
                LOG.warning('Error message:')
                LOG.warning(e)
                LOG.warning('Trying next SAFE server in list (if any)...')
                continue

            status_code = None
            if resp:
                status_code = resp.status_code
                try:
                    safe_result = resp.json()
                except Exception as e:
                    LOG.warning((f'Error occurred while parsing response '
                                 f'from SAFE server: {server}'))
                    LOG.warning('Error message:')
                    LOG.warning(e)
                    LOG.warning('Trying next SAFE server in list (if any)...')
                    continue
                finally:
                    resp.close()

            LOG.debug(f'Status code from SAFE is: {status_code}')
            if status_code == 200:
                # Default to deny.
                result_message = (
                    f'SAFE did not permit access for {user_DN} '
                    f'to dataset {dataset_SCID}'
                )
                result = False

                if (safe_result.get('result') == 'succeed'):
                    # SAFE reported affirmative result.
                    result_message = (
                        f'SAFE permitted access for {user_DN} '
                        f'to dataset {dataset_SCID}'
                    )
                    result = True

                LOG.debug(result_message)
                self.update_safe_result_cache(url, methodParams, result)
                return result
            else:
                LOG.debug((f'SAFE server {server} returned '
                           f'status code {status_code}'))
                LOG.debug('Trying next SAFE server in list (if any)...')
                continue

        LOG.warning(('None of the configured SAFE servers replied;' +
                     'denying access.'))
        return False

    def is_it_safe(self, path, dataset_SCID,
                   user_DN, ns_token, project_ID):
        if check_labels(path, dataset_SCID):
            return self.safe_check_access(dataset_SCID, user_DN,
                                          ns_token, project_ID)
        return False

    def safe_entry_generator(self, abspath, request_uuid,
                             entries, dataset_SCID,
                             user_DN, ns_token, project_ID):
        entries_start = timer()

        for e in entries:
            if (self.is_it_safe(e.abspath, dataset_SCID,
                                user_DN, ns_token, project_ID)):
                yield e

        entries_end = timer()
        entries_message = (
            f'Processing entries for request {request_uuid} '
            f'on directory {abspath} '
            f'completed in {entries_end - entries_start} seconds'
        )
        METRICS_LOG.info(entries_message)

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
                     set static mime type for files (no auto detection)."""

        if browse_root:
            rootdir = RootDirectory(browse_root, autoindex=self)
        else:
            rootdir = self.rootdir
        path = re_sub(r'\/*$', '', path)
        abspath = join(rootdir.abspath, path)

        if request.cert is None:
            return abort(401, 'Client certificate not found.')
        if request.verified_jwt_claims is None:
            return abort(401, 'Notary Service JWT not found.')

        LOG.debug('Path is: %s' % abspath)

        dataset_SCID = request.verified_jwt_claims.get('data-set')
        if dataset_SCID is None:
            return abort(401, 'Unable to find data-set in JWT claims.')
        user_DN = request.verified_jwt_claims.get('sub')
        if user_DN is None:
            return abort(401, 'Unable to find sub in JWT claims.')
        ns_token = request.verified_jwt_claims.get('ns-token')
        if ns_token is None:
            return abort(401, 'Unable to find ns-token in JWT claims.')
        project_ID = request.verified_jwt_claims.get('project-id')
        if project_ID is None:
            return abort(401, 'Unable to find project-id in JWT claims.')

        if isdir(abspath):
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
            safe_entries = self.safe_entry_generator(abspath,
                                                     request.uuid,
                                                     entries,
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
        elif (isfile(abspath) and
              self.is_it_safe(abspath, dataset_SCID, user_DN,
                              ns_token, project_ID)):
            if mimetype:
                return send_file(abspath, mimetype=mimetype)
            else:
                return send_file(abspath)
        else:
            return abort(404)

    def query_safe_result_cache(self, url, methodParams):
        key = f'{url}{methodParams}'
        val = self.safe_result_cache.get(key)
        if val:
            result, expire_time = val
            if (dt_now() < expire_time):
                return result
        return None

    def update_safe_result_cache(self, url, methodParams, result):
        if ((len(self.safe_result_cache) == 0) and
                (self.safe_result_cache_seconds != 0)):
            # Initialize cache config
            expire_seconds = self.app.config.get('SAFE_RESULT_CACHE_SECONDS')
            if expire_seconds is not None:
                self.safe_result_cache_seconds = expire_seconds
            else:
                LOG.info('Using default value.')
            LOG.info((f'SAFE result cache expiry time is '
                      f'{self.safe_result_cache_seconds} seconds.'))

        key = f'{url}{methodParams}'
        expire_time = (dt_now() +
                       timedelta(0, self.safe_result_cache_seconds))
        self.safe_result_cache[key] = (result, expire_time)
