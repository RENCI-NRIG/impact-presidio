#!/usr/bin/env python3

# Credit due to Max Klymyshyn:
# https://gist.github.com/joymax/8ffc63fd901c6de7073c18ae023d5cbc#file-wsgi_profiler_conf-py
# Code adapted to Python 3.

import cProfile
import pstats
import logging
import os
import time

from io import StringIO

PROFILE_LIMIT = int(os.environ.get("PROFILE_LIMIT", 120))
PROFILER = bool(int(os.environ.get("PROFILER", 1)))

print("""

# ** USAGE:
$ PROFILE_LIMIT=100 gunicorn -c ./wsgi_profiler.py wsgi

# ** TIME MEASUREMENTS ONLY:
$ PROFILER=0 gunicorn -c ./wsgi_profiler.py wsgi

""")


def profiler_enable(worker, req):
    worker.profile = cProfile.Profile()
    worker.profile.enable()
    worker.log.info("PROFILING %d: %s" % (worker.pid, req.uri))


def profiler_summary(worker, req):
    s = StringIO()
    worker.profile.disable()
    ps = pstats.Stats(worker.profile, stream=s).sort_stats('cumulative')
    ps.print_stats(PROFILE_LIMIT)

    logging.error(f'\n[{worker.pid}] [INFO] [req.method] URI {req.uri}')
    logging.error(f'[{worker.pid}] [INFO] {s.getvalue()}')


def pre_request(worker, req):
    worker.start_time = time.time()
    if PROFILER is True:
        profiler_enable(worker, req)


def post_request(worker, req, *args):
    total_time = time.time() - worker.start_time
    logging.error("\n[%d] [INFO] [%s] Load Time: %.3fs\n" % (
        worker.pid, req.method, total_time))
    if PROFILER is True:
        profiler_summary(worker, req)
