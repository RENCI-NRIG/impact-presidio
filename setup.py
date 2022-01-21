import io
import re
from setuptools import setup

with io.open('impact_presidio/__init__.py', 'rt', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*?)\'', f.read()).group(1)

setup(
    name='impact_presidio',
    version=version,
    packages=['impact_presidio'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'Flask-AutoIndex >= 0.6.2',
        'gunicorn >= 19.9.0',
        'gevent >= 1.4',
        'pyOpenSSL >= 18.0.0',
        'pem >= 19.1.0',
        'PyYAML >= 3.13',
        'requests >= 2.22.0',
        'xattr >= 0.9.6',
        'ns_jwt >= 0.1.2',
        'jwcrypto >= 1.0'
    ]
)
