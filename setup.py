import io
import re
from setuptools import setup

with io.open('impact-presidio/__init__.py', 'rt', encoding='utf8') as f:
    version = re.search(r'__version__ = \'(.*?)\'', f.read()).group(1)

setup(
    name='impact-presidio',
    version=version,
    packages=['impact-presidio'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'Flask-AutoIndex >= 0.6.2',
        'gunicorn >= 19.9.0',
        'pyOpenSSL >= 18.0.0',
        'xattr >= 0.9.6'
    ]
)
