from setuptools import setup
import re
import os
import codecs
from setuptools import find_packages
here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with codecs.open(os.path.join(here, *parts), 'r') as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


with open('requirements.txt', 'r') as f:
    required = f.read().splitlines()

setup(
    version=find_version("neuroglancer_auth", "__init__.py"),
    name='neuroglancer_auth',
    description='an authorization service for neuroglancer related services ',
    author='Chris Jordan',
    author_email='chris@eyewire.org',
    url='https://github.com/seung-lab/neuroglancer-auth',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=required
)
