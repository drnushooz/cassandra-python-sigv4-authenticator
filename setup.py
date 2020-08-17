from setuptools import setup, find_packages

with open('VERSION') as version_file:
    version = version_file.read().strip()

with open('sigv4auth/version.py', 'w') as f:
    f.write("VERSION = '%s'\n" % version)

with open('README.md') as readme_file:
    readme = readme_file.read()

install_requires = [
    'boto3',
    'cassandra-driver',
    'six'
]

setup(
    name='cassandra-python-sigv4-authentication',
    version=version,
    author='drnushooz',
    packages=find_packages(exclude=['tests*']),
    url='https://github.com/drnushooz/cassandra-python-sigv4-authenticator',
    license='Apache License 2.0',
    description='AWS Signature v4 support for Datastax Cassandra Python driver',
    long_description=open('README.md').read(),
    install_requires=install_requires,
    keywords='aws cassandra keyspaces sigv4',
    test_suite='tests.TestSignatureV4Authenticator',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
    ],
)