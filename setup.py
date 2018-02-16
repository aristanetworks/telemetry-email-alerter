import codecs

from setuptools import setup

with open('./requirements.pip') as dependencies_file:
    dependencies = dependencies_file.read().split('\n')
    dependencies = filter(lambda dep: len(dep) > 0, dependencies)

with codecs.open('./README.rst', encoding='utf8') as readme_file:
    readme = readme_file.read()

setup(
    name='telemetry_email_alerter',
    version='1.0.7',
    description='Script for subscribing to Arista Telemetry Events and sending email alerts.',
    long_description=readme,
    author='Arista Telemetry Team',
    url='https://github.com/aristanetworks/telemetry-email-alerter',
    download_url='https://github.com/aristanetworks/telemetry-email-alerter/archive/v1.0.7.tar.gz',
    keywords='alerts arista cvp email notifications smtp telemetry',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
    ],
    packages=['telemetry_email_alerter'],
    install_requires=dependencies,
    entry_points={
        'console_scripts': [
            'telemetry-email-alerter = telemetry_email_alerter.__main__:main',
        ]
    }
)
