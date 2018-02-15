from distutils.core import setup

setup(
    name='telemetry_email_alerter',
    packages=['telemetry_email_alerter'],
    version='1.0',
    description='Script for subscribing to Arista Telemetry Events and sending email alerts.',
    author='Seb Bacanu',
    author_email='sebastian@arista.com',
    url='https://github.com/aristanetworks/telemetry-email-alerter',
    download_url='https://github.com/aristanetworks/telemetry-email-alerter/archive/v1.0.tar.gz',
    keywords=[
        'alerts',
        'arista',
        'cvp',
        'email',
        'notifications',
        'smtp',
        'telemetry',
    ],
    classifiers=[],
)
