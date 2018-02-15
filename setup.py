from setuptools import setup

with open('./requirements.pip') as dependencies_file:
    dependencies = dependencies_file.read().split('\n')
    dependencies = filter(lambda dep: len(dep) > 0, dependencies)

setup(
    name='telemetry_email_alerter',
    version='1.0.1',
    description='Script for subscribing to Arista Telemetry Events and sending email alerts.',
    author='Seb Bacanu',
    author_email='sebastian@arista.com',
    url='https://github.com/aristanetworks/telemetry-email-alerter',
    download_url='https://github.com/aristanetworks/telemetry-email-alerter/archive/v1.0.0.tar.gz',
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
            'telemetry_email_alerter = telemetry_email_alerter:main',
        ]
    }
)
