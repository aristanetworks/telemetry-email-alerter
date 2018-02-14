#!/usr/bin/env python

import argparse
from Crypto.Hash import SHA256
from email.mime.text import MIMEText
import getpass
import json
import logging
import random
import requests
import string
import smtplib
import ssl
import websocket
import threading
import time

API_VERSION_1 = '1.0.0'
AUTH_PATH = 'cvpservice/login/authenticate.do'
GET = 'get'
SUBSCRIBE = 'subscribe'


class TelemetryWs(object):
    """
    Class to handle connection methods required to get
    and subscribe to steaming data.
    """

    def __init__(self, cmd_args, passwords):
        super(TelemetryWs, self).__init__()

        if cmd_args.noTelemetrySsl:
            telemetry_ws = 'ws://{}/aeris/v1/wrpc/'.format(cmd_args.telemetryUrl)
            self.socket = websocket.WebSocketApp(
                telemetry_ws,
                on_message=self.on_message,
                on_error=self.on_error,
                on_close=self.on_close,
            )
        else:  # login and setup wss
            credentials = {
                'userId': cmd_args.telemetryUsername,
                'password': passwords['telemetryPassword'],
            }
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            }
            request = requests.post(
                'https://{}/{}'.format(cmd_args.telemetryUrl, AUTH_PATH),
                data=json.dumps(credentials), headers=headers,
                verify=not cmd_args.noSslValidation,
            )

            if request.status_code == 200:
                logging.info('Successfully logged in to Telemetry.')
                headers = [
                    'Cookie: session_id={}'.format(request.json()['sessionId']),
                    'Cache-Control: no-cache',
                    'Pragma: no-cache',
                ]
                telemetry_ws = 'wss://{}/aeris/v1/wrpc/'.format(cmd_args.telemetryUrl)
                self.socket = websocket.WebSocketApp(
                    telemetry_ws,
                    on_message=self.on_message,
                    on_error=self.on_error,
                    on_close=self.on_close,
                    header=headers,
                )
            else:
                logging.error('Telemetry credentials invalid. Could not log in.')
                exit()

        if cmd_args.noSmtpSsl:
            self.server = smtplib.SMTP(cmd_args.smtpServer, cmd_args.port)
        else:
            self.server = smtplib.SMTP_SSL(cmd_args.smtpServer, cmd_args.port)

        if cmd_args.smtpUsername:
            try:
                self.server.login(cmd_args.userName, passwords['smtpUsername'])
            except Exception as e:
                print e
                exit()

        self.config = cmd_args
        self.devices = {}
        self.devices_get_token = None
        self.devices_sub_token = None
        self.events_token = None
        self.socket.on_open = self.on_run

    def on_run(self, _):
        """
        Methods to run when the ws connects
        """
        logging.info('Websocket connected.')
        self.get_and_subscribe_devices()
        self.get_events()

    def send_message(self, command, token, args):
        """
        Formats a message to be send to Telemetry WS server
        """
        data = {
            'token': token,
            'command': command,
            'params': args,
            'version': API_VERSION_1,
        }

        json_data = json.dumps(data)
        logging.debug('Sending request: {}'.format(json_data))
        self.socket.send(json_data)

    @staticmethod
    def on_close(_):
        """
        Run when ws closes.
        """
        logging.info('Websocket connection closed.')

    @staticmethod
    def on_error(_, error):
        """
        Print websocket error
        """
        if type(error) is KeyboardInterrupt:
            return

        logging.error('Websocket connection error: {}'.format(error))

    @staticmethod
    def make_token():
        """
        Generate request token
        """
        seed = ''.join(random.choice(string.ascii_uppercase + string.digits)
                       for _ in range(20))
        token = SHA256.new(seed).hexdigest()[0:38]
        return token

    def on_message(self, _, message):
        """
        Print message received from websocket
        """
        logging.debug('Received message: {}'.format(message))
        data = json.loads(message)

        if 'result' not in data:
            return

        if data['token'] == self.events_token:
            event_updates = []
            for result in data['result']:
                for notification in result['Notifications']:
                    if 'updates' not in notification:
                        continue
                    for key, update in notification['updates'].items():
                        event_updates.append(update['value'])

            for event in event_updates:
                self.send_email(event)
        elif (
                data['token'] == self.devices_get_token
                or data['token'] == self.devices_sub_token
        ):
            device_notifications = data['result'][0]['Notifications']
            device_updates = {}
            for notification in device_notifications:
                if 'updates' not in notification:
                    continue

                for key, value in notification['updates'].items():
                    device_updates[key] = value
            self.process_devices(device_updates)

    def get_events(self):
        """
        Subscribes to Telemetry events
        """
        logging.info('Subscribing to Telemetry events.')
        self.events_token = self.make_token()
        args = {'query': {'analytics': {'/events/activeEvents': True}}}
        subscribe = threading.Thread(
            target=self.send_message,
            args=(SUBSCRIBE, self.events_token, args)
        )
        subscribe.start()

    def get_and_subscribe_devices(self):
        """
        Subscribes to the list of devices that are streaming data to CVP.
        We'll use this list of devices keyed by the serial number to add more
        info to the email.
        """
        logging.info('Subscribing to Telemetry devices.')
        self.devices_get_token = self.make_token()
        self.devices_sub_token = self.make_token()

        # Get the current object
        get_args = {
            'query': {'analytics': {'/DatasetInfo/EosSwitches': True}},
            'count': False,
        }
        get_devices = threading.Thread(
            target=self.send_message,
            args=(GET, self.devices_get_token, get_args),
        )
        get_devices.start()

        # subscribe for future changes
        args = {'query': {'analytics': {'/DatasetInfo/EosSwitches': True}}}
        subscribe = threading.Thread(
            target=self.send_message,
            args=(SUBSCRIBE, self.devices_sub_token, args),
        )
        subscribe.start()

    def process_devices(self, device_updates):
        """
        Iterate through the list of devices and store the mapping of
        serial number to hostname
        """
        for key, value in device_updates.items():
            self.devices[key] = value['value']['hostname']

        logging.info('Received devices. Total device count is {}.'.format(len(self.devices)))

    def send_email(self, event):
        """
        Send an email using variables above
        """
        logging.debug('Preparing email notification.')

        data = event['data']

        # Try to lookup the hostname, if not found return the serialnum
        host = self.devices.get(data.get('deviceId'), data.get('deviceId'))
        severity = event['severity']
        title = event['title']
        desc = event['description']
        timestamp = event['timestamp'] / 1000  # ms to sec
        datetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

        body = '''{} event on {} at {}\n \
        Description: {}\n \
        View Event at {}/telemetry/events\n'''.format(severity, host, datetime, desc, self.config.telemetryUrl)

        message = MIMEText(body)

        message['From'] = self.config.smtpUsername
        message['To'] = self.config.sendToAddress
        if self.config.sendCcAddress:
            message['Cc'] = self.config.sendCcAddress
        message['Subject'] = '{} {} {}'.format(self.config.subjectPrefix, severity, title)

        self.server.sendmail(
            self.config.sendToAddress,
            self.config.sendToAddress.split(','),
            message.as_string(),
        )
        logging.info('Email sent for event: {} {}'.format(severity, title))


def get_password(prompt):
    try:
        return getpass.getpass(prompt)
    except KeyboardInterrupt:
        exit()


def main():
    parser = argparse.ArgumentParser(description='Redirect streaming events as email notifications.')

    parser.add_argument(
        'telemetryUrl',
        help='IP address or hostname of CVP or Telemetry',
    )
    parser.add_argument(
        'smtpServer',
        help='IP address or hostname of SMTP (email) server',
    )
    parser.add_argument(
        'sendToAddress',
        help='Comma-separated list of email recipients',
    )
    parser.add_argument(
        '-c',
        '--sendCcAddress',
        help='Comma-separated list of email recipients',
    )
    parser.add_argument(
        '-s',
        '--subjectPrefix',
        default='[CloudVision Telemetry]',
        help='Text to prefix the Subject line',
    )
    parser.add_argument(
        '-p',
        '--port',
        type=int,
        default=465,
        help='destination port on SMTP server',
    )
    parser.add_argument(
        '--smtpUsername',
        help='SMTP (email) server username, if authentication is required. e.g.: bob@acme.com',
    )
    parser.add_argument(
        '--smtpPassword',
        help='''SMTP (email) server password, if authentication is required.
                If omitted you will be prompted for it at startup''',
    )
    parser.add_argument(
        '--noSmtpSsl',
        action='store_true',
        default=False,
        help='Flag to disable SSL SMTP connection',
    )
    parser.add_argument(
        '--noTelemetrySsl',
        action='store_true',
        default=False,
        help='Flag to disable SSL websocket connection',
    )
    parser.add_argument(
        '--telemetryUsername',
        help='Telemetry username, if authentication is required',
    )
    parser.add_argument(
        '--telemetryPassword',
        help='''Telemetry password, if authentication is required.
                If omitted you will be prompted for it at startup''',
    )
    parser.add_argument(
        '--noSslValidation',
        action='store_true',
        default=False,
        help='Disable validation of SSL certificates (inadvised; potentially dangerous)',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        default=False,
        help='Display additional info messages'
    )

    cmd_args = parser.parse_args()

    passwords = dict()

    if cmd_args.smtpPassword:
        passwords['smtpPassword'] = cmd_args.smtpPassword
    elif cmd_args.smtpUsername:
        passwords['smtpPassword'] = get_password('Enter SMTP server password for {}'.format(cmd_args.smtpUsername))

    if cmd_args.telemetryPassword:
        passwords['telemetryPassword'] = cmd_args.telemetryPassword
    elif not cmd_args.noTelemetrySsl:
        passwords['telemetryPassword'] = get_password('Enter Telemetry password for {}'.format(cmd_args.telemetryUrl))

    logging_level = logging.DEBUG if cmd_args.verbose else logging.WARNING
    logging.basicConfig(level=logging_level)

    connection = TelemetryWs(cmd_args, passwords)

    try:
        ssl_options = None
        if cmd_args.noSslValidation:
            ssl_options = {
                'check_hostname': False,
                'cert_reqs': ssl.CERT_NONE,
            }

        connection.socket.run_forever(sslopt=ssl_options)
    except KeyboardInterrupt:
        connection.socket.close()
        exit()


if __name__ == '__main__':
    main()
