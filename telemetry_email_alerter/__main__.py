import argparse
import getpass
import logging
import ssl

from telemetry_email_alerter import TelemetryWs


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
        nargs='+',
        help='List of email recipients',
    )
    parser.add_argument(
        '-cc',
        '--sendCcAddress',
        nargs='+',
        help='List of CC email recipients',
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
