# Telemetry email alerter

Python script that allows you to subscribe to Arista Telemetry events and then send them to an SMTP server for email notifications.

## Usage

You can run the script with the following args:

| Name | Required? | Description |
|---|---|---|
| `telemetryUrl` | yes | The IP address or hostname of your CVP Telemetry instance |
| `smtpServer` | yes | The IP address or hostname of your SMTP (email) server |
| `sendToAddress` | yes | The email to send notifications to |
| `--sendCcAddresses a@example.com,b@example.com` | no | Emails to CC notifications for, comma-separated |
| `--port 1234` | no | The port your SMTP server listens to if it use a non-standard port |
| `--subjectPrefix 'CVP Alert'` | no | A message to prepend to email subjects |
| `--noSmtpSsl` | no | Disable SSL for SMTP connections |
| `--smtpUsername a@example.com` | no | SMTP server username if authentication is required |
| `--smtpPassword secret` | no | SMTP server password if authentication is required. You will be prompted at startup if this is not provided |
| `--noTelemetrySsl` | no | Disable SSL for Telemetry connections |
| `--telemetryUsername example` | no | Telemetry username if authentication is required |
| `--telemetryPassword secret` | no | Telemetry password if authentication is required. You will be prompted at startup if this is not provided |
| `--noSslValidation` | no | Disables validation of SSL certificates. For debugging purposes. Not advised to use in real environments |
| `--verbose` | no | Show logging messages |

## Development info

You will need Python 2.7 with [`pip` and `virtualenv`](https://packaging.python.org/tutorials/installing-packages/). Create a `virtualenv` to house the dependencies of this project. Once that's done, you can install dependencies by running `pip install -r requirements.pip` from the project root.

You can test email sends by using `smtp.gmail.com` with your Gmail username and password for authentication. Alternatively you can use [`mailslurper`](https://github.com/mailslurper/mailslurper) on your machine locally.
