# Telemetry email alerter

Python script that allows you to subscribe to Arista Telemetry events and then send them to an SMTP server for email notifications.

Emails are sent for events that occur while the alerter is running—you won't get alerts for past events.

We recommend you set up email filters to limit notifications. For example, you can set up filters to ignore "INFO" events based on the email subject.

## Installation

Python 2.7 and [`pip`](https://packaging.python.org/tutorials/installing-packages) are required.

You can download the alerter via `pip` by running `pip install telemetry_email_alerter`.

## Usage

You can start up the alerter by running:

```
telemetry_email_alerter <telemetry-server> <smtp-server> <email-1> <email-2> ... <email-n>
```

The full list of arguments accepted by the script are listed below.

| Name | Required? | Default | Description |
|---|---|---|---|
| `telemetryUrl` | yes | — | The IP address or hostname of your CVP Telemetry instance |
| `smtpServer` | yes | — | The IP address or hostname of your SMTP (email) server |
| `sendToAddress` | yes | — | The emails to send notifications to. You can specify multiple emails |
| `--sendCcAddresses a@example.com b@example.com` | no | — | Emails to CC notifications for. You can specify multiple emails |
| `--port 1234` | no | 465 | The port your SMTP server listens to if it use a non-standard port |
| `--subjectPrefix 'CVP Alert'` | no | \[CloudVision Telemetry\] | A message to prepend to email subjects |
| `--noSmtpSsl` | no | off (SSL is used) | Disable SSL for SMTP connections |
| `--smtpUsername a@example.com` | no | — | SMTP server username if authentication is required |
| `--smtpPassword secret` | no | — | SMTP server password if authentication is required. You will be prompted at startup if this is not provided |
| `--noTelemetrySsl` | no | off (SSL is used) | Disable SSL for Telemetry connections |
| `--telemetryUsername example` | no | — | Telemetry username if authentication is required |
| `--telemetryPassword secret` | no | — |Telemetry password if authentication is required. You will be prompted at startup if this is not provided |
| `--noSslValidation` | no | off (validation is used) | Disables validation of SSL certificates. For debugging purposes. Not advised to use in real environments |
| `--verbose` | no | off | Show logging messages |

## Using an SMTP server

We recommend you use an SMTP server you run and maintain yourself. Your company might have one you can use.

Alternatively you can use [the Gmail SMTP server](https://support.google.com/a/answer/176600). You can use your Gmail username and [an app password](https://support.google.com/accounts/answer/185833). Be aware of its send limits though—it's certainly possible you might exceed them.

## Development info

You will need Python 2.7 with [`pip` and `virtualenv`](https://packaging.python.org/tutorials/installing-packages/). Create a `virtualenv` to house the dependencies of this project. Once that's done, you can install dependencies by running `pip install -r requirements.pip` from the project root.

You can test email notifications by using the Gmail SMTP server mentioned in [Using an SMTP server](#using-an-smtp-server). Alternatively you can use an app like [`mailslurper`](https://github.com/mailslurper/mailslurper) on your machine locally.
