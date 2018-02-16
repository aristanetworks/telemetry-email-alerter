Telemetry email alerter
=======================

Python script that allows you to subscribe to Arista Telemetry events and then send them to an SMTP server for email notifications.

Emails are sent for events that occur while the alerter is running—you won't get alerts for past events.

We recommend you set up email filters to limit notifications. For example, you can set up filters to ignore "INFO" events based on the email subject.

Installation
------------

Python 2.7 and `pip <https://packaging.python.org/tutorials/installing-packages>`__ are required.

You can download the alerter via ``pip`` by running ``pip install telemetry-email-alerter``.

Usage
-----

You can start up the alerter by running:

::

    telemetry-email-alerter <telemetry-server> <smtp-server> <email-1> <email-2> ... <email-n>

The full list of arguments accepted by the script are listed below.

+-----------------------+-----------------+-----------------+-----------------+
| Name                  | Required?       | Default         | Description     |
+=======================+=================+=================+=================+
| telemetryUrl          | yes             | —               | The IP address  |
|                       |                 |                 | or hostname of  |
|                       |                 |                 | your CVP        |
|                       |                 |                 | Telemetry       |
|                       |                 |                 | instance        |
+-----------------------+-----------------+-----------------+-----------------+
| smtpServer            | yes             | —               | The IP address  |
|                       |                 |                 | or hostname of  |
|                       |                 |                 | your SMTP       |
|                       |                 |                 | (email) server  |
+-----------------------+-----------------+-----------------+-----------------+
| sendToAddress         | yes             | —               | The emails to   |
|                       |                 |                 | send            |
|                       |                 |                 | notifications   |
|                       |                 |                 | to. You can     |
|                       |                 |                 | specify         |
|                       |                 |                 | multiple emails |
+-----------------------+-----------------+-----------------+-----------------+
| --sendCcAddress       | no              | —               | Emails to CC    |
| a@example.com         |                 |                 | notifications   |
| b@example.com         |                 |                 | for. You can    |
|                       |                 |                 | specify         |
|                       |                 |                 | multiple emails |
+-----------------------+-----------------+-----------------+-----------------+
| --port 1234           | no              | 465             | The port your   |
|                       |                 |                 | SMTP server     |
|                       |                 |                 | listens to if   |
|                       |                 |                 | it use a        |
|                       |                 |                 | non-standard    |
|                       |                 |                 | port            |
+-----------------------+-----------------+-----------------+-----------------+
| --subjectPrefix       | no              | [CloudVision    | A message to    |
| 'CVP Alert'           |                 | Telemetry]      | prepend to      |
|                       |                 |                 | email subjects  |
+-----------------------+-----------------+-----------------+-----------------+
| --noSmtpSsl           | no              | off (SSL is     | Disable SSL for |
|                       |                 | used)           | SMTP            |
|                       |                 |                 | connections     |
+-----------------------+-----------------+-----------------+-----------------+
| --smtpUsername        | no              | —               | SMTP server     |
| a@example.com         |                 |                 | username if     |
|                       |                 |                 | authentication  |
|                       |                 |                 | is required     |
+-----------------------+-----------------+-----------------+-----------------+
| --smtpPassword        | no              | —               | SMTP server     |
| secret                |                 |                 | password if     |
|                       |                 |                 | authentication  |
|                       |                 |                 | is required.    |
|                       |                 |                 | You will be     |
|                       |                 |                 | prompted at     |
|                       |                 |                 | startup if this |
|                       |                 |                 | is not provided |
+-----------------------+-----------------+-----------------+-----------------+
| --noTelemetrySsl      | no              | off (SSL is     | Disable SSL for |
|                       |                 | used)           | Telemetry       |
|                       |                 |                 | connections     |
+-----------------------+-----------------+-----------------+-----------------+
| --telemetryUsername   | no              | —               | Telemetry       |
| example               |                 |                 | username if     |
|                       |                 |                 | authentication  |
|                       |                 |                 | is required     |
+-----------------------+-----------------+-----------------+-----------------+
| --telemetryPassword   | no              | —               | Telemetry       |
| secret                |                 |                 | password if     |
|                       |                 |                 | authentication  |
|                       |                 |                 | is required.    |
|                       |                 |                 | You will be     |
|                       |                 |                 | prompted at     |
|                       |                 |                 | startup if this |
|                       |                 |                 | is not provided |
+-----------------------+-----------------+-----------------+-----------------+
| --noSslValidation     | no              | off (validation | Disables        |
|                       |                 | is used)        | validation of   |
|                       |                 |                 | SSL             |
|                       |                 |                 | certificates.   |
|                       |                 |                 | For debugging   |
|                       |                 |                 | purposes. Not   |
|                       |                 |                 | advised to use  |
|                       |                 |                 | in real         |
|                       |                 |                 | environments    |
+-----------------------+-----------------+-----------------+-----------------+
| --verbose             | no              | off             | Show logging    |
|                       |                 |                 | messages        |
+-----------------------+-----------------+-----------------+-----------------+

Using an SMTP server
--------------------

We recommend you use an SMTP server you run and maintain yourself. Your company might have one you can use.

Alternatively you can use `the Gmail SMTP server <https://support.google.com/a/answer/176600>`__. You can use your Gmail username and `an app password <https://support.google.com/accounts/answer/185833>`__. Be aware of its send limits though—it's certainly possible you might exceed them.

Development info
----------------

You will need Python 2.7 with ``pip`` and ``virtualenv``. You can read more about these in `the Python packaging documentation <https://packaging.python.org/tutorials/installing-packages/>`__. Create a ``virtualenv`` to house the dependencies of this project. Once that's done, you can install dependencies by running ``pip install -r requirements.pip`` from the project root.

You can test email notifications by using the Gmail SMTP server mentioned in `Using an SMTP server <#using-an-smtp-server>`__. Alternatively you can use an app like `mailslurper <https://github.com/mailslurper/mailslurper>`__ on your machine locally.

To run the script locally, you can run the ``telemetry_email_alerter`` package from the project root:

::

    python telemetry_email_alerter [...args]
