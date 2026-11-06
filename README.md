# Agent360

360 Monitoring ([360monitoring.com](https://360monitoring.com)) is a web service that monitors and displays your server performance statistics.

Agent360 is OS-agnostic software compatible with Python 3.7 and 3.8.
It is optimized for low CPU usage and includes an extendable set of useful plugins.

[![Build Status](https://github.com/plesk/agent360/workflows/Agent360-Test-And-Deploy/badge.svg?branch=master)](https://github.com/plesk/agent360/actions/workflows/test-and-deploy.yml)

## Documentation

You can find the full documentation, including the feature-complete REST API, at [docs.360monitoring.com](https://docs.360monitoring.com/docs) and [docs.360monitoring.com/docs/api](https://docs.360monitoring.com/docs/api).

## Automatic Installation (All Linux Distributions)

You can install Agent360 with the default configuration on all Linux distributions with a single command.

1. Connect to your server via SSH.
2. Find your USERTOKEN. To do so, [go to the servers page](https://monitoring.platform360.io/servers/overview) and click the Add server button.
3. Run the following command:

    ```sh
    wget -q -N https://monitoring.platform360.io/agent360.sh && bash agent360.sh USERTOKEN
    ```

## Automatic Installation (Windows)

Download the [installer](https://github.com/plesk/agent360/releases) and install it on your Windows server.

The installer will ask for your USERTOKEN, which you can get [from the servers page](https://monitoring.platform360.io/servers/overview).

## Manual Installation

To customize installation options, install Agent360 manually.

1. Connect to your server via SSH.
2. Run the following command for your server platform:

    - Debian GNU/Linux:

        ```sh
        apt-get install python3-dev python3-setuptools python3-pip
        pip3 install agent360
        wget -O /etc/agent360.ini https://monitoring.platform360.io/agent360.ini
        ```

    - Fedora/CentOS version 6 or earlier (Python 2.7):

        ```sh
        yum install python-devel python-setuptools gcc
        easy_install agent360 netifaces psutil
        wget -O /etc/agent360.ini https://monitoring.platform360.io/agent360.ini
        ```

    - Fedora/CentOS version 7 and later (Python 3):

        ```sh
        yum install python36-devel python36 gcc
        pip3 install agent360
        wget -O /etc/agent360.ini https://monitoring.platform360.io/agent360.ini
        ```

3. Find your USERTOKEN. To do so, [go to the servers page](https://monitoring.platform360.io/servers/overview) and click the Add server button. You need this to generate a server ID.
4. Run the following command (USERTOKEN is the value from the previous step):

    ```sh
    agent360 hello USERTOKEN /etc/agent360-token.ini
    ```

5. Create a systemd service at [agent360.service](http://_vscodecontentref_/0) with the following content:

    ```ini
    [Unit]
    Description=Agent360

    [Service]
    ExecStart=/usr/local/bin/agent360
    User=agent360

    [Install]
    WantedBy=multi-user.target
    ```

6. Run the following commands:

    ```sh
    chmod 644 /etc/systemd/system/agent360.service
    systemctl daemon-reload
    systemctl enable agent360
    systemctl start agent360
    ```

## Building Windows Setup

Prerequisite: [Inno Setup](https://jrsoftware.org/isdl.php) is used as the installer. The build script assumes it is installed in the default location.

Run `php windows/build.php` to create the setup file.
