%define name agent360
%define version 1.3.1
%define unmangled_version 1.3.1
%define release 1
%define VenvDir /opt/agent360-venv

Summary: 360monitoring agent
Name: %{name}
Version: %{version}
Release: %{release}
Source: %{name}-%{unmangled_version}.tar.gz
License: BSD-3-Clause
Group: Networking Tools
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: 360 monitoring <360support@webpros.com>
Url: https://github.com/plesk/agent360
Requires: epel-release,gcc,python-devel,python-pip,ntp,pyOpenSSL,python2-psutil,python-netifaces,python2-simplejson


%description
360monitoring Agent
==============

360monitoring is a web service of monitoring and displaying statistics of
your server performance.

This software is an OS-agnostic agent compatible with Python 3.7 and 3.8.
It's been optimized to have a small CPU consumption and comes with an
extendable set of useful plugins.


%pre
if [ ! -f /var/log/agent360.log ]; then
	touch /var/log/agent360.log && chmod a+w /var/log/agent360.log
fi

%post
if [ "$(grep -c '^agent360:' /etc/passwd)" = "0" ]; then
        echo "Creating user and group agent360"
        groupadd -r agent360 && adduser -r  -s "/sbin/nologin" -M -N -c "agent360 daemon" -g agent360 agent360
else
        echo "User creation skipped, user is already present"
fi


if [ -f /usr/lib/systemd/system/agent360.service ]; then
	echo "Enabling and starting agent360 service"
	systemctl daemon-reload && systemctl enable agent360.service && systemctl start agent360.service
else
	echo "Cannot start agent360 service, systemd script is not present"
fi

echo "For registering with agent360 servers, please run the following command as root with a valid agent360 USERID: \"agent360 hello USERID\" and restart the agent360 service"

%preun
if [ -f /usr/lib/systemd/system/agent360.service ]; then
	systemctl stop agent360.service && systemctl disable agent360.service
fi

%postun
rm -Rf %{VenvDir}/bin/agent360 /usr/share/doc/agent360 /etc/systemd/system/multi-user.target.wants/agent360.service /var/log/agent360.log /etc/agent360-token.ini >/dev/null 2>&1
if [ "$(grep -c '^agent360:' /etc/passwd)" = "1" ]; then
        echo "Removing user and group agent360"
        userdel agent360
else
        echo "User deletion skipped, agent360 user does not exist"
fi
systemctl daemon-reload

%prep
%setup -n %{name}-%{unmangled_version} -n %{name}-%{unmangled_version}

%build
python3 -m build --sdist --wheel --outdir dist/

%install
python3 -m venv %{VenvDir} && echo -e "\\e[32m  [SUCCESS] Virtual environment has been created\\e[m"
. %{VenvDir}/bin/activate && echo -e "\\e[32m  [SUCCESS] Virtual environment has been activated\\e[m"
# Install agent360 in virtual environment
pip3 install agent360 --upgrade && echo -e "\\e[32m  [SUCCESS] Finished with agent360\\e[m"
deactivate
echo /. > INSTALLED_FILES

# Create a symlink for global access
ln -sf %{VenvDir}/bin/agent360 /usr/local/bin/agent360

%files -f INSTALLED_FILES
%defattr(-,root,root)