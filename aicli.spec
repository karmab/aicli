#
# spec file for package aicli
#
# Copyright (c) 2022 Karim Boumedhel
#

Name:           {{{ git_dir_name }}}
Version:        99.{{{ git_custom_version }}}
Release:        0%{?dist}
Url:            http://github.com/karmab/aicli
Summary:        Client for Assisted Installer API
License:        ASL 2.0
Group:          Development/Languages/Python
VCS:            {{{ git_dir_vcs }}}
Source:         {{{ git_dir_pack }}}
AutoReq:        no
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  python3 python3-setuptools
Requires:       assisted-service-client python3 python3-prettytable python3-PyYAML

%description
This is a python client on top of the generated assisted-installer python library to ease working with assisted installer

%global debug_package %{nil}
%global __python /usr/bin/python3
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "import sys; from distutils.sysconfig import get_python_lib; sys.stdout.write(get_python_lib())")}

%prep
{{{ git_dir_setup_macro }}}

%build
sed -i "s/install_requires=INSTALL/install_requires=[]/" setup.py
sed -i '/INSTALL/d' setup.py
#GIT_VERSION="$(curl -s https://github.com/karmab/aicli/commits/master | grep 'https://github.com/karmab/aicli/commits/master?' | sed 's@.*=\(.......\).*+.*@\1@') $(date +%Y/%m/%d)"
#echo $GIT_VERSION > aicli/version/git
%{__python} setup.py build

%install
%{__python} setup.py install --prefix=%{_prefix} --root=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python_sitelib}/*
%attr(0755,root,root) %{_bindir}/aicli

%changelog
{{{ git_dir_changelog }}}
