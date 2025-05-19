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
BuildRequires:  python3 python3-setuptools python3-build python3-pip
Requires:       assisted-service-client python3 python3-prettytable python3-PyYAML

%description
This is a python wrapper around assisted-installer library

%global debug_package %{nil}
%global __python /usr/bin/python3
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "import sys; from distutils.sysconfig import get_python_lib; sys.stdout.write(get_python_lib())")}

%prep
{{{ git_dir_setup_macro }}}

%build
sed -i "/dependencies = /d" pyproject.toml
python3 -m build

%install
pip3 install --force-reinstall . --prefix=%{_prefix} --root=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python_sitelib}/*
%attr(0755,root,root) %{_bindir}/aicli
%attr(0755,root,root) %{_bindir}/aiclimcp

%changelog
{{{ git_dir_changelog }}}
