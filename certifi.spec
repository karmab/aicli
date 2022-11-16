#
# spec file for package certifi
#
# Copyright (c) 2022 Karim Boumedhel
#

Name:           certifi
Version:        2022.9.24
Release:        0%{?dist}
Url:            https://github.com/certifi/python-certifi
Summary:        Certifi
License:        ASL 2.0
Group:          Development/Languages/Python
VCS:            {{{ git_dir_vcs }}}
Source:         {{{ git_dir_pack }}}
AutoReq:        no
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  python3
Requires:       python3

%description
Certifi rpm

%global debug_package %{nil}
%global __python /usr/bin/python3
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "import sys; from distutils.sysconfig import get_python_lib; sys.stdout.write(get_python_lib())")}

%prep
{{{ git_dir_setup_macro }}}

%build
%{__python} setup.py build

%install
%{__python} setup.py install --prefix=%{_prefix} --root=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python_sitelib}/*

%changelog
{{{ git_dir_changelog }}}
