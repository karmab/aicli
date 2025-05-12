#
# spec file for package assisted-service-client
#
# Copyright (c) 2022 Karim Boumedhel
#

Name:           assisted-service-client
Version:        99.{{{ git_custom_version }}}
Release:        0%{?dist}
Url:            https://github.com/openshift/assisted-service
Summary:        Assisted Installer Client Library
License:        ASL 2.0
Group:          Development/Languages/Python
VCS:            {{{ git_dir_vcs }}}
Source:         {{{ git_dir_pack }}}
AutoReq:        no
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  java python3 python3-setuptools git python3-pip
Requires:       python3 python3-certifi

%description
assisted-installer python library

%global debug_package %{nil}
%global __python /usr/bin/python3
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "import sys; from distutils.sysconfig import get_python_lib; sys.stdout.write(get_python_lib())")}

%prep
{{{ git_dir_setup_macro }}}

%build
curl https://repo1.maven.org/maven2/io/swagger/swagger-codegen-cli/2.4.8/swagger-codegen-cli-2.4.8.jar > swagger-codegen-cli.jar
# curl https://raw.githubusercontent.com/openshift/assisted-service/v2.27.0/swagger.yaml > swagger.yaml
curl https://raw.githubusercontent.com/openshift/assisted-service/master/swagger.yaml > swagger.yaml
sed -i '/pattern:/d' swagger.yaml
echo '{"packageName" : "assisted_service_client", "packageVersion": "1.0.0"}' > swagger.spec
java -jar swagger-codegen-cli.jar generate --lang python --config swagger.spec --output build --input-spec swagger.yaml

%install
cd build
pip3 install --force-reinstall . --prefix=%{_prefix} --root=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python_sitelib}/*

%changelog
{{{ git_dir_changelog }}}
