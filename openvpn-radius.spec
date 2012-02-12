Name:           openvpn-auth-radius
Version:        2.1
Release:        1%{?dist}
Summary:        OpenVPN plugin for RADIUS

Group:          Networking/Other
License:        GPL
URL:            http://www.02strich.de
Source0:        openvpn-auth-radius-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  doxygen
Requires:		openvpn       

%description
An OpenVPN plugin for RADIUS authentication and accounting for OpenVPN 2.x


%prep
%setup -q


%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT

install -d %{buildroot}%{_libdir}/openvpn/plugin/lib
install -d %{buildroot}%{_sysconfdir}/openvpn/auth

install -m0755 openvpn-auth-radius.so -t %{buildroot}%{_libdir}/openvpn/plugin/lib/
install -m0600 auth-radius.conf %{buildroot}%{_sysconfdir}/openvpn/auth/radius.conf  


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc COPYING README auth-radius.conf ToDo ChangeLog vsascript.pl
%dir %{_sysconfdir}/openvpn/auth/
%config(noreplace) %{_sysconfdir}/openvpn/auth/radius.conf
%{_libdir}/openvpn/plugin/lib/openvpn-auth-radius.so 
