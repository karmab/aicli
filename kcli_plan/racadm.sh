USER="root"
PASSWORD="hendrix"
SERVER="10.0.0.1"
ISO_URL="http://10.0.0.2/testk.iso"
echo """[racadm]
name=Racadm
baseurl=http://linux.dell.com/repo/hardware/dsu/os_dependent/RHEL8_64
enabled=1
gpgcheck=0""" > /etc/yum.repos.d/racadm.repo
dnf -y install openssl-devel srvadmin-idracadm7
export PATH=/opt/dell/srvadmin/bin:$PATH
# /opt/dell/srvadmin/bin/idracadm7 -r $SERVER -u $USER -p $PASSWORD remoteimage -s
# /opt/dell/srvadmin/bin/idracadm7 -r $SERVER -u $USER -p $PASSWORD remoteimage -d
# /opt/dell/srvadmin/bin/idracadm7 -r $SERVER -u $USER -p $PASSWORD remoteimage -c -l $ISO_URL
# /opt/dell/srvadmin/bin/idracadm7 -r $SERVER -u $USER -p $PASSWORD set iDRAC.VirtualMedia.BootOnce 1
# /opt/dell/srvadmin/bin/idracadm7 -r $SERVER -u $USER -p $PASSWORD set iDRAC.ServerBoot.FirstBootDevice VCD-DVD
# /opt/dell/srvadmin/bin/idracadm7 -r $SERVER -u $USER -p $PASSWORD serveraction powercycle
