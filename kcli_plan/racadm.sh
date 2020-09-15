echo """[racadm]
name=Racadm
baseurl=http://linux.dell.com/repo/hardware/dsu/os_dependent/RHEL8_64
enabled=1
gpgcheck=0""" > /etc/yum.repos.d/racadm.repo
yum -y install openssl-devel srvadmin-idracadm7
export PATH=/opt/dell/srvadmin/bin:$PATH
alias racadm=/opt/dell/srvadmin/bin/idracadm7
# racadm -r 10.19.133.31  -u root -p calvin remoteimage -s
racadm -r 10.19.133.31 -u root -p calvin remoteimage -d
racadm -r 10.19.133.31 -u root -p calvin remoteimage -c -l  http://10.19.135.231/testk.iso
racadm -r 10.19.133.31 -u root -p calvin set iDRAC.VirtualMedia.BootOnce 1
racadm -r 10.19.133.31 -u root -p calvin set iDRAC.ServerBoot.FirstBootDevice VCD-DVD
racadm -r 10.19.133.31 -u root -p calvin serveraction powercycle
