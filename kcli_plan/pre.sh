sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
setenforce 0
dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce git conntrack tmux --nobest 
systemctl enable --now docker
ssh-keygen -t rsa -N '' -f /root/.ssh/id_rsa
