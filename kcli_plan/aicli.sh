ENGINE={{ "docker" if method == 'minikube' else 'podman' }} 
export HOME=/root
cd /root/assisted-service
dnf -y install python3-pip socat make
pip3 install waiting
python3 setup.py install
pip3 install git+https://github.com/karmab/assisted-installer-cli.git#egg=assisted-installer-cli
