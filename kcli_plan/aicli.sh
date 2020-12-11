ENGINE={{ "docker" if method == 'minikube' else 'podman' }} 
export HOME=/root
cd /root/assisted-service
dnf -y install python3-pip socat make
pip3 install waiting
git clone https://github.com/openshift/assisted-service
cd assisted-service
#docker run -v $PWD:/here --rm quay.io/ocpmetal/assisted-service:latest cp -r /clients/assisted-service-client-1.0.0.tar.gz /here
$ENGINE build -t ocpmetal/assisted-service -f Dockerfile.assisted-service .
$ENGINE run -v $PWD:/here --rm ocpmetal/assisted-service:latest cp -r /clients/assisted-service-client-1.0.0.tar.gz /here
tar zxvf assisted-service-client-1.0.0.tar.gz
cd assisted-service-client-1.0.0
python3 setup.py install
pip3 install git+https://github.com/karmab/assisted-installer-cli.git#egg=assisted-installer-cli
