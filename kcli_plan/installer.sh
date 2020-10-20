export HOME=/root
cd /root
yum -y install python3-pip socat make
pip3 install waiting
git clone https://github.com/openshift/assisted-service
cd assisted-service
IP=$(hostname -I | cut -d' ' -f1)
REVERSE_NAME=$(dig -x $IP +short | sed 's/\.[^\.]*$//')
AI_URL=http://${REVERSE_NAME:-$IP}:8090
sed -i "s@REPLACE_BASE_URL@$AI_URL@" deploy/assisted-service-configmap.yaml
make deploy-all {{ "TARGET=oc-ingress" if not minikube else "" }}
make deploy-ui {{ "TARGET=oc-ingress" if not minikube else "" }}
#docker run -v $PWD:/here --rm quay.io/ocpmetal/assisted-service:latest cp -r /clients/assisted-service-client-1.0.0.tar.gz /here
docker build -t ocpmetal/assisted-service -f Dockerfile.assisted-service .
docker run -v $PWD:/here --rm ocpmetal/assisted-service:latest cp -r /clients/assisted-service-client-1.0.0.tar.gz /here
tar zxvf assisted-service-client-1.0.0.tar.gz
cd assisted-service-client-1.0.0
python3 setup.py install
pip3 install git+https://github.com/karmab/assisted-installer-cli.git#egg=assisted-installer-cli
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=assisted-service -o name) --for=condition=Ready
tmux new-session -s port-forward-service -d "while true; do kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/assisted-service 8090:8090; done"
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=ocp-metal-ui -o name) --for=condition=Ready
tmux new-session -s port-forward-ui -d "while true; do kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/ocp-metal-ui 8080:80; done"
echo "export AI_URL=$AI_URL" >> /root/.bashrc
echo "export PATH=/usr/local/bin:\$PATH" >> /root/.bashrc
