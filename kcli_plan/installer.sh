export HOME=/root
cd /root
yum -y install python3-pip socat make
pip3 install waiting
git clone https://github.com/openshift/assisted-service
cd assisted-service
IP=$(hostname -I | cut -d' ' -f1)
REVERSE_NAME=$(dig -x $IP +short | sed 's/\.[^\.]*$//')
URL=http://${REVERSE_NAME:-$IP}:8090
sed -i "s@REPLACE_BASE_URL@$URL@" deploy/assisted-service-configmap.yaml
make deploy-all {{ "TARGET=oc-ingress" if not minikube else "" }}
make deploy-ui {{ "TARGET=oc-ingress" if not minikube else "" }}
docker run -v $PWD:/here --rm quay.io/ocpmetal/assisted-service:latest cp -r /clients/assisted-service-client-1.0.0.tar.gz /here
tar zxvf assisted-service-client-1.0.0.tar.gz
cd assisted-service-client-1.0.0
python3 setup.py install
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=assisted-service -o name) --for=condition=Ready
tmux new-session -s port-forward-service -d "kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/assisted-service 8090:8090"
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=ocp-metal-ui -o name) --for=condition=Ready
tmux new-session -s port-forward-ui -d "kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/ocp-metal-ui 8080:80"
echo "export AI_URL=$(hostname -I |cut -f1 -d' '):8090" >> /root/.bashrc
