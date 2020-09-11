export HOME=/root
cd /root
yum -y install python3-pip socat make
pip3 install waiting
git clone https://github.com/openshift/assisted-service
cd assisted-service
make deploy-all {{ "TARGET=oc-ingress" if not minikube else "" }}
make deploy-ui {{ "TARGET=oc-ingress" if not minikube else "" }}
docker run -v $PWD:/here --rm quay.io/ocpmetal/assisted-service:latest cp -r /clients/assisted-service-client-1.0.0.tar.gz /here
tar zxvf assisted-service-client-1.0.0.tar.gz
cd assisted-service-client-1.0.0
python3 setup.py install
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=ocp-metal-ui -o name) --for=condition=Ready
tmux new-session -s portforward -d "kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/ocp-metal-ui 8080:80"
