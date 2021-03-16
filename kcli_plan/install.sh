export HOME=/root
cd /root
dnf -y install python3-pip socat make tmux git
pip3 install waiting
git clone https://github.com/openshift/assisted-service
cd assisted-service
IP=$(hostname -I | cut -d' ' -f1)
REVERSE_NAME=$(dig -x $IP +short | sed 's/\.[^\.]*$//')
AI_URL=http://${REVERSE_NAME:-$IP}:8090
sed -i "s@REPLACE_BASE_URL@$AI_URL@" deploy/assisted-service-configmap.yaml
{% if method == "minikube" %}
make deploy-all
make deploy-ui
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=assisted-service -o name) --for=condition=Ready
tmux new-session -s port-forward-service -d "while true; do kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/assisted-service 8090:8090; done"
kubectl wait -n assisted-installer $(kubectl get pod -n assisted-installer -l app=ocp-metal-ui -o name) --for=condition=Ready
tmux new-session -s port-forward-ui -d "while true; do kubectl -n assisted-installer port-forward --address 0.0.0.0 svc/ocp-metal-ui 8080:80; done"
{% elif method == "openshift" %}
export KUBECONFIG=/root/kubeconfig
make deploy-all TARGET=oc-ingress
make deploy-ui TARGET=oc-ingress
{% else %}
dnf -y module disable container-tools
dnf -y install 'dnf-command(copr)'
dnf -y copr enable rhcontainerbot/container-selinux
curl -L -o /etc/yum.repos.d/devel:kubic:libcontainers:stable.repo https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/CentOS_8/devel:kubic:libcontainers:stable.repo
dnf -y install podman
sed -i "s@SERVICE_BASE_URL=.*@SERVICE_BASE_URL=$AI_URL@" onprem-environment
sed -i "s/5432,8000,8090,8080/5432:5432 -p 8000:8000 -p 8090:8090 -p 8080:8080/" Makefile
export AUTH_TYPE=none 
make deploy-onprem
{% endif %}
echo "export AI_URL=$AI_URL" >> /root/.bashrc
echo "export PATH=/usr/local/bin:\$PATH" >> /root/.bashrc
