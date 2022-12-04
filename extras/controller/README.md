This is a controller leveraging aicli and using aiclideployments to run full deployments end to end

## Requisites

- a running kubernetes/openshift cluster and KUBECONFIG env variable pointing to it (or simply .kube/config)
- valid offline token
- valid pull secret
- valid public key

## Deploying

Prepare the proper secrets

```
kubectl create secret generic offline-token --from-file=offline-token=$HOME/.aicli/offlinetoken.txt
kubectl create secret generic pull-secret --from-file=pull-secret=openshift_pull.json
kubectl create secret generic public-key --from-file=public-key=$HOME/.ssh/id_rsa.pub
```

Then deploy the controller:

```
kubectl create -f https://raw.githubusercontent.com/karmab/aicli/master/extras/controller/deploy.yml
```

## How to use

Here goes a some sample CR to get you started:

```
apiVersion: aicli.karmalabs.local/v1
kind: Aiclideployment
metadata:
  name: biloute
spec:
  base_dns_domain: karmalabs.corp
  api_vip: 192.168.122.251
  ingress_vip: 192.168.122.250
  bmc_user: admin
  bmc_password: password
  hosts:
  - name: ci-ai-master-0
    bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/21111111-1111-1111-1111-111111111181
  - name: ci-ai-master-1
    bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/21111111-1111-1111-1111-111111111182
  - name: ci-ai-master-2
    bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/21111111-1111-1111-1111-111111111183
```
