This is a controller leveraging aicli and using aiclideployments to run full deployments end to end

## Requisites

- a running kubernetes/openshift cluster and KUBECONFIG env variable pointing to it (or simply .kube/config)
- valid offline token
- valid pull secret
- valid public key
- in order to deploy clusters with baremetal hosts, you will need the redfish BMC information. Additionally, if the BMC of your nodes needs an iso url finished in .iso, you will need to deploy a side httpd container

## Deploying

Prepare the proper secrets

```
oc create ns aicli-infra
oc create -n aicli-infra secret generic offline-token --from-file=offline-token=$HOME/.aicli/offlinetoken.txt
oc create -n aicli-infra secret generic pull-secret --from-file=pull-secret=openshift_pull.json
oc create -n aicli-infra secret generic public-key --from-file=public-key=$HOME/.ssh/id_rsa.pub
```

Then deploy the controller with a side httpd container:

```
oc adm policy add-scc-to-user anyuid system:serviceaccount:aicli-infra:default
oc create -f https://raw.githubusercontent.com/karmab/aicli/main/extras/controller/deploy_with_httpd.yml
```

or the same without httpd:

```
oc create -f https://raw.githubusercontent.com/karmab/aicli/main/extras/controller/deploy.yml
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
  - name: ci-ai-ctlplane-0
    bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/21111111-1111-1111-1111-111111111181
  - name: ci-ai-ctlplane-1
    bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/21111111-1111-1111-1111-111111111182
  - name: ci-ai-ctlplane-2
    bmc_url: http://192.168.122.1:8000/redfish/v1/Systems/21111111-1111-1111-1111-111111111183
```

If you need to use the httpd side container, add the following variable to the spec:

```
iso_url: http://web-aicli-infra.apps.relocate.karmalabs.corp
```

This url can be gathered using `oc get route -n aicli-infra web -o jsonpath='{.spec.host}'`
