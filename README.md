This is a sample python client on top of the generated assisted-installer python library to ease working with assisted installer

Available features:

- create/delete cluster (autoinjecting pull secret file and ssh public key)
- create/download discovery iso
- list cluster/hosts
- update hostnames and host roles
- update cluster attributes such as api vip and ingress vip 
- launch cluster install

# Deploying

## Cli

Install the package with

```
pip3 install aicli
```

To upgrade it later on

```
pip3 install -U aicli assisted-service-client
```

### Container mode

```
alias aicli='docker run --net host -it --rm -e AI_OFFLINETOKEN=$AI_OFFLINETOKEN -v $HOME/.aicli:/root/.aicli -v $PWD:/workdir quay.io/karmab/aicli'
```

Where AI_OFFLINETOKEN is an environment variable used to access public saas. This token can be retrieved at [https://cloud.redhat.com/openshift/token](https://cloud.redhat.com/openshift/token)

With onprem mode, you can instead use `-e AI_URL=$AI_URL`

### Targetting staging environment

the flag `--staging` can be set to target the internal staging environment

Alternatively, set the env variable STAGING to true (or any non empty string, really)

In container mode, that would be `-e STAGING=true`

## Assisted installer Plan

To deploy assisted installer, you can use kcli with the provided plan in the kcli_plan directory

```
cd kcli_plan
kcli create plan
``` 

# How to use

## Setting target url

You need to indicate a target AI_URL, which can be done with the flag *--url*

The url is in this format `http://$AI_IP:8080` 

Alternatively, you can set it as an environment variable

## Parameters

For most of the commands, you can pass parameters either on the command line by repeating `-P key=value` or by putting them in a parameter file, in yaml format.

If present, the file  `aicli_parameters.yml` is also parsed.

## Using the cli

### Help

```
aicli -h
```

### List 

```
aicli list cluster
```

```
aicli list host
```

## Creating/Deleting a cluster

```
aicli create cluster myclu
```

```
aicli delete cluster myclu
```

## Get info

```
aicli info cluster mycluster
```

```
aicli info host myhost
```

## Update objects

```
aicli update cluster myclu -P api_vip=192.168.122.253
```

```
aicli update host host_id -P name=coolname.testk.karmalabs.com
```

The following command can be used to update the names of all the nodes named localhost to master-X instead in each cluster

```
aicli update host localhost -P role=master
```

## Handling iso

```
aicli create iso myclu
aicli download iso myclu
```

#3 Update data

```
aicli create iso myclu
aicli download iso myclu
```

## Launch an install

```
aicli start cluster myclu
```

## Add extra workers

For this purpose, we assume we already have an installer cluster (named myclu). When creating a new cluster with the same name and the '-day2' extension, the api code will create a dedicated cluster for adding host purposes.

```
aicli create cluster myclu-day2
# gather the discovery iso and launch hosts as usual then
aicli start cluster myclu-day2
```

## Sample aicli_parameters.yml

```
openshift_version: 4.8
sno: true
pull_secret: my_pull_secret.json
disconnected_url: testk-disconnecter.ipv6only:5000
hosts:
 bonka-0:
   role: master
 bonka-1:
   role: worker
installconfig:
   additionalTrustBundle: |
       -----BEGIN CERTIFICATE-----
       MIIGCzCCA/OgAwIBAgIUYwFxO7EeEDFL52wY1hoNingo3pgwDQYJKoZIhvcNAQEL
       BQAwgYAxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZNYWRyaWQxFTATBgNVBAcMDFNh
       biBCZXJuYXJkbzESMBAGA1UECgwJS2FybWFsYWJzMQ8wDQYDVQQLDAZHdWl0YXIx
       JDAiBgNVBAMMG3Rlc3RrLWRpc2Nvbm5lY3Rlci5pcHY2b25seTAeFw0yMTA0MDgx
       MDUzNDRaFw0yMjA0MDgxMDUzNDRaMIGAMQswCQYDVQQGEwJVUzEPMA0GA1UECAwG
       TWFkcmlkMRUwEwYDVQQHDAxTYW4gQmVybmFyZG8xEjAQBgNVBAoMCUthcm1hbGFi
       czEPMA0GA1UECwwGR3VpdGFyMSQwIgYDVQQDDBt0ZXN0ay1kaXNjb25uZWN0ZXIu
       aXB2Nm9ubHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVHZNDqBkG
       e0BAs7SxVQSGzbd8bvNwNPn8pP2IRnjL2Vohz4qi7bqOpxWDI5YIY9MWyRGYAzAZ
       A/ik8ncDl324/6o8BxbdrB8TPL4+vIpYsNKbKR4i6W138CRa+opL3QjTA6P8YqyG
       GR/Tcb1jfDSKE6Z2alDFhFWgyexSkmsojwiFZqo5VySeR/miV783aJbgju9xwxw+
       O4lQt8OxIt8fSW+DYV0Wkt/nrUZUlAiIQMXIq8M+zLgp+SGVuFwLTIawoU97aU0V
       42AE29fCZFMmb0zSEZG1N8Q+dcur8Vk5O/g+ZGjwBavecYp01D0sdRSUXE2WxaI0
       iM8dHlTtXRWOIGrTHEG1AtTqnKFELMTE0d9WeHXW/5cFBL2F8M37iH8uw1MANVFC
       0UjAwJsHaoZgGYJ+gHsurlARSKx5G+SCopnvmEM8rleCjqT0yXwBs7YVhfDQOB6U
       ap+af+Dq1YpXLmbIm4tVYIOe+kohsx0x0mMGq3b48yUIG6QkMAJ++yjdJVVBX2EQ
       6NmEWDkTJIQSXG9o5XgrznICZR3zmLgbMuemoncpDRXymWZ4O7Dv2F11vLOAWg/c
       vfhuCMZF5s3ZSVExgCv84L98OzLmdPSljNoyUTOcM95MkXAcenJ0sucmO2D3RXq9
       UM80PpiRYcDwVH8qtvlQ0j+nd6PbzZ7y9QIDAQABo3sweTAdBgNVHQ4EFgQUDLhV
       vXxGQXm4xJ4ZW/pk+83ZgqYwHwYDVR0jBBgwFoAUDLhVvXxGQXm4xJ4ZW/pk+83Z
       gqYwDwYDVR0TAQH/BAUwAwEB/zAmBgNVHREEHzAdght0ZXN0ay1kaXNjb25uZWN0
       ZXIuaXB2Nm9ubHkwDQYJKoZIhvcNAQELBQADggIBAMw6LJFimWzXRdByw2bWZoul
       jRToZoOZdf9YddRQdxg08mllVKTBoDZ0gb8+TF3/PMGnF5Oi6+Gxm1dsNDFv+Qdt
       7zm3zWEqKP+u3g+35alNkQgMfgDV21OVQjYwVS5BijAWuQM6exRZYs1I++19YvLW
       NCaLuUqVxMdQUnl00+4cgOT2P5lBt1vkL4SFiR2Hy92NrhAfsbnacJN+MY77luei
       rxfUC9qLzU+7Wl5SgnxEkalDRMYWp9u8KuhWS5yeli158gdgLBeqfJr8EWksTG2m
       vK6w9zKcFwhYTcq7NgZJPECOg7DnjbvwDP7VdqrO2UMvHrf31ziXW1O5bzWnkqxF
       0q8mdjiJJi1tQK/Vxb9lS64P4bbFBlVo9sEES4JnfY3pKs0s/hdzrdSJJHbSt/lG
       aqHNpx+kHsWgC8/athDOqo66S97u39vumdWheUWPsx8sitZ9MvA6tOGbnIPvm/hB
       +Gfpn1pUCk2rYuMY40qiAgpJsi56wfA6j2s1aX7sDp4pIgaslfoxyxXvbcpAhhQo
       hizMMC0XdZhlUj9df4PQdPPrckha/9rrYf1GjIO4tqPPxdqPACNhR9UwDd8qJarp
       Ig5BBu37RdjCR7JGSF/2QisMmyKoTnyD9P+lFKTgGfsbbxrp7XdeLYY7xaFRzkuZ
       gAedh+jkW6mjkMIu5RUU
       -----END CERTIFICATE-----
   imageContentSources:
   - mirrors:
     - testk-disconnecter.ipv6only:5000/ocp4
     source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
   - mirrors:
     - testk-disconnecter.ipv6only:5000/ocp4
     source: registry.ci.openshift.org/ocp-release
```

