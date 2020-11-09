CLUSTER={{ cluster }}
DOMAIN={{ domain }}
API_IP={{ api_ip }}
INGRESS_IP={{ ingress_ip }}
export AI_URL=http://$(kcli info vm $CLUSTER -installer -v -f ip):8080
aicli create cluster $CLUSTER -P base_dns_domain=$DOMAIN
aicli create iso $CLUSTER
ssh {{ config_user | default('root') }}@{{ config_host|default(network|local_ip) }} curl 
ssh {{ config_user | default('root') }}@{{ config_host|default(network|local_ip) }} kcli start plan $CLUSTER
sleep 180
aicli update cluster $CLUSTER -P api_vip=$API_IP -P ingress_vip=$INGRESS_IP
aicli start cluster $CLUSTER
