CLUSTER=testk
export AI_URL=http://$(kcli info vm $CLUSTER-installer -v -f ip):8080
aicli create cluster $CLUSTER
aicli create iso $CLUSTER
aicli download iso $CLUSTER
mv $CLUSTER.iso /var/lib/libvirt/images
kcli start plan ai
sleep 180
aicli update cluster $CLUSTER -P api_vip=192.168.122.253 -P ingress_vip=192.168.122.252
aicli start cluster $CLUSTER
