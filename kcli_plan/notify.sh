IP=$(hostname -I |cut -f1 -d" ")
echo UI available at http://$IP:8080
