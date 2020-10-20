pip3 install -e git+https://github.com/karmab/assisted-installer-cli.git#egg=assisted-installer-cli
export AI_URL="$(hostname -I |cut -f1 -d' '):8090"
aicli create cluster {{ cluster }}
aicli create iso {{ cluster }}
aicli download iso {{ cluster }}
dnf copr enable karmab/kcli ; dnf -y install kcli
scp {{ cluster }}.iso {{ config_user }}@{{ config_host }}:/var/lib/libvirt/images
kcli -C {{ config_host }} start plan {{ cluster }}
