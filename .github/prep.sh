apt-get update
apt-get -y install podman pycodestyle codespell

python3 -m venv venv
. venv/bin/activate
pip3 install copr-cli pep8 wheel setuptools twine build
