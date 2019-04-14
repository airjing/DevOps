#https://docs.openstack.org/kolla/latest/admin/image-building.html
#https://greatbsky.github.io/kolla-for-openstack-in-docker/en.html
mkdir Repos
cd Repos
git clone https://github.com/openstack/kolla
sudo -y apt install python-pip tox
pip install --upgrade pip==9.0.3
cd Repos/kolla
git checkout stable/mitaka
cd ..
pip install -r kolla/requirements.txt -r kolla/test-requirements.txt
pip install kolla/
cd kolla
cp -r etc/kolla /etc/
sudo apt -y install python-devel libffi-devel openssl-devel gcc
pip install -U python-openstackclient python-neutronclient
pip install tox
tox -e genconfig