#https://docs.openstack.org/kolla/latest/admin/image-building.html
#https://greatbsky.github.io/kolla-for-openstack-in-docker/en.html
mkdir Repos
cd Repos
git clone https://github.com/openstack/kolla
sudo apt -y install python-pip tox
pip install --upgrade pip==9.0.3
cd Repos/kolla
git checkout stable/rocky
cd ..
sudo pip install -r kolla/requirements.txt -r kolla/test-requirements.txt
sudo pip install kolla/
cd kolla
cp -r etc/kolla /etc/
sudo apt -y install python-devel libffi-devel openssl-devel gcc
pip install -U python-openstackclient python-neutronclient
pip install tox
cd Repos/kolla
tox -e genconfigkolla