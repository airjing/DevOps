#https://docs.openstack.org/kolla/latest/admin/image-building.html
#https://greatbsky.github.io/kolla-for-openstack-in-docker/en.html
#https://docs.openstack.org/kolla-ansible/latest/user/quickstart.html
# Install dependencies
sudo apt-get update -y
sudo apt-get install -y python-dev libffi-dev gcc libssl-dev python-selinux python-setuptools python-pip
sudo pip install -U pip

sudo rm -r /usr/lib/python2.7/dist-packages/PyYAML-3.11.egg-info
sudo rm -r /usr/lib/python2.7/dist-packages/yaml*
sudo pip install ansible
sudo pip install kolla-ansible
sudo mkdir -p /etc/kolla
sudo chown $USER:$USER /etc/kolla
cp -r /usr/local/share/kolla-ansible/etc_examples/kolla/* /etc/kolla
cp /usr/local/share/kolla-ansible/ansible/inventory/* .
sudo kolla-genpwd
sudo pip install kolla
sudo pip install tox
cd ~\Repos\kolla
tox -e genconfig
sudo kolla-build -b ubuntu
sudo kolla-build --registry 10.0.75.10:4000 --push
sudo kolla-ansible -i all-in-one bootstrap-servers
sudo kolla-ansible -i all-in-one prechecks
sudo kolla-ansible -i all-in-one deploy

