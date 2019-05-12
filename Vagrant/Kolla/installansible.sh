echo 'starting install ansible'
# update apt source
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
sudo cp /home/vagrant/163-xenial.list /etc/apt/sources.list
sudo apt-get update
sudo apt-get install python-pip
sudo pip install -U pip
sudo apt-get install python-dev libffi-dev gcc libssl-dev python-selinux python-setuptools
# Install Docker
sudo apt-get -y install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
#sudo add-apt-repository "deb [arch=amd64] http://mirrors.aliyun.com/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
sudo add-apt-repository "deb [arch=amd64] https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get -y update
sudo apt-get -y install docker-ce --allow-unauthenticated
sudo apt-add-repository --yes --update ppa:ansible/ansible
sudo apt-get install ansible
sudo apt-get install cifs-utils,bind9,dnsutils
sudo rm -r /usr/lib/python2.7/dist-packages/PyYAML-3.11.egg-info
sudo rm -r /usr/lib/python2.7/dist-packages/yaml*
sudo pip install kolla-ansible
sudo cp -r /usr/local/share/kolla-ansible/etc_examples/kolla /etc/
sudo cp /usr/local/share/kolla-ansible/ansible/inventory/* .  
sudo kolla-ansible/tools/generate_passwords.py
sudo apt-get upgrade
sudo cp -p /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
sudo docker pull registry.docker-cn.com/library/ubuntu:16.04