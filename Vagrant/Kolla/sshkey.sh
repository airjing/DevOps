# generate privatekey for ansible
sudo ssh-keygen -f /home/vagrant/.ssh/id_rsa -t rsa -b 4096 -q -N ""
sudo ssh-agent bash
sudo ssh-add /home/vagrant/.ssh/id_rsa
# generate inventory file
#sudo echo "testserver ansible_host=127.0.0.1 ansible_port=22 ansible_user=vagrant ansible_private_key_file=/home/vagrant/.ssh/id_rsa" > /home/vagrant/playbook/hosts
sudo chown vagrant /home/vagrant/.ssh/id_rsa
sudo chown vagrant /home/vagrant/.ssh/id_rsa.pub