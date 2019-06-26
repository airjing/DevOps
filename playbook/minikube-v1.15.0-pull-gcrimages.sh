docker pull gcr.azk8s.cn/google_containers/k8s-dns-sidecar-amd64:1.15.0
docker pull gcr.azk8s.cn/google_containers/k8s-dns-dnsmasq-nanny-amd64:1.15.0
docker pull gcr.azk8s.cn/google_containers/kubernetes-dashboard-amd64:v1.10.1
docker pull gcr.azk8s.cn/google_containers/kube-scheduler:v1.15.0
docker pull gcr.azk8s.cn/google_containers/coredns:1.3.1
docker pull gcr.azk8s.cn/google_containers/kube-controller-manager:v1.15.0
docker pull gcr.azk8s.cn/google_containers/kube-apiserver:v1.15.0
docker pull gcr.azk8s.cn/google_containers/pause:3.1
docker pull gcr.azk8s.cn/google_containers/etcd:3.3.10
docker pull gcr.azk8s.cn/google_containers/kube-addon-manager:v9.0
docker pull gcr.azk8s.cn/google_containers/k8s-dns-kube-dns-amd64:1.14.13
docker pull gcr.azk8s.cn/google_containers/kube-proxy:v1.15.0
docker pull gcr.azk8s.cn/google_containers/storage-provisioner:v1.8.1
docker pull airjing/repo:latest
docker tag airjing/repo:latest gcr.io/k8s-minikube/storage-provisioner:v1.8.1
docker rmi airjing/repo:latest