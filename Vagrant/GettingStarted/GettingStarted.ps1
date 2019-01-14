# common box
# generic/centos7
# generic/ubuntu1604
$boxes = @"
[{
    "Box":"generic/centos7"
    "Provider":"hyperv"
    "Description":"A generic CentOS 7.6 image, ready for use as an application or development environment."
},
{
    "Box":"generic/ubuntu1604"
    "Provider":"hyperv"
    "Description":"A generic Ubuntu 16.04.5(aka Xenial Xerus) image."
}
"@


#vagrant init hashicorp/precise64
#vagrant up

$jsonboxes = $boxes | ConvertTo-Json
$jsonboxes[0]