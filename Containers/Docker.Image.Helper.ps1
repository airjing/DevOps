$ImageStore = "E:\DockerImages"
$jsonimages = @"
{
    "WCOW": [        
        {
            "image":"microsoft-powershell",
            "URL":"https://hub.docker.com/_/microsoft-powershell",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/powershell:latest"
                }
            ]
        },
        {
            "image":"microsoft/dotnet",
            "URL":"https://hub.docker.com/r/microsoft/dotnet",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull microsoft/dotnet"
                }
            ]
        },
        {
            "image":"microsoft/aspnetcore-build",
            "URL":"https://hub.docker.com/r/microsoft/aspnetcore-build",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull microsoft/aspnetcore-build"
                }
            ]
        },
        {
            "image":"microsoft/aspnetcore-build",
            "URL":"https://hub.docker.com/r/microsoft/aspnetcore-build",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull microsoft/aspnetcore-build"
                }
            ]
        },        
        {
            "image":"microsoft/aspnet",
            "URL": "https://hub.docker.com/_/microsoft-dotnet-framework-aspnet",
            "FeaturedTags": [
                {
                    "tag":"4.7.2",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/dotnet/framework/aspnet:4.7.2"
                },
                {
                    "tag":"3.5",
                    "pull":"False",
                    "pullcmd":"docker pull mcr.microsoft.com/dotnet/framework/aspnet:3.5"
                }
            ]            
        },
        {
            "image":"microsoft/windowsservercore",
            "URL":"https://hub.docker.com/_/microsoft-windows-servercore",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore",
                    "OsVersion":"Windows Server LTSC 2016"
                },
                {
                    "tag":"ltsc2019",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore:ltsc2019",
                    "OsVersion":"Windows Server LTSC 2019"
                },
                {
                    "tag":"1809",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore:1809",
                    "OsVersion":"windows Server, version 1809"
                }
            ]
        },
        {
            "image":"microsoft/nanoserver",
            "URL":"https://hub.docker.com/_/microsoft-windows-nanoserver",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/nanoserver",
                    "OsVersion":"Windows Server 2016 SAC"
                },
                {
                    "tag":"1809",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/nanoserver:1809",
                    "OsVersion":"windows Server, version 1809"
                }
            ]
        },
        {
            "image":"microsoft/mssql-server-windows-developer",
            "URL":"https://hub.docker.com/r/microsoft/mssql-server-windows-developer",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull microsoft/mssql-server-windows-developer",
                    "runcmd":"docker run -d -p 1433:1433 -e sa_password=<SA_PASSWORD> -e ACCEPT_EULA=Y microsoft/mssql-server-windows-developer"
                }
            ]
        },
        {
            "image":"microsoft/iis",
            "URL":"https://hub.docker.com/_/microsoft-windows-servercore-iis",
            "FeaturedTags":[
                {
                    "tag":"ltsc2019",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"
                },
                {
                    "tag":"windowsservercore-1803",
                    "pull":"True",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-1803"
                },
                {
                    "tag":"windowsservercore-1709",
                    "pull":"False",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-1709"
                },
                {
                    "tag":"windowsservercore-ltsc2016",
                    "pull":"False",
                    "pullcmd":"docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2016"
                }
            ]            
        },
        {
            "image":"redis",
            "URL":"https://hub.docker.com/_/redis",
            "FeaturedTags":[
                {
                    "tag":"null",
                    "pull":"True",
                    "pullcmd":"docker pull redis"
                }
            ]            
        },
        {
            "image":"mongo",
            "URL":"https://hub.docker.com/_/mongo",
            "FeaturedTags":[
                {
                    "tag":"null",
                    "pull":"True",
                    "pullcmd":"docker pull mongo"
                }
            ]            
        }
    ],
    "LCOW":[
        {
            "image":"microsoft/mcr-hello-world",
            "URL":"https://hub.docker.com/_/microsoft-mcr-hello-world",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"False",
                    "pullcmd":"docker pull mcr.microsoft.com/mcr/hello-world"
                }
            ]
        },
        {
            "image":"microsoft/azure-cli",
            "URL":"https://hub.docker.com/r/microsoft/azure-cli",
            "Tags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull microsoft/azure-cli"
                }
            ]
        },       
        {
            "image":"alpine",
            "URL":"https://hub.docker.com/_/alpine",
            "FeaturedTags":[
                {
                    "tag":"null",
                    "pull":"True",
                    "pullcmd":"docker pull alpine"
                }
            ]            
        },        
        {
            "image":"busybox",
            "URL":"https://hub.docker.com/_/busybox",
            "FeaturedTags":[
                {
                    "tag":"null",
                    "pull":"True",
                    "pullcmd":"docker pull busybox"
                }
            ]            
        },
        {
            "image":"ubuntu",
            "URL":"https://hub.docker.com/_/ubuntu",
            "FeaturedTags":[
                {
                    "tag":"14.04",
                    "pull":"True",
                    "pullcmd":"docker pull ubuntu:1404",
                    "OsVersion":"trusty"
                },
                {
                    "tag":"16.04",
                    "pull":"True",
                    "pullcmd":"docker pull ubuntu:1604",
                    "OsVersion":"xenial"
                },
                {
                    "tag":"18.04",
                    "pull":"True",
                    "pullcmd":"docker pull ubuntu:1804",
                    "OsVersion":"bionic"
                },
                {
                    "tag":"18.10",
                    "pull":"True",
                    "pullcmd":"docker pull ubuntu:1810",
                    "OsVersion":"cosmic"
                },
                {
                    "tag":"19.04",
                    "pull":"True",
                    "pullcmd":"docker pull ubuntu:1904",
                    "OsVersion":"disco"
                }
            ]            
        },
        {
            "image":"centos",
            "URL":"https://hub.docker.com/_/centos",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull centos",
                    "OsVersion":"7"
                },
                {
                    "tag":"centos6",
                    "pull":"True",
                    "pullcmd":"docker pull centos:centos6",
                    "OsVersion":"6"
                },
                {
                    "tag":"centos7.6.1810",
                    "pull":"True",
                    "pullcmd":"docker pull centos:centos7.6.1810",
                    "OsVersion":"7.6.1810"
                },
                {
                    "tag":"centos6.9",
                    "pull":"True",
                    "pullcmd":"docker pull centos:centos6.9",
                    "OsVersion":"6.9"
                },
                {
                    "tag":"centos6.6",
                    "pull":"True",
                    "pullcmd":"docker pull centos:centos6.6",
                    "OsVersion":"6.6"
                }
            ]            
        },
        {
            "image":"amazonlinux",
            "URL":"https://hub.docker.com/_/amazonlinux",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull amazonlinux",
                    "OsVersion":"2.0.20190212"
                }
            ]            
        },
        {
            "image":"swift",
            "URL":"https://hub.docker.com/_/swift",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull swift",
                    "OsVersion":"4.2.2"
                }
            ]            
        },
        {
            "image":"httpd",
            "URL":"https://hub.docker.com/_/httpd",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull httpd",
                    "OsVersion":"2.4.38"
                }
            ]            
        },
        {
            "image":"mariadb",
            "URL":"https://hub.docker.com/_/mariadb",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull mariadb",
                    "rumcmd":"docker run --name some-mariadb -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mariadb:tag",
                    "rumcmd1":"docker run --name some-app --link some-mariadb:mysql -d application-that-uses-mysql"
                }
            ]            
        },
        {
            "image":"mysql",
            "URL":"https://hub.docker.com/_/mysql",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull mysql:latest",
                    "OsVersion":"8.0.15",
                    "rumcmd":"docker run --name some-mysql -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql:tag",
                    "rumcmd1":"docker run --name some-app --link some-mariadb:mysql -d application-that-uses-mysql"
                }
            ]            
        },
        {
            "image":"nginx",
            "URL":"https://hub.docker.com/_/nginx",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull nginx:latest",
                    "OsVersion":"1.15.8",
                    "rumcmd":"docker run --name some-nginx -v /some/content:/usr/share/nginx/html:ro -d nginx"
                }
            ]            
        },
        {
            "image":"postgres",
            "URL":"https://hub.docker.com/_/postgres",
            "FeaturedTags":[
                {
                    "tag":"latest",
                    "pull":"True",
                    "pullcmd":"docker pull postgres:latest",
                    "OsVersion":"11.2",
                    "rumcmd":"docker run --name some-postgres -e POSTGRES_PASSWORD=mysecretpassword -d postgres"
                }
            ]            
        },
        {
            "image":"redis",
            "URL":"https://hub.docker.com/_/redis",
            "FeaturedTags":[
                {
                    "tag":"null",
                    "pull":"True",
                    "pullcmd":"docker pull redis"
                }
            ]            
        },
        {
            "image":"mongo",
            "URL":"https://hub.docker.com/_/mongo",
            "FeaturedTags":[
                {
                    "tag":"null",
                    "pull":"True",
                    "pullcmd":"docker pull mongo"
                }
            ]            
        }
    ]
}
"@

function Get-DockerImages {
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Platform
    )
    $objimages = ConvertFrom-Json $jsonimages
    $images = $objimages.WCOW    
    if($Platform -eq "linux")
    {
        $images = $objimages.LCOW
    }    
    foreach($i in $images)
    {
        for($t=0;$t -lt $i.Tags.Count;$t++)
        {
            if($i.Tags[$t].pull -eq "True")
            {
                Invoke-Expression $i.Tags[$t].pullcmd
            }
        }              
    }    
}

# export images to local driver
function Export-DockerImages
{
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $ExportToPath
    )
    if(!(Test-Path $ExportToPath))
    {
        New-Item -Path $ExportToPath -ItemType Directory -Force
    }
    $images = docker images
    for($i=1; $i -le $images.count-1;$i++)
    {
        $image = $images[$i] -split '\s+|\t+'
        $imageshortname = $image[0].split("/")[-1]
        $tag = $image[1]
        $imageid = $image[2]        
        $imagesize = $image[6]
        $imagepath = "$ExportToPath\$imageshortname-$tag.tar"
        if($imagepath -notmatch "<none>")
        {
            & docker $image[0] save -o $imagepath
        }          
    }
}
# import images
function Import-DockerImages
{
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ImportFromPath,
        [Parameter(Mandatory = $false)]
        [string]
        $TarFileList
    )
    if (Test-Path $ImportFromPath)
    {
        if(($TarFileList -ne $null) -or ($TarFileList -ne ""))
        {
            $imagefiles = $TarFileList.Split(";")      
        }
        else
        {
            $imagefiles = Get-ChildItem $ImportFromPath -Filter *.tar
        }
        foreach ($f in $imagefiles)
            {
                & docker load -i $f
            }  
    }
    else {
        Write-Error "$ImportFromPath doesn't exist!"
    }   
}

function Pull-DockerImages
{
    $dockerinfo = & docker info
    if($dockerinfo[17] -match "windows")
    {
        #Get-DockerImages
    }
    if($dockerinfo[28] -match "linux")
    {
        #Get-DockerImages -Platform "linux"
    }
}

Pull-DockerImages
Export-DockerImages -ExportToPath $ImageStore
Import-DockerImages -ImportFromPath $ImageStore -TarFileList "hello.tar;abc.tar"
