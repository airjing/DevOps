<#
.SYNOPSIS
A helper which interact with IPAM website - http://ipam.rnea.iptv.mr.ericsson.se

.DESCRIPTION
Function collections to manage IP address on http://ipam.rnea.iptv.mr.ericsson.se

.EXAMPLE
C:\PS> IPAM.Helper.ps1

.LINK
https://dev.azure.com/mediakind/Toolbox/_git/BJLABOPS
https://phpipam.net/api/api_documentation/
https://phpipam.net/api/api_curl_example/
#>
$invokePath = Split-Path -Parent $PSCommandPath
$ipamapiurl = "http://ipam.xx.xx.xxx.xx/api/myapp/"
$ipamuser = "admin"
$ipampwd = "P@ssword!$"
$defaultSourceFilePath = "$invokePath\BJLAB_IP.xlsx"
$r = $null

function Get-BasicAuthToken{
<#
.DESCRIPTION
Convert clear user:password to based64 string which used to authentication on 
IPAM website.

.INPUTS
System.String. Get global variables $ipamuser and $ipampwd

.OUTPUTS
System.String. Base64 encoded string

#>
    $pair = "{0}:{1}" -f $ipamuser,$ipampwd
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    return $base64  
}

function Get-VlanFromSource{
<#

.DESCRIPTION
Get VLAN info from an "overall" sheet in Excel file.

.OUTPUTS
System.Array

#>
    param(
        # Parameter SourceFilePath
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_})]
        [string]
        $SourceFilePath
    )
    # all valns in "overall" sheet
    $sheet = "overall"
    if(!$SourceFilePath)
    {
        $SourceFilePath = $defaultSourceFilePath
    }
    $skiprow = 1
    $domainId = 1
    $Rows = [array]@()
    $excel = New-Object -ComObject Excel.application
    $wb = $excel.Workbooks.Open($SourceFilePath)    
    $sh = $wb.Sheets.Item($sheet).UsedRange
    $sh.rows | Select-object -Skip $skiprow |ForEach-Object {
        $row = $_.Value2
        
        if($row[1,2])
        {
            $description = $row[1,2]
        }
        else{
            $description = ""
        }
        if($row[1,9] -eq 1)
        {
            $item = @{
                "domainId" = $domainId
                "name" = $row[1,1]                
                "description" = $description
                "CIDR" = $row[1,3]
                "number" = $row[1,8]
            }
            $Rows += $item
        }
    }
    $excel.Workbooks.Close()
    return $Rows
}
function Get-SubnetFromSource{
<#

.DESCRIPTION
Get IP-Host mapping from an sheet in Excel file.

.PARAMETER SourceFilePath
System.String. The Path of source file.

.PARAMETER Subnet
System.String. represent sheet name. expected columns are listed below:
- ip
- hostname
- description
- port
- Switch
- Tag 
- mac 
- owner 
- subnetId. 
- action. Boolean, 1 means add that entity to IPAM website. 0 means skip.

.OUTPUTS
System.Array. A collections of all IP entities.

#>
    param(
        # Source File Path
        [Parameter(Mandatory = $false)]
        [string]
        $SourceFilePath,
        # Sheet Name
        [Parameter(Mandatory = $false)]
        [string]
        $Subnet
    )
    if(!$SourceFilePath)
    {
        $SourceFilePath = $defaultSourceFilePath
    }    
    if($Subnet)
    {
        $Subnet = "10.164.78.0"
    }
    # skip first 4 rows.    
    $skiprow = 4
    $Subnets = @()
    $excel = New-Object -ComObject Excel.application
    $wb = $excel.Workbooks.Open($SourceFilePath)    
    #$sh = $wb.Sheets.Item($Subnet).Range("A1:J64")    
    $sh = $wb.Sheets.Item($Subnet).UsedRange
    $sh.rows | Select-object -Skip $skiprow |ForEach-Object {
        $row = $_.Value2
        if($row[1,10] -eq 1)
        {
            $owner = ""
            $mac = ""
            $tagInText = $row[1,6]
            $tag = 2
            if(!$tagInText)
            {
                $tagInText = "Used"
            }            
            if($row[1,7])
            {
                $mac = $row[1,7]
            }
            if($row[1,8])
            {
                $owner = $row[1,8]
            }
            switch($tagInText){
                {$tagInText -eq "Offline"}{$tag = 1}
                {$tagInText -eq "Used"}{$tag = 2}
                {$tagInText -eq "Reserved"}{$tag = 3}
                {$tagInText -eq "DHCP"}{$tag = 4}
            }
            $ip = @{
                'ip' = $row[1,1]
                'hostname' = $row[1,2]
                'description' = $row[1,3]
                'port' = $row[1,4]
                'note' = $row[1,5]
                'tag' = $tag
                'mac' = $mac
                'owner' = $owner
                'subnetId' = $row[1,9]
            }
            $Subnets += $ip
        }
    }
    $excel.Workbooks.Close()
    return $Subnets
}

function Update-SubnetToSource{
<#

.DESCRIPTION
Update Subnet fields to Source File. the most common scenario is set action 
column to 0 when that entity added to IPAM website.

.PARAMETER Field
Indicate which column to be update in spreadsheet.

.PARAMETER StatusCode
Based on http status code to update parameter Field

.OUTPUTS
Boolean. 
0 = Success. 
1 = Fail.

#>
    param(
        # SourceFilePath
        [Parameter(Mandatory = $false)]
        [string]
        $SourceFilePath,
        # IP Address
        [Parameter(Mandatory = $true)]
        [string]
        $IPAddress,
        # Sheet Name
        [Parameter(Mandatory = $false)]
        [string]
        $Sheet,
        # UpdateField
        [Parameter(Mandatory = $false)]
        [string]
        $UpdateField,
        # StatusCode
        [Parameter(Mandatory = $false)]
        [string]
        $StatusCode
    )
    if(!$Sheet)
    {
        $Sheet = "10.164.78.0"
    }
    if(!$SourceFilePath)
    {
        $SourceFilePath = $defaultSourceFilePath
    }
    if(!$UpdateField)
    {
        $UpdateField = "action"
    }    
    $actionText = 1
    try{
        $excel = New-Object -ComObject Excel.application
        $wb = $excel.Workbooks.Open($SourceFilePath)
        #$sh = $wb.Worksheets.Item($Sheet).Range("A1:J64")    
        $sh = $wb.Worksheets.Item($Sheet).UsedRange
        $row = $sh.Find("$IPAddress").Row
        $column = $sh.Find("$UpdateField").Column
        if($row -and $column)
        {        
            switch ($StatusCode) {
                {$StatusCode -match "20"} { $actionText = 0 }
                {($StatusCode -eq "400") -or ($StatusCode -eq "500")} { $actionText = 1 }
                {$StatusCode -eq 409} { $actionText = 0 }
            }           
            $sh.Cells.Item($row,$column).Value2 = $actionText
        }        
    }
    catch{
        throw $_.Exception
    }
    finally{
        $wb.Save()
        $wb.Close()
    }    
}

function Get-SubnetOnIpam{
<#

.DESCRIPTION
Get subnet ID from IPAM site

.PARAMETER SubnetInCIDR
System.String like 10.164.78.0 without netmask

.OUTPUTS
Subnet object

#>
    param(
        # Parameter Subnet
        [Parameter(Mandatory = $true)]
        [string]
        $SubnetInCIDR
    )
    $uri = "{0}subnets/search/{1}/" -f $ipamapiurl,$SubnetInCIDR
    $response = Invoke-IpamApi -Uri $uri -Method Get
    if($response -eq "404")
    {
        return $response
    }
    else {        
        return ($response.Content | ConvertFrom-Json).data
    }
}

function ConvertTo-IPv4Binarry
{
<#

.DESCRIPTION
Convert IPAddress string form to binarry form.

.PARAMETER IPAddress
System.String

.OUTPUTS
System.String

#>
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $IPAddress
    )    
    $binIPAddr = $null
    $ipAddr = [System.Net.IPAddress]::Parse($IPAddress)
    $ipAddrBytes = $ipAddr.GetAddressBytes()
    foreach($byte in $ipAddrBytes)
    {
        $binIPAddr += [System.Convert]::ToString($byte,2).PadLeft(8,'0')
    }
    return $binIPAddr
}
function ConvertTo-IPv4String
{
<#

.DESCRIPTION
Convert IPAddress binarry form to String form.

.PARAMETER IPAddressBinarry
System.String

.OUTPUTS
System.String

#>
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $IPAddressBinarry
    )
    for($i = 0; $i -lt 32; $i+=8)
    {
        $strByte = $IPAddressBinarry.Substring($i,8)
        $strIP += "$([System.Convert]::ToInt32($strByte,2))."
    }
    return $strIP.TrimEnd(".")
}

function ConvertTo-NetmaskInIPv4
{
<#

.DESCRIPTION
Convert netmask length to IPV4

.PARAMETER PrefixLength
System.String

.OUTPUTS
System.String

#>
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [byte]
        $PrefixLength
    )
    $binPrefixLength = ('1' * $PrefixLength).PadRight(32,'0')
    for($i = 0;$i -lt 32; $i+=8)
    {
        $strByte = $binPrefixLength.Substring($i,8)
        $strIP += "$([System.Convert]::ToInt32($strByte,2))."
    }
    return $strIP.TrimEnd(".")
}

function  Get-NetworkIDIPv4 {
<#

.DESCRIPTION
Calculate NetworkID by IPAddress and PrefixLength

.PARAMETER IPAddress
System.string. like 10.164.78.10

.PARAMETER PrefixLength
System.byte. like 26

.OUTPUTS
System.String. like 10.164.78.0/26
this string will be used to query subnetId on IPAM site.

.EXAMPLE
Get-NetworkIDIPv4 -IPAddress "10.170.137.168" -PrefixLength 27

#>
    param (
        # Parameter IPAddress
        [Parameter(Mandatory = $true)]
        [string]
        $IPAddress,
        # Parameter PrefixLength
        [Parameter(Mandatory = $true)]
        [byte]
        $PrefixLength
    )
    $netmaskIP = ConvertTo-NetmaskInIPv4 -PrefixLength $PrefixLength
    $binIPAddress = ConvertTo-IPv4Binarry -IPAddress $IPAddress
    $binNetmask = ConvertTo-IPv4Binarry -IPAddress $netmaskIP

    #Calculate NetworkID
    for($i =0; $i -lt 32;$i++)
    {
        if(($binIPAddress[$i] -eq $binNetmask[$i]) -and ($binNetmask[$i] -ne '0'))
        {
            $bitNetworkID = "1"
        }
        else {
            $bitNetworkID = "0"
        }
        $binNetworkID += $bitNetworkID
    }    
    $networkID = ConvertTo-IPv4String -IPAddressBinarry $binNetworkID
    
    Write-Host "------------------------------------------------------------"
    
    $msg = "{0,20} -> {1,-40}" -f $PrefixLength,$netmaskIP
    Write-Host $msg
    
    $msg = "{0,20} -> 0x{1,-40}" -f $IPAddress,$binIPAddress
    Write-Host $msg
    
    $msg = "{0,20} -> 0x{1,-40}" -f $netmaskIP,$binNetmask
    Write-Host $msg
   
    $msg = "{0,20} -> 0x{1,-40}" -f "NetworkID in Binarry",$binNetworkID    
    Write-Host $msg
    
    $msg = "{0,20} -> {1,-40}" -f "NetworkID in Decimal",$networkID
    Write-Host $msg
    Write-Host "------------------------------------------------------------"
    return $networkID
}
function Get-IpamToken {
<#

.DESCRIPTION
Get token from IPAM website.

.INPUTS
System.String. a base64 encoded string which returned by Get-BasicAuthToken

.OUTPUTS
System.String. a token which returned by IPAM website.

#>    
    $uri = "{0}user/" -f $ipamapiurl
    $base64 = Get-BasicAuthToken
    $header = @{
        "Authorization" = "Basic $base64"
    }
    try{
        $response = Invoke-WebRequest -Uri $uri -Method 'POST' -Headers $header        
        $responseContent = $response.Content | ConvertFrom-Json
        $token = $responseContent.data.token
        $expires = $responseContent.data.expires
        if($expires -gt [DateTime]::Now)
        {
            return $token
        }
    }
    catch{
        $_.Exception.Response.StatusCode.value__
    }    
}

function Invoke-IpamApi{
<#

.DESCRIPTION
a common function which help on consume IPAM APIs.

.PARAMETER Uri
System.String. Valid format is http://ipam/api/myapp/controllers

.PARAMETER Method
enum WebRequestMethod. 

.PARAMETER Body
System.String

.OUTPUTS
http status code

#>

    param(
        # Uri to IPAM API
        [Parameter(Mandatory = $true)]
        [string]
        $Uri,
        # Method of Restful API
        [Parameter(Mandatory = $true)]
        [Validateset("Default","Delete","Get","Head","Merge","Options","Patch",`
                    "Post","Put","Trace")]
        [string]
        $Method,
        # Parameter Headers
        [Parameter(Mandatory = $false)]
        [hashtable]
        $Headers,
        # hashtable object represents IP object
        [Parameter(Mandatory = $false)]
        [hashtable]
        $Param
    ) 
    $statuscode = ""   
    if(!$Headers)
    {
        $Headers = @{
            "Content-Type" = "application/json"
            "token" = Get-IpamToken
        } 
    }    
    if(($Method -eq "Get") -or ($Method -eq "Post"))
    {
        $Body = $Param | ConvertTo-Json
    }
    if($Method -eq "Patch")
    {
        $Body = ConvertTo-UrlEncoded -Hashtable $Param
        $Body.TrimEnd("&")
        $Headers."Content-Type" = "application/x-www-form-urlencoded"
    }
    #if(($Method -eq "Patch") -and ($Uri -match "devices/"))
    #{
    #    $Body = $Param
    #}
    
    try{
        if(!$Body)
        {
            $response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers
        }
        else {
            $response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers `
                                            -Body $Body
        }       
        return $response
    }
    catch{
        $statuscode = $_.Exception.Response.StatusCode.value__
        return $statuscode
    }    
}

function Get-IPAddressOnIpam{
<#

.DESCRIPTION
Get IPAddress object on Ipam by IPAddress or hostname

.PARAMETER IPAddress
System.String

.PARAMETER Hostname
System.String

.OUTPUTS
IPAddress object
#>
    param(
        # Parameter IPAddress
        [Parameter(Mandatory = $false)]
        [string]
        $IPAddress,
        # Parameter Hostname
        [Parameter(Mandatory = $false)]
        [string]
        $Hostname
    )
    if($IPAddress)
    {
        $uri = "{0}addresses/search/{1}/" -f $ipamapiurl,$IPAddress
    }
    if($Hostname)
    {
        $uri = "{0}addresses/search_hostname/{1}/" -f $ipamapiurl,$Hostname
    }
    if($uri)
    {
        $response = Invoke-IpamApi -Uri $uri -Method Get
        $IP = ($response.Content | ConvertFrom-Json).data
        return $IP
    }
    else {
        Write-Error "Cannot send request to empty EndPoint"
    }   
}

function Update-IpAddressOnIpam{
<#

.DESCRIPTION
Update the ip address information on IPAM website.

.PARAMETER IP
System.Hashtable. 

.PARAMETER SubnetId
System.int. The SubnetId which the IP belongs to.

.PARAMETER Action
System.string. either Create or Update

.PARAMETER SyncUpdateToSource
boolean. if set to true to update the change to source spreadsheet file.

#>    
    param(
        # IP object
        [Parameter(Mandatory = $false,ValueFromPipeline = $true)]
        [hashtable]
        $IP,
        # Subnet
        [Parameter(Mandatory = $false)]
        [string]
        $Subnet,
        # Parameter SubnetId
        [Parameter(Mandatory = $false)]
        [int16]
        $SubnetId,        
        # Parameter Action
        [Parameter(Mandatory = $false)]
        [string]
        $Action,
        # Parameter SyncUpdateToSource
        [Parameter(Mandatory = $false)]
        [bool]
        $SyncUpdateToSource
    )
    if(!$Action)
    {
        $Action = "Update"
    }
    $SyncUpdateToSource = $false
    if(!$IP)
    {
        $IP = @{
            "subnetId" = 8
            "ip" = "10.164.78.10"        
            "description" = "Ingress"
            "hostname" = 'BJE12-ACQ-02'
            "mac" = ""
            "owner" = ""
            "tag" = 2
                #Tags
                #   {
                #   "Offline" = 1
                #   "Used" = 2
                #   "Reserved" = 3
                #   "DHCP" = 4
                #
                #   }
            "port" = "eth6"
            "note" = "switch003"
        }       
    }    
    $ipaddress = $IP.ip
    if($Action -eq "Update")
    {
        $uri = "{0}addresses/{1}/" -f $ipamapiurl,$IP.id
        $IP.Remove("id")
        $IP.Remove("ip")
        $response = Invoke-IpamApi -Uri $uri -Method Patch -Param $IP
        $code = $response[1].StatusCode
        if($SyncUpdateToSource)
        {
            Update-SubnetToSource -IP $ipaddress -Sheet $Subnet -StatusCode $response
        }        
        switch ($code) {
            {$code -eq 200} { Write-Host "$Action Succeed - $ipaddress"}
            {$code -eq 400} { Write-Error "$Action Bad Request - $ipaddress"}
            {$code -eq 409} { Write-Warning "$Action Conflict - $ipaddress"}
            {$code -eq 401} { Write-Error "$Action Wrong token - $ipaddress"}        
        }
    }
    if($Action -eq "Create")
    {        
        $uri = "{0}addresses/" -f $ipamapiurl
        $response = Invoke-IpamApi -Uri $uri -Method Post -Param $IP
        $code = ($response.Content | ConvertFrom-Json).code
        if($SyncUpdateToSource)
        {
            Update-SubnetToSource -IP $ipaddress -Sheet $Subnet -StatusCode $response
        }        
        switch ($code) {
            {$code -eq 201} { Write-Host "$Action Succeed - $ipaddress"}
            {$code -eq 400} { Write-Error "$Action Bad Request - $ipaddress"}
            {$code -eq 409} { Write-Warning "$Action Conflict - $ipaddress"}
            {$code -eq 401} { Write-Error "$Action Wrong token - $ipaddress"}        
        }
    } 
}

function ConvertTo-UrlEncoded{
<#

.DESCRIPTION
Convert a hashtable object to Uel encoded string, like
"Key1=Key1.Value&key2=key2.Value"
But ignore keys with empty string value.

.PARAMETER Hashtable

.OUTPUTS
system.string
expected output like this: 
"hostname=SHAOJC-HP&description=Ethernet&mac=40-B0-34-3B-40-44&tag=2"
#>
    param(
        # Parameter Hashtable
        [Parameter(Mandatory = $true)]
        [hashtable]
        $Hashtable
    )
    $param = ""
    foreach($item in $Hashtable.GetEnumerator())
    {
        if($item.Value -ne "")
        {
            if($item.Key -eq "tag")
            {
                switch ($item.Value) {
                    {$item.Value -eq "Offline"} { $Item.Value = 1 }
                    {$item.Value -eq "Used"} { $Item.Value = 2 }
                    {$item.Value -eq "Reserved"} { $Item.Value = 3 }
                    {$item.Value -eq "DHCP"} { $Item.Value = 4 }
                    Default {}
                }
            }            
            $param += "{0}={1}&" -f $item.key,$item.value
        }
    } 
    return $param.TrimEnd("&")  
}

function Update-SubnetOnIpam{
<#
.DESCRIPTION
Add or Update VLAN defination on IPAM

.PARAMETER Subnet
System.Array.

.PARAMETER domainId
System.Int

.OUTPUTS
System.String. return http status code.

#>

    param(
        # Parameter Subnet
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]
        $Subnet,
        # Parameter domainId
        [Parameter(Mandatory = $false)]
        [byte]
        $domainId
    )
    if(!$domainId)
    {
        $domainId = 1
    }
    if(!$Subnet)
    {
        
        $item = @{
            "domainId" = $domainId
            "name" = "testdata_vlan_name"
            "number" = 1000
            "description" = "testdata_vlan_description"
        }
        $Subnet += $item
    }
    foreach($v in $Subnet){
        # create VLAN
        if($v.description -eq "")
        {
            $desc = "{0}.VLAN.{1}" -f $v.name,$v.number
        }
        $vlan = @{
            "domainId" = $v.domainId
            "name" = "VLAN." + $v.name
            "number" = $v.number
            "description" = $desc
        }
        $uri = "{0}vlan/" -f $ipamapiurl
        $response = Invoke-IpamApi -Uri $uri -Method Post -Param $vlan
        $vlanid = $response.Content | ConvertFrom-Json | Select-Object id
        $param_subnet = $null
        if($response.StatusCode -match "20")
        {
            $uri = "{0}subnets/" -f $ipamapiurl
            $desc = "{0}.Subnet_{1}" -f $v.name,$v.CIDR
            $param_subnet = @{
                "subnet" = $v.CIDR.split("/")[0]
                "mask" = [byte]$v.CIDR.split("/")[-1]
                "description" = $desc
                "sectionId" = 3
                "vlanId" = $vlanid.id
            }            
            $response = Invoke-IpamApi -Uri $uri -Method Post -Param $param_subnet
        }
    }
}

function Get-VlanOnIpam{
<#

.DESCRIPTION
Get All VLANs from IPAM

.OUTPUTS
System.Array

#>
    $uri = "{0}vlan/" -f $ipamapiurl
    $response = Invoke-IpamApi -Uri $uri  -Method Get
    return = ($response.content | convertfrom-json).data
}

function Remove-VlanOnIpam {
<#

.DESCRIPTION
Remove a VLAN on IPAM by ID

.PARAMETER IDRange
System.Array VLAN object ID in IPAM, it's not VLANID on switch.

.OUTPUTS
System.Array. response with each ID

.EXAMPLE

Remove-VlanOnIpam -IDRange (5..20)

#>
    param (
        # Parameter ID
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]
        $IDRange
    )
    $results = @()
    $uri = "{0}vlan/" -f $ipamapiurl
    if($IDRange)
    {
        foreach($i in $IDRange)
        {
            $body = @{
                "id" = $i
            }
            $response = Invoke-IpamApi -Uri $uri -Method Delete -Param $body
            $result = @{
                "$i" = "$response"
            }
            $results += $result
        }
    }
    $results    
}
function Get-RackOnIpam{
<#

.DESCRIPTION
Get Rack's information on IPAM.

.PARAMETER Rack
System.String. Rack Name

.OUTPUTS
System.Array

#>

    param(
        # Parameter Rack
        [Parameter(Mandatory = $false,ValueFromPipeline = $true)]
        [string]
        $Rack
    )
    $uri = "{0}tools/racks/" -f $ipamapiurl
    $response = Invoke-IpamApi -Uri $uri -Method 'Get'
    if($Rack)
    {
        $r =  $response.Content | ConvertFrom-Json | foreach-object { $_.data } `
                                | Where-Object {$_.name -eq $Rack}
        if($r)
        {
            return $r
        }
        else {
            Write-Warning "$Rack doesn't exist!"
        }
    }
    else {
        if($response.StatusCode -eq "200")
        {
            return ($response.Content | ConvertFrom-Json).data
        }
    }
}

function Update-DeviceOnIpam{
<#

.DESCRIPTION
Create a new device on IPAM

.PARAMETER Device
hashtable.
$device = @(
    @{
        "hostname" = "testdata_HOSTNAME"
        "ip_addr" = "192.168.1.1"
        "description" = "description"
        "sections" = 3
        "rack" = "1"
        "rack_start" = "25"
        "rack_size" = "1"
        "location" = "1"
    }
)
.PARAMETER Action
Create or Update

.OUTPUTS
System.Array. response status for each device

#>
    param(
        # Parameter Device
        [Parameter(Mandatory = $false,ValueFromPipeline = $true)]
        [hashtable]
        $Device,
        # Parameter Action
        [Parameter(Mandatory = $false)]
        [string]
        $Action
    )
    $results = @()
    $uri = "{0}devices/" -f $ipamapiurl
    if(!$Device)
    {        
        $Device = @(
            @{
                "hostname" = "BJDF4-AS-01"
                "ip_addr" = ""
                "description" = "testdata_description"
                "sections" = 3
                "rack" = "1"
                "rack_start" = "1"
                "rack_size" = "1"
                "location" = "1"
            }
        )
    }   
    #$rack = Get-RackOnIpam -Rack $Device.Rack
    $dev = Get-DeviceOnIpam -Devicename $Device.hostname
    $Method = 'Post'    
    # Update exist device
    if($dev -ne -1)
    {
        $Method = 'Patch'
        $uri = "{0}{1}/" -f $uri,$dev.id
        $body = @{            
            "hostname" = $Device.hostname
            "ip_addr" = $Device.ip_addr
            #"description" = $Device.description
            "sections" = 3
            "rack" = "$($Device.Rack)"
            "rack_start" = $Device.Rack_Start
            "rack_size" = "1"
            "location" = 1
        }
        $response = Invoke-IpamApi -Uri $uri -Method $Method -Param $body
        $result = @{
            "hostname" = $Device.hostname
            "Status" = $response[1]
            "id" = $dev.id
        }
        $results += $result
    }
    #Create a new device
    else {
        $body = @{
            "hostname" = $Device.hostname
            "ip_addr" = $Device.ip_addr
            #"description" = $Device.description
            "sections" = 3
            "rack" = "$($Device.Rack)"
            "rack_start" = $Device.Rack_Start
            "rack_size" = "1"
            "location" = $Device.Location
        }
        $response = Invoke-IpamApi -Uri $uri -Method $Method -Param $body
        $result = @{
            "hostname" = $Device.hostname
            "Status" = ($response.Content | ConvertFrom-Json).message 
            "id" = ($response.Content | ConvertFrom-Json).id
        }
        $results += $result                      
    }
    return $results      
}

function Get-DeviceOnIpam{
<#

.DESCRIPTION
Get a device from IPAM site by given name.

.PARAMETER Devicename
System.String. Device Name

.OUTPUTS
hashtable or -1

#>
    param(
        # Parameter Device
        [Parameter(Mandatory = $true)]
        [string]
        $Devicename
    )
    $uri = "{0}devices/" -f $ipamapiurl
    $response = Invoke-IpamApi -Uri $uri -Method Get
    $dev = ($response.Content | ConvertFrom-Json).data `
            | Where-Object {$_.hostname -eq $Devicename}
    if($dev)
    {
        return $dev
    }
    else {
        return -1
    }
}
#Get-IpamToken
#Update-IpAddressOnIpam
#Get-SubnetFromSource -Subnet "10.164.78.0" | Update-IpAddressOnIpam -IP $input -Subnet "10.164.78.0"
#New-DeviceOnIpam
#Get-DeviceOnIpam -Device "BJDF4-AS-02"
#Get-SubnetOnIpam "10.164.78.0/26"
#Get-IPAddressOnIpam -IPAddress "10.164.78.16"
Get-VlanFromSource | Update-SubnetOnIpam -Subnet $input