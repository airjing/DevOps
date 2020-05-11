<#
.SYNOPSIS
CosmosLab Main Script File

.DESCRIPTION
Function collections for Server Management.

.EXAMPLE
C:\PS> Main.ps1

.LINK
https://dev.azure.com/mediakind/Toolbox/_git/BJLABOPS

#>
$invokePath = Split-Path -Parent $PSCommandPath
. "$invokePath\Logging.Helper.ps1"
$Hostname = (Get-Childitem Env:\COMPUTERNAME).Value
$Model = (Get-WmiObject Win32_ComputerSystem).Model
$LabProfile = $null
$artifact = Get-Content "$invokePath\Artifacts.json" | ConvertFrom-Json
$ops = @{
        Root = "C:\CosmosLab";
        VHDStore = "C:\CosmosLab\ParentDisks"
        }
                
function Get-ComputerInfo {
<#
.EXAMPLE
$lines = Get-Content C:\Users\shaojc\Repos\BJLABOPS\CosmosLab\LabManifest\pkilab\mr.txt
foreach($l in $lines)
{
    Get-ComputerInfo -ComputerName localhost | Export-Xml -OutputFile ..\localhost.xml
}
#>
    param (
        [Parameter(Mandatory = $false,ValueFromPipeline = $true)]
        [string]
        $ComputerName
    )
    if(!$ComputerName)
    {
        $ComputerName = "localhost"
    }
    if(!(Test-Connection $ComputerName -Quiet))
    {
        $info = @{
            "Hostname" = $ComputerName
            "Status" = "Offline"
        }
        $Server = New-Object -TypeName PSObject -Property $info
        return $Server
    }
    else
    {
        $wmi_computersystem = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName  -ErrorAction SilentlyContinue
        if(!$wmi_computersystem)
        {
            $info = @{
                "Hostname" = $ComputerName
                "Status" = "AccessDenied"
                "BIOS" = ""
                "OS" = ""
                "NetAdapters" = ""
                "InstalledSoftwares" = ""
            }
            $Server = New-Object -TypeName PSObject -Property $info
            return $Server  
        }
        $wmi_os = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName
        $wmi_bios = Get-WmiObject Win32_BIOS -ComputerName $ComputerName
        $OSInstallDate = $wmi_os.ConvertToDateTime($wmi_os.InstallDate)
        $OSLiveTime = (Get-Date) - $OSInstallDate
        $LastBootUpTime = $wmi_os.ConvertToDateTime($wmi_os.LastBootUpTime)
        $UpTime = (Get-Date) - $LastBootUpTime
        $os = @{
            "OSCaption" = $wmi_os.Caption.Replace("® "," ")
            "BuildNumber" = $wmi_os.BuildNumber
            "BootDevice" = $wmi_os.BootDevice
            "CurrentTimeZone" = $wmi_os.CurrentTimeZone
            "OSArchitecture" = $wmi_os.OSArchitecture
            "WindowsDirectory" = $wmi_os.WindowsDirectory
            "OSInstallDate" = ("{0:s}" -f $OSInstallDate)
            "OSLiveTime" = ("{0:d}" -f [string]$OSLiveTime)
            "UpTime" = ("{0:d}" -f [string]$UpTime)
        }
        # Query NetAdapter by WMI to support Win2008
        $netadapters = Get-WmiObject Win32_NetworkAdapter -ComputerName $ComputerName | where-object {$_.MacAddress -and $_.PhysicalAdapter}| Sort-Object -Property MacAddress
        if($netadapters)
        {
            $info_netadapters = @()
            
            foreach($netadapter in $netadapters)
            {
                $ipconfiguration = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName | Where-Object { $_.Index -eq $netAdapter.deviceId}
                $DNSServers = ""
                #$allproperties = $netAdapter | Get-NetAdapterAdvancedProperty
                #$sendbuffers = ($allproperties | Where-Object {$_.DisplayName -eq "Transmit Buffers"}).DisplayValue
                #$recbuffers = ($allproperties | Where-Object {$_.DisplayName -eq "Receive Buffers"}).DisplayValue
                #$rss = ($allproperties | Where-Object {$_.DisplayName -eq "Receive Side Scaling"}).DisplayValue
                #$vmq = ($allproperties | Where-Object {$_.DisplayName -eq "Virtual Machine Queues"}).DisplayValue           
                foreach($dnsserver in $local:ipconfiguration.DNSServerSearchOrder)
                {
                    $DNSServers += $dnsserver + ";"
                }           
                $info_netadapter = @{}
                $IPv4Address  = ""
                $DefaultIPGateway = ""
                $IPSubnet = ""
                if($ipconfiguration.IPAddress)
                {
                    $IPv4Address  = $ipconfiguration.IPAddress[0]
                    $DefaultIPGateway = $ipconfiguration.DefaultIPGateway
                    $IPSbunet = $ipconfiguration.IPSubnet[0]
                }  
                $info_netadapter = @{
                    "Name" = $netadapter.Name
                    "NetEnabled" = $netadapter.NetEnabled
                    "LinkSpeed" = $netadapter.Speed
                    "InterfaceDescription" = $netadapter.Description
                    "ifIndex" = $netadapter.Index
                    "MacAddress" = $netadapter.MacAddress
                    "IPv4Address" = $IPv4Address                    
                    "IPv4DefaultGateway" = $DefaultIPGateway
                    "DNSServer" = $DNSServers.TrimEnd(";")
                    "IPSubnet" = $IPSubnet
                    #"TransmitBuffers" = $sendbuffers
                    #"ReceiveBuffers" = $recbuffers
                    #"ReceiveSideScaling" = $rss
                    #"VirtualMachineQueues" = $vmq
                }
                $info_netadapters += $info_netadapter
            }
        }
        $bios = @{
            "Manufacturer" = $wmi_computersystem.Manufacturer
            "Model" = $wmi_computersystem.Model
            "SerialNumber" = $wmi_bios.SerialNumber
            "SMBIOSBIOSVersion" = $wmi_bios.SMBIOSBIOSVersion
        }

        $info = @{
            "Hostname" = $wmi_computersystem.Name
            "Status" = "Up"
            "BIOS" = $bios            
            "OS" = $os
            "NetAdapters" = $info_netadapters
            "InstalledSoftwares" = Get-InstalledSoftware -Computer $ComputerName -SoftwareName "Microsoft,Mediaroom,Symantec,Cylance"
        }
        if($wmi_bios.Manufacturer -eq "Microsoft")
        {
            $physicalhost = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").PhysicalHostName
            $info.Add("VHost",$physicalhost)
        }
        $Server = New-Object -TypeName PSObject -Property $info
        return $Server
    }
}
function Export-Xml{
    param(
        # Parameter help description
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject]
        $InputObject,
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [int16]
        $Deepth,
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [string]
        $OutputFile
    )    
    if(!$OutputFile)
        {
            $OutputFile = "output.xml"
        }
    if(Test-Path $OutputFile)
    {
        $xmldoc = [xml](Get-Content $OutputFile)
    }
    else{
        $xmldoc = New-Object System.Xml.XmlDocument
        $xmlroot = $xmldoc.CreateElement("Servers")
        $xmldoc.AppendChild($xmlroot)
        $xmldoc.Save($OutputFile)
    }
    if($InputObject)
    {
        $strHostname = $InputObject.Hostname
        $xmlEleServer = $xmldoc.SelectSingleNode("//Servers/Server[Hostname='$strHostname']")
        # Create new Server //Servers/Server
        if(!$xmlEleServer)
        {
            $xmlEleServer = $xmldoc.CreateElement("Server")
            $xmlEleServer.SetAttribute("Name",$strHostname)
            $xmlEleServer.SetAttribute("SN",$InputObject.BIOS.SerialNumber)
            $xmlEleServer.SetAttribute("Status",$InputObject.Status)
            foreach($property in $InputObject.PSObject.Properties)
            {
                if($property.TypeNameOfValue -eq "System.Collections.Hashtable")
                {
                    $xmlComponent = $xmldoc.CreateElement($property.Name)
                    foreach($subProperty in $property.Value.GetEnumerator())
                    {
                        $xmlSub = $xmldoc.CreateElement($subProperty.Name)
                        $xmlSub.InnerText = $subProperty.Value
                        $xmlComponent.AppendChild($xmlSub)
                    }
                    $xmlEleServer.AppendChild($xmlComponent)
                }
                if($property.TypeNameOfValue -eq "System.Object[]")
                {
                    $xmlComponent = $xmldoc.CreateElement($property.Name) 
                    foreach($item in $property.Value)
                    {
                        $xmlComponentItem = $xmldoc.CreateElement($property.Name.TrimEnd('s'))
                        foreach($itemProperty in $item.Keys)
                        {
                            $xmlItemProperty = $xmldoc.CreateElement($itemProperty)
                            $xmlItemProperty.InnerText = $item[$itemProperty]
                            $xmlComponentItem.AppendChild($xmlItemProperty)
                        }
                        $xmlComponent.AppendChild($xmlComponentItem)
                    }
                    $xmlEleServer.AppendChild($xmlComponent)
                    
                }
                #if($property.TypeNameOfValue -eq "System.String")
                #{
                #    $xmlSub = $xmldoc.CreateElement($property.Name)
                #    $xmlSub.InnerText = $property.Value
                #    $xmlEleServer.AppendChild($xmlSub)
                #}
            }
            ($xmldoc.SelectSingleNode("//Servers")).AppendChild($xmlEleServer)
            $xmldoc.Save($OutputFile)
        }
    }    
    if(!$InputObject)
    {        
        $xmlwriter = New-Object System.Xml.XmlTextWriter($OutputFile,$null)
        $xmlwriter.Formatting = "Indented"
        $xmlwriter.Indentation = 2
        $xmlwriter.IndentChar = ' '
        $xmlwriter.WriteStartDocument()
        #$xmlwriter.WriteProcessingInstruction("xml-stylesheet","type='text/xsl' herf='style.xsl'")            
        #Write root element
        try{
            $xmlwriter.WriteStartElement("Servers")
            $xmlwriter.WriteStartElement("Server")
            foreach($property in $InputObject.PSObject.Properties)
            {
                if($property.TypeNameOfValue -eq "System.Collections.Hashtable")
                {
                    $xmlwriter.WriteStartElement($property.Name)
                    foreach($subProperty in $property.Value.GetEnumerator())
                    {
                        $xmlwriter.WriteElementString($subProperty.Name,$subProperty.Value)
                    }
                    $xmlwriter.WriteEndElement()
                }
                if($property.TypeNameOfValue -eq "System.Object[]"){
                    $xmlwriter.WriteStartElement($property.Name)
                    foreach($item in $property.Value)
                    {
                        $xmlwriter.WriteStartElement($property.Name.TrimEnd('s'))
                        foreach($subitem in $item.Keys)
                        {
                            if(!$subitem.Value.Keys)
                            {
                                $xmlwriter.WriteElementString($subitem,$item[$subitem])
                            }
                            else {
                                $xmlwriter.WriteStartElement($subitem.Name)
                                foreach($childItem in $subitem.Keys)
                                {
                                    $xmlwriter.WriteElementString($childItem,$subitem[$childItem])
                                }
                                $xmlwriter.WriteEndElement()
                            }
                        }                        
                        $xmlwriter.WriteEndElement()
                    }
                    $xmlwriter.WriteEndElement()
                }
                if($property.TypeNameOfValue -eq "System.String")
                {                    
                    $xmlwriter.WriteElementString($property.Name,$property.Value)
                }
            }
        }
        finally{
            $xmlwriter.WriteEndElement()
        $xmlwriter.WriteEndElement()
    $xmlwriter.WriteEndDocument()
    $xmlwriter.Flush()
    $xmlwriter.Close()
        }
    }
}
function Write-Xml{
#set the formatting
$xmlsetting = New-Object System.Xml.XmlWriterSettings
$xmlsetting.Indent = $true
$xmlsetting.IndentChars = ' '
$xmlwriter = [System.Xml.XmlWriter]::Create("example.xml",$xmlsetting)

$xmlwriter.WriteStartDocument()
$xmlwriter.WriteProcessingInstruction("xml-stylesheet","type='text/sxl' herf='style.xsl'")
$xmlwriter.WriteStartElement("ROOT")
    $xmlwriter.WriteStartElement("Object")
    $xmlwriter.WriteAttributeString("Current",$true)
    $xmlwriter.WriteAttributeString("Owner",$HOME)  
        $xmlwriter.WriteElementString("Property1","Value 1")        
        $xmlwriter.WriteElementString("Property2","Value 2")
            $xmlwriter.WriteStartElement("SubObject")
                $xmlwriter.WriteElementString("Property3", "Value 3")
            $xmlwriter.WriteEndElement()        
        $xmlwriter.WriteEndElement()
$xmlwriter.WriteEndElement()
$xmlwriter.WriteEndDocument()
$xmlwriter.Flush()
$xmlwriter.Close()
}
function Get-ServerList{
    param(
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [string]
        $ServerLayout
    )
    if(!$ServerLayout)
    {
        $ServerLayout = ".\EN03B\EN03B_serverLayout.xml"
    }
    $xml = [xml](Get-Content $ServerLayout)
    #branch 
    $branch = $xml.configuration.components.serverLayout.branch
    [hashtable]$objProperty = @{}
    $objProperty.Add("Branch",$branch.Name)
    $objProperty.Add("Domain",$branch.Domain)

    function ConvertTo-Object(){
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Part
    )
        $parts = $null
        switch ($Part) {
            {$Part -eq "groups"} { $parts = $branch.groupdefinitions.group }
            {$Part -eq "nlbs"} { $parts = $branch.zones.zone.nlbs.nlb }
            {$Part -eq "computers"} { $parts = $branch.zones.zone.computers.computer }
            Default {}
        }
        [hashtable]$tempHash = @{}
        $resultArray = @()
        foreach($p in $parts)
        {
            $tempHash.Clear()
            $tempHash.Add($p.name,$p.connectionString)
            $resultArray += $tempHash.Clone()            
        }
        return $resultArray
    }
    $objProperty.Add("groups",(ConvertXmlTo-Object -Part "groups"))
    $objProperty.Add("nlbs",(ConvertXmlTo-Object -Part "nlbs"))
    $objProperty.Add("computers",(ConvertXmlTo-Object -Part "computers"))
    
    # create branch psobject
    $objBranch = New-Object -TypeName psobject -Property $objProperty
    $objBranch
}

function Convert-ComputerInfoToCsv{
    param(        
        [Parameter(Mandatory = $false)]
        [string]
        $Manifest
    )
    if(!$Manifest)
    {
        $Manifest = ".\output.xml"
    }
    [xml]$xml = Get-Content $Manifest
    $xml.Servers.Server | Select-Object Name,SN,Status,VHost,@{Name = "Model";Expression={$_.BIOS.Model}},`
        @{Name="Manufacturer";Expression={$_.BIOS.Manufacturer}},`
        @{Name="OSCaption";Expression={$_.OS.OSCaption}},`
        @{Name="BuildNumber";Expression={$_.OS.BuildNumber}},`
        @{Name="OSArchitecture";Expression={$_.OS.OSArchitecture}},`
        @{Name="OSInstallDate";Expression={$_.OS.OSInstallDate}},`
        @{Name="UpTime";Expression={$_.OS.UpTime}},`
        @{Name="NIC0_Mac";Expression={$_.NetAdapters.NetAdapter[0].MacAddress}},`
        @{Name="NIC0_IP";Expression={$_.NetAdapters.NetAdapter[0].IPV4Address}},`
        @{Name="NIC0_GW";Expression={$_.NetAdapters.NetAdapter[0].IPV4DefaultGateway}},`
        @{Name="NIC0_IPSubnet";Expression={$_.NetAdapters.NetAdapter[0].IPSubnet}},`
        @{Name="NIC0_DNSServer";Expression={$_.NetAdapters.NetAdapter[0].DNSServer}},`
        @{Name="NIC0_Desc";Expression={$_.NetAdapters.NetAdapter[0].InterfaceDescription}},`
        @{Name="NIC1_Mac";Expression={$_.NetAdapters.NetAdapter[1].MacAddress}},`
        @{Name="NIC1_IP";Expression={$_.NetAdapters.NetAdapter[1].IPV4Address}},`
        @{Name="NIC1_GW";Expression={$_.NetAdapters.NetAdapter[1].IPV4DefaultGateway}},`
        @{Name="NIC1_IPSubnet";Expression={$_.NetAdapters.NetAdapter[1].IPSubnet}},`
        @{Name="NIC1_DNSServer";Expression={$_.NetAdapters.NetAdapter[1].DNSServer}},`
        @{Name="NIC1_Desc";Expression={$_.NetAdapters.NetAdapter[1].InterfaceDescription}} | export-csv ".\output.csv"
}
function Publish-DeviceOnIpam
{
<#

.DESCRIPTION
System.hashtable.
Pubilsh a device on IPAM site.
the Input object should be a hashtable object to reprents Device.
then sned it to ./IPAM/IPAM.Helper.ps1; New-DeviceOnIpam

.PARAMETER Devicename
System.String. 
if specified Devicename, will query device's informaton from ProvisionFile. like OOB IP, position in rack 

.PARAMETER ProvisionFile
System.String.
a path to provision file

#>
    param(
        # Parameter Devicename
        [Parameter(Mandatory = $false)]
        [string]
        $Devicename,
        # Parameter ProvisionFile
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_})]
        [string]
        $ProvisionFile
    )
    if(!$ProvisionFile)
    {
        $ProvisionFile = $provisonFile
    }
    #for remote device
    if($Devicename)
    {
        $Hostname = $Devicename
        $Model = (Get-WmiObject Win32_ComputerSystem -ComputerName $Hostname).Model
    }    
    [xml]$xmlDevices = Get-Content $ProvisonFile
    $device = $xmlDevices.Devices.Rack.Device | ? {$_.name -eq $Hostname}
    if($device)
    {
        $rackId = $device.ParentNode.ID
        $rack_size = 1
        switch($Model)
        {
            {$Model -contains "380" }{$rack_size = 2}
        }
        #$rack = Get-RackOnIpam -Rack $server.rack
        $objDevice = @{
            "hostname" = "$Hostname"
            "ip_addr" = "$($Device.ip_addr)"
            "sections" = "3"
            "rack" = "$rackId"
            "rack_start" = "$($device.rack_start)"
            "rack_size" = "$rack_size"
            "location" = "1"
        }
        Update-DeviceOnIpam -Device $objDevice
        Publish-IPAddressOnIpam -ComputerName $Hostname
    }
    else {
        Write-Error "$Devicename doesn't exist!"
    }
    
}
function Publish-IPAddressOnIpam
{
<#

.DESCRIPTION
Update IPAddress information on IPAM site.

.PARAMETER ComputerName
System.String
If given ComputerName, the query NIC infomation from remote computer.

#>
    param(
        # Parameter ComputerName
        [Parameter(Mandatory = $false)]
        [string]
        $ComputerName
    )
    if($ComputerName)
    {
        $CimSession = $ComputerName
    }
    else {
        $CimSession = localhost
    }

    $nics = Get-NetAdapter -Physical -CimSession $CimSession | Where-Object {$_.Status -eq "Up"}
    if($nics)
    {
        foreach($nic in $nics)
        {
            $ipconfiguration = $nic | Get-NetIPConfiguration -ErrorAction Ignore
            $ipaddr = $ipconfiguration.IPv4Address.IPAddress
            $PrefixLength = $ipconfiguration.IPv4Address.PrefixLength
            $desc = "{0} | {1}" -f $nic.InterfaceAlias,$nic.InterfaceDescription 
            #$ipaddr = "10.164.78.93"
            $IP = Get-IPAddressOnIpam -IPAddress $ipaddr
            $device = Get-DeviceOnIpam -Devicename $Hostname
            $port = Search-SwitchPort -MacAddress $nic.MacAddress
            # IPAddress already provisioned on IPAM site, Update detailed informationIP
            if($IP)
            {
                $IP = @{                    
                    'id' = $IP.id
                    'ip' = $ipaddr
                    'hostname' = $Hostname
                    'description' = $desc
                    'port' = "$port"
                    #'note' = ""
                    'tag' = "Used"
                    'mac' = $nic.MacAddress
                    'deviceId' = $device.id
                    #'owner' = ""
                    #'subnetId' = $ip.SubnetId
                }                
                Update-IpAddressOnIpam -IP $IP
            }
            #IPAddress doesn't exist on IPAM site, need create first.
            #In order to create IPAddress on IPAM site, subnetId needed.
            #Subnet_netid likes 10.164.78.0 without netmask            
            else
            {
                $networkID = Get-NetworkIDIPv4 -IPAddress $ipaddr -PrefixLength $PrefixLength
                $subnetImap = Get-SubnetOnIpam -SubnetInCIDR "$networkID/$PrefixLength"                
                $IP = @{                    
                    #'id' = $ip.id
                    'ip' = $ipaddr
                    'hostname' = $Hostname
                    'description' = $desc
                    'port' = "$port"
                    'note' = ""
                    'tag' = 2
                    'mac' = $nic.MacAddress
                    'deviceId' = $device.id
                    'owner' = ""
                    'subnetId' = [byte]$subnetImap.id
                }
                Update-IpAddressOnIpam -IP $IP -Action "Create"
            }            
        }        
    }    
}
function Search-SwitchPort{
<#

.DESCRIPTION
Search out TOR switch port by given MAC Address
dump mac address-table on switch side
then parse output by Excel
only keep three columes by order: vlantag, mac, port
then save it with comma delimited csv file
expected format like this
vlantag,mac,port
101,2c59.e547.2e0c,Eth101/1/1

.PARAMETER MacAddress
System.String

.OUTPUTS
System.String.
return switch port

#>
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $MacAddress
    )
    $macdelimiter = $MacAddress.Substring(2,1)
    $MacAddress = $MacAddress.Replace($macdelimiter,'').ToLower()
    [array]$entries = Import-Csv $Mactable -Delimiter ',' -Header 'vlantag','mac','port','switchname'    
    $entity = $entries | Where-Object {$_.mac.Replace('.','') -eq $MacAddress}
    if($entity)
    {
        if($entity.switchname)
        {
            return "{1}/{0}" -f $entity.port,$entity.switchname.Substring(10)
        }
        else {
            return $entity.port
        }
        
    }
    else {
        return "UnknownPort"
    }
        
}

function Convert-PlainTextToBase64
{
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $PlainText,
        [Parameter(Mandatory = $true)]
        [bool]
        $UnattendPassword
    )
    if($UnattendPassword)
    {
        $PlainText = "{0}{1}" -f $PlainText,"AdministratorPassword"
    }
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($PlainText)
    $base64 = [System.Convert]::ToBase64String($bytes)
    return $base64
    
    $p = "UABAAHMAcwB3AG8AcgBkADEAIQBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFAAYQBzAHMAdwBvAHIAZAA="

    $password = [System.Convert]::FromBase64String($p)
    $b = [System.Text.Encoding]::Unicode.GetString($password)
    $b=[System.Text.RegularExpressions.Regex]::Replace($b,"AdministratorPassword$","")
}

function Convert-Base64ToPlainText{
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Base64String,
        [Parameter(Mandatory = $true)]
        [bool]
        $UnattendPassword
    )
    $bytes = [System.Convert]::FromBase64String($Base64String)
    $plainstring = [System.Text.Encoding]::Unicode.GetString($bytes)
    if($UnattendPassword)
    {
        $plainstring = [System.Text.RegularExpressions.Regex]::Replace($plainstring,"AdministratorPassword$","")
    }
    return $plainstring
}

function New-UnattendFile
{
    param(
        [Parameter(Mandatory = $true)]
        [Object]
        $VMProfile,       
        [Parameter(Mandatory = $false)]
        [string]
        $MacAddress
    )
    if (Test-Path "$($Ops.Root)\unattend.xml")
    {
        Remove-Item "$($Ops.Root)\unattend.xml"
    }
    #
    # https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/
    #
    $ipaddr = "{0}/{1}" -f $VMProfile.Networking[0].IPAddress,$VMProfile.Networking[0].PrefixLength
    $localAdminPasswd = $VMProfile.LocalAdministratorPassword
    $unattendFile = New-Item "$($Ops.Root)\unattend.xml" -ItemType File
    $xmlUnattend = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <WindowsDeploymentServices>
                <Login>
                    <Credentials>
                        <Domain></Domain>
                        <Password></Password>
                        <Username></Username>
                    </Credentials>
                </Login>
            </WindowsDeploymentServices>
            <EnableFirewall>false</EnableFirewall>
            <EnableNetwork>true</EnableNetwork>
            <Restart>Restart</Restart>
        </component>
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <IEHardenAdmin>false</IEHardenAdmin>
            <IEHardenUser>false</IEHardenUser>
        </component>
        <component name="Microsoft-Windows-ServerManager-SvrMgrNc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DoNotOpenServerManagerAtLogon>true</DoNotOpenServerManagerAtLogon>
        </component>
        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Identification>
                <Credentials>
                    <Domain>%USERDOMAIN%</Domain>
                    <Password>%USERPASSWORD%</Password>
                    <Username>%USERNAME%</Username>
                </Credentials>
                <JoinDomain>%MACHINEDOMAIN%</JoinDomain>
                <JoinWorkgroup>%JoinWorkgroup%</JoinWorkgroup>
            </Identification>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <!--Value>UABAAHMAcwB3AG8AcgBkADEAIQBQAGEAcwBzAHcAbwByAGQA</Value-->
                    <Value>$localAdminPasswd</Value>
                    <PlainText>false</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>administrator</Username>
            </AutoLogon>
            <ComputerName>%ComputerName%</ComputerName>
        </component>       
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>UABAAHMAcwB3AG8AcgBkADEAIQBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFAAYQBzAHMAdwBvAHIAZAA=</Value>
                    <PlainText>false</PlainText>
                </AdministratorPassword>
            </UserAccounts>            
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <!--HideLocalAccountScreen>true</HideLocalAccountScreen-->
            </OOBE>
            <TimeZone>China Standard Time</TimeZone>
            <RegisteredOwner>SCLAB</RegisteredOwner>
            <RegisteredOrganization>SCLAB</RegisteredOrganization>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>cmd.exe /c powershell -command set-executionpolicy Unrestricted; . C:\SetIP.ps1</CommandLine>
                    <Order>1</Order>
                    <Description>Setup IP</Description>
                </SynchronousCommand>
            </FirstLogonCommands>
            <Display>
                <ColorDepth>32</ColorDepth>
                <HorizontalResolution>1024</HorizontalResolution>
                <VerticalResolution>768</VerticalResolution>
            </Display>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>0409:00000409</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
    </settings>
</unattend>
"@

    [xml]$xmlUnattend_specialize_IPAddress=@"
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <Interfaces>
            <Interface wcm:action="add">
	            <Identifier>$MacAddress</Identifier>
                <Ipv4Settings>
                    <DhcpEnabled>false</DhcpEnabled>
                </Ipv4Settings>
                <Ipv6Settings>
                    <DhcpEnabled>false</DhcpEnabled>
                </Ipv6Settings>
                <UnicastIpAddresses>
                    <IpAddress wcm:action="add" wcm:keyValue="1">$ipaddr</IpAddress>
                </UnicastIpAddresses>
                <Routes>
                    <Route wcm:action="add">
                        <Identifier>0</Identifier>
                        <Prefix>0.0.0.0/0</Prefix>
                        <NextHopAddress>$($VMProfile.Networking[0].Gateway)</NextHopAddress>
                    </Route>
                </Routes>
            </Interface>
        </Interfaces>
    </component>
  </settings>
</unattend>
"@

    $dnsservers = $VMProfile.Networking.DNSServer.Split(",")
    [XML]$xmlUnattend_specialize_DNS=@"
<unattend xmlns="urn:schemas-microsoft-com:unattend">
<settings pass="specialize">
    <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Interfaces>
            <Interface wcm:action="add">
                <Identifier>$MacAddress</Identifier>
                <DNSServerSearchOrder>
                    <!--IpAddress wcm:action="add" wcm:keyValue="1"></IpAddress-->
                </DNSServerSearchOrder>
                <EnableAdapterDomainNameRegistration>true</EnableAdapterDomainNameRegistration>
                <DisableDynamicUpdate>false</DisableDynamicUpdate>
            </Interface>
        </Interfaces>
    </component>
</settings>
</unattend>
"@
    [System.Xml.XmlNamespaceManager]$nsmgr = $xmlUnattend.NameTable
    $nsmgr.AddNamespace("urn","urn:schemas-microsoft-com:unattend")
    $nsmgr.AddNamespace('wcm', "http://schemas.microsoft.com/WMIConfig/2002/State")
    $xmldns = $xmlUnattend_specialize_DNS.CreateElement("IpAddress",$nsmgr.LookupNamespace("urn"))
    $i = 1
    $dnsservers | ForEach-Object {
        $dnsserver = $_
        $xmldns.SetAttribute("action",$nsmgr.LookupNamespace("wcm"),"add")
        $xmldns.SetAttribute("keyValue",$nsmgr.LookupNamespace("wcm"),$i)
        $xmldns.InnerText = "$dnsserver"
        $xmlUnattend_specialize_DNS.unattend.settings.component.Interfaces.Interface.DNSServerSearchOrder.AppendChild($xmldns.Clone())
        $i++
    }

    #Load variables from LabProfile

    $UnattendedJoin = $xmlUnattend.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"}

    if($VMProfile.WindowsAD) 
    {
        $UnattendedJoin.Identification.Credentials.Domain = $VMProfile.WindowsAD.DomainName
        $UnattendedJoin.Identification.Credentials.Password = $VMProfile.WindowsAD.DomainAdminPassword
        $UnattendedJoin.Identification.Credentials.Username = $VMProfile.WindowsAD.DomainAdmin
        $UnattendedJoin.Identification.JoinDomain = $VMProfile.WindowsAD.DomainName
        $UnattendedJoin.Identification.JoinWorkgroup = ""
    }
    else
    {
        $UnattendedJoin.Identification.JoinDomain = ""
        $UnattendedJoin.Identification.JoinWorkgroup = "WorkGroup"
    }
    # Specialize - Microsoft-Windows-Shell-Setup
    $UnattendSpecialize = $xmlUnattend.unattend.settings | Where-Object {$_.pass -eq "specialize"}
    $UnattendSpecializeShellSetup = $UnattendSpecialize.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"}
    $UnattendSpecializeShellSetup.ComputerName = $VMProfile.Name

    # oobeSystem - Microsoft-Windows-Shell-Setup
    switch($VMProfile.Role)
    {
        "DomainController" {$cmdline = "Powershell.exe C:\DCPromo.ps1"}
        "WindowsAdminCenter" {$cmdline = "Powershell.exe C:\WAC_Deploy.ps1"}
        "ScaleOutFileServer" {$cmdline = "PowerShell.exe C:\SOFS_Deploy.ps1"}
        "Hyper-V-Host" {$cmdline = "PowerShell.exe C:\Hyper-V-Host_Deploy.ps1"}
    }

    $Unattendoobe = $xmlUnattend.unattend.settings | Where-Object {$_.pass -eq "oobeSystem"}
    $UnattendoobeWindowsShellSetup = $Unattendoobe.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"}
    $UnattendoobeWindowsShellSetup.TimeZone = $VMProfile.TimeZone
    $UnattendoobeWindowsShellSetup.RegisteredOrganization = $VMProfile.WindowsAD.RegisteredOrganization
    $UnattendoobeWindowsShellSetup.RegisteredOwner = $VMProfile.WindowsAD.RegisteredOwner
    if($cmdline)
    {
        $UnattendoobeWindowsShellSetup.FirstLogonCommands.SynchronousCommand.CommandLine = $cmdline    
    }
    if($MacAddress)
    {
        ($xmlUnattend.unattend.settings | Where-Object {$_.pass -eq 'Specialize'}).AppendChild($xmlUnattend.ImportNode($xmlUnattend_specialize_IPAddress.unattend.settings.component,$true))
        ($xmlUnattend.unattend.settings | Where-Object {$_.pass -eq 'Specialize'}).AppendChild($xmlUnattend.ImportNode($xmlUnattend_specialize_DNS.unattend.settings.component,$true))     
    }
    $xmlUnattend.Save($unattendFile)
    Return $unattendFile
}

function New-FirstLogonScriptFile
{
    param(
        # Parameter help description
        [Parameter(Mandatory=$true)]
        [object]
        $VMProfile
    )
    #TODO:
    if ($VMProfile.Role -eq "DomainController")
    {
        $DCPromoScriptFile = "$($Ops.Root)\DCPromo.ps1"
        if (Test-Path $DCPromoScriptFile)
        {
            Remove-Item $DCPromoScriptFile
        }
        $DCPromo = @"
. C:\SetIP.ps1
Install-WindowsFeature -Name DHCP,AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $($VMProfile.WindowsAD.DomainName) -DomainNetBIOSName $($VMProfile.WindowsAD.DomainNetbiosName) -ForestMode Win2012 -DomainMode Win2012 -InstallDNS -SkipAutoConfigureDNS -SafeModeAdministratorPassword (ConvertTo-SecureString -string "P@ssword" -AsPlainText -Force) -Force -NoRebootOnCompletion
Add-DhcpServerInDC
#Add-DhcpServerv4Scope -Name "Lab Network" -StartRange "192.168.1.200" -EndRange "192.168.1.250" -SubnetMask "255.255.255.0"
#Add-DhcpServerv4Scope -Name "Cluster Network" -StartRange "10.10.10.200" -EndRange "10.10.10.250" -SubnetMask "255.255.255.0"
#Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -DnsServer $($VMProfile.Networking.IPAddress) -Router 192.168.1.1
#Set-DhcpServerv4OptionValue -ScopeId "10.10.10.0" -DnsServer $($VMProfile.Networking.Gateway) -Router 10.10.10.1
#Set-DhcpServerv4Binding -BindingState $true -InterfaceAlias $($VMProfile.Networking.Gateway)
Restart-Computer -Force
"@
        
        Set-Content -Path $DCPromoScriptFile -Value $DCPromo
        return $DCPromoScriptFile
    }
    if($Role -eq "WindowsAdminCenter")
    {
        $wacDeployScriptFile = "$($Ops.Root)\WAC_Deploy.ps1"
        if (Test-Path $wacDeployScriptFile)
        {
            Remove-Item $wacDeployScriptFile
        }
        $wacDeployScriptFileContent = @"
. C:\SetIP.ps1
Install-WindowsFeature -Name FileAndStorage-Services,File-Services,FS-FileServer,RSAT,RSAT-Role-Tools,RSAT-Hyper-V-Tools
`$wacUrl = "http://aka.ms/WACDownload"
`$wacMsi = "C:\WACInstaller.msi"
(New-Object System.Net.WebClient).DownloadFile(`$wacUrl,`$wacMsi)
msiexec /i `$wacMsi /qn /L*v C:\WACInstall.txt SME_PORT=443 SSL_CERTIFICATE_OPTION=generate
"@
        Set-Content -Path $wacDeployScriptFile -Value $wacDeployScriptFileContent
        return $wacDeployScriptFile
    }
    if($Role -eq "ScaleOutFileServer")
    {
        $SOFSDeployScriptFile = "$($Ops.Root)\SOFS_Deploy.ps1"
        if (Test-Path $SOFSDeployScriptFile)
        {
            Remove-Item $SOFSDeployScriptFile
        }
        $SOFSDeployScriptFileContent = @"
. C:\SetIP.ps1
Install-WindowsFeature -Name File-Services,Failover-Clustering -IncludeManagementTools
"@
        Set-Content -Path $SOFSDeployScriptFile -Value $SOFSDeployScriptFileContent
        return $SOFSDeployScriptFile
    }
    if($Role -eq "Hyper-V-Host")
    {
        $HyperVHostDeployScriptFile = "$($Ops.Root)\Hyper-V-Host_Deploy.ps1"
        if (Test-Path $HyperVHostDeployScriptFile)
        {
            Remove-Item $HyperVHostDeployScriptFile
        }
        $HyperVHostDeployScriptFileContent = @"
. C:\SetIP.ps1
Install-WindowsFeature -Name Hyper-V,File-Services,Failover-Clustering -IncludeManagementTools
"@
        Set-Content -Path $HyperVHostDeployScriptFile -Value $HyperVHostDeployScriptFileContent
        return $HyperVHostDeployScriptFile
    }
}

function New-SetIPScriptFile
{
    param(
        # Parameter help description        
        [Parameter(Mandatory = $true)]
        [object]
        $VMProfile
    )
    $SetIPScriptFile = "$($Ops.Root)\SetIP.ps1"
    if(Test-Path $SetIPScriptFile)
    {
        Remove-Item $SetIPScriptFile
    }
    if($VMProfile.OSVHDTemplate.Contains("2008SP2"))
    {
        $scripts = "[array]`$nics = Get-WMIObject Win32_NetworkAdapter -filter `"NetEnabled=True`"`n"
        $scripts += "`$nics = `$nics | Sort-Object -Property MacAddress`n"
    }
    else
    {
        $scripts = "`$nics = Get-NetAdapter | Sort-Object -Property MacAddress`n"
    }
    
    for($i=0;$i -lt $VMProfile.Networking.Count;$i++)
    {     
        switch($VMProfile.Networking[$i].PrefixLength)
        {
            "27" {$mask = "255.255.255.224"}
            "26" {$mask = "255.255.255.192"}
            "25" {$mask = "255.255.255.128"}
            "24" {$mask = "255.255.255.0"}
            "23" {$mask = "255.255.254.0"}
            "22" {$mask = "255.255.252.0"}
        }
        if($VMProfile.Networking[$i].Type -eq "Static")
        {
            if($VMProfile.OSVHDTemplate.Contains("2008SP2"))
            {
                $AddDNSServer = $true
                if($VMProfile.Networking[$i].DNSServer)
                {
                    $dnsservers = $VMProfile.Networking[$i].DNSServer.split(",")
                }
                else {
                    $AddDNSServer = $false
                }                
                $ipaddr = $VMProfile.Networking[$i].IPAddress
                $ipgw = $VMProfile.Networking[$i].Gateway                
                $nicnewname = $($VMProfile.Networking[$i].vSwitch)
                $scripts += "`$nicname = `$nics[$i].NetConnectionID`n"
                $scripts += "netsh interface ip delete dnsserver `$nicname all`n"
                if($AddDNSServer)
                {
                    $scripts += "netsh interface ip set dnsserver `$nicname static $($dnsservers[0]) primary`n"
                    $scripts += "netsh interface ip add dnsserver `$nicname $($dnsservers[1]) index=2`n"
                }                
                $scripts += "netsh interface set interface name=`$nicname newname=`"$nicnewname`"`n"
                $scripts += "netsh interface ip set address name=`"$nicnewname`" static addr=$ipaddr mask=$mask gateway=$ipgw gwmetric=$i`n"                               
            }
            else 
            {
                $scripts += "New-NetIPAddress -InterfaceIndex `$nics[$i].ifIndex -IPAddress $($VMProfile.Networking[$i].IPAddress) -DefaultGateway $($VMProfile.Networking[$i].Gateway) -PrefixLength $($VMProfile.Networking[$i].PrefixLength)`n"
                $scripts += "`$nics[$i] | Set-DnsClientServerAddress -ServerAddresses (`"$($VMProfile.Networking[0].DNSServer.Replace(',','","'))`")`n" 
            }            
        } 
        if(($VMProfile.Networking[$i].Type -eq "DHCP") -or (!$VMProfile.Networking[$i].IPAddress))
        {
            if($VMProfile.OSVHDTemplate.Contains("2008SP2"))
            {
                $scripts += "netsh interface ip set address name=`"$($VMProfile.Networking[$i].vSwitch)`" source=dhcp`n"
            }
            else 
            {
                $scripts += "`$nics[$i] | Set-NetIpInterface -Dhcp Enabled`n"
            }
            
        }
        if(!($VMProfile.OSVHDTemplate.Contains("2008SP2")))
        {

            $scripts += "`$nics[$i] | Rename-NetAdapter -NewName `"$($VMProfile.Networking[$i].vSwitch)`n`""
        }     
    }
    Set-Content -Path $SetIPScriptFile -Value $scripts
    return $SetIPScriptFile
}

function Get-LabProfile{
<#

.DESCRIPTION
Load Lab metadata from Lab.[LabName].json file

.OUTPUTS

#>
    param(        
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path "$invokepath\$_"})]
        [String]
        $LabProfileFile
    )    
    return Get-Content $LabProfileFile | ConvertFrom-Json
}
function Get-WindowsBuildNumber 
{
    WriteInfo "Getting Windows Build Number..."
    $os = Get-WmiObject -Class Win32_OperatingSystem
    return [int]($os.BuildNumber)
}

function Get-WindowsVersion {
<#
.DESCRIPTION
Get Windows version

6.0.6003 - Windows Server 2008 SP2
6.3.9600 - Windows Server 2012 R2
10.0.xxxxx - Windows Server 2019
 
#>    
    WriteInfo "Getting Windows Version"
    $os = Get-WmiObject -Class Win32_OperatingSystem
    return [string]($os.Version)    
}
function Start-PrerequestCheck{
<#
.DESCRIPTION
Check if prerequest software exist.

#>

#checking for compatible OS
    WriteInfoHighlighted "Checking if OS is Server 2016 or newer"
    $BuildNumber = Get-WindowsBuildNumber
    if($BuildNumber -ge 10586)
    {
        WriteSuccess "OS is Windows10 1511 / Server 2016 or newer"
    }
    else {
        WriteErrorAndExit "Windows Version $BuildNumber detected. Version 10586 and newer is needed. Exiting"
    }

    #checking folder structure
    "ParentDisks",`
    "Tools\DSC",`
    "Tools\ToolsVHD\DiskSpd",`
    "Tools\ToolsVHD\SCVMM\ADK",`
    "Tools\ToolsVHD\SCVMM\SQL", `
    "Tools\ToolsVHD\SCVMM\SCVMM\UpdateRollup",`
    "Tools\ToolsVHD\VMFleet" | ForEach-Object{
        if(!(Test-Path "$($Ops.Root)\$_")) {New-Item -type Directory -Path "$($Ops.Root)\$_"}}

    "Tools\ToolsVHD\SCVMM\ADK\Copy_ADK_with_adksetup.exe_here.txt", `
    "Tools\ToolsVHD\SCVMM\SQL\copy_SQL2016_with_setup.exe_here.txt", `
    "Tools\ToolsVHD\SCVMM\SCVMM\Copy_SCVMM_with_setup.exe_here.txt", `
    "Tools\ToolsVHD\SCVMM\SCVMM\UpdateRollup\Copy_SCVMM_Update_Rollup_MSPs_here.txt" | ForEach-Object{
        if(!(Test-Path "$($Ops.Root)\$_")) {New-Item -type File -Path "$($Ops.Root)\$_";WriteInfo $_.FullName.Length}} 
    
    #Download conver-windowsimage into Tools and ToolsVHD
    WriteInfoHighlighted "Testing convert-windowsimage presence in \Tools"
    if(Test-Path "$($Ops.Root)\Tools\convert-windowsimage.ps1")
    {
        WriteSuccess "`t convert-windowsimage.ps1 already exists in \Tools, skipping and download"    
    }
    else {
        WriteInfo "`t Downloading convert-windowsimage"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/live/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1`
            -OutFile "$($Ops.Root)\Tools\convert-windowsimage.ps1"
        }
        catch {
            WriteError "`t Failed to download convert-windowsimage.ps1"
            WriteInfo "Copy local file to instead..."
            Copy-Item -Path ".\convert-windowsimage.ps1" -Destination "$($Ops.Root)\Tools\convert-windowsimage.ps1"
        }
    }
    WriteInfoHighlighted "Testing convert-windowsimage presence in \Tools\ToolsVHD"
    if (!(Test-Path "$($Ops.Root)\Tools\ToolsVHD\convert-windowsimage.ps1"))
    {
        Copy-Item "$($Ops.Root)\Tools\convert-windowsimage.ps1" "$($Ops.Root)\Tools\ToolsVHD\convert-windowsimage.ps1"
        WriteSuccess "`t convert-windowsimage.ps1 copied into \Tools\ToolsVHD"
    }
    else {
        WriteSuccess "`t convert-windowsimage.ps1 already exists in \Tools\ToolsVHD"
    }

    # Check Hyper-V Feature on HOST
    WriteInfoHighlighted "Checking if Hyper-V is installed"
    if ((Get-WmiObject Win32_OperatingSystem).Caption -match "Server")
    {
        WriteInfo -message "This machine is running on Server based Windows edition" -indent 1
        if ((Get-WindowsFeature -Name "*Hyper-V*").InstallState -eq "Installed")
        {
            WriteSuccess "`tHyper-V and Management Tools is installed"
        }
        else {
            WriteError "`tHyper-V isn't installed, Installing Hyper-V ..."
            try {
                Install-WindowsFeature -Name Hyper-V,RSAT-Hyper-V-Tools,Hyper-V-Tools,Hyper-V-PowerShell
            }
            catch {
                WriteError "`tInstall Hyper-V failed"
            }        
        }
    }
    else {
        WriteInfo "`tThis machine is running on Clinet based Windows edition"
        if((Get-WindowsOptionalFeature -online -featurename Microsoft-Hyper-V).state -eq "Enabled")
        {
            WriteSuccess "`tHyper-V and Management Tools is insalled"
        }
        else
        {
            WriteError "`tHyper-V isn't installed, Installing Hyper-V ..."
            try
            {
                Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
            }
            catch
            {
                WriteError "`tInstall Hyper-V failed"
            }        
        }    
    }
    # List all physical NIC in UP status
    $nics = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
    $nics | Format-Table -AutoSize
    if($nics.count -gt 1)
    {
        $SharewithOS = $true
    }
    else{
        $SharewithOS = $false
    }
    #Check vSwitch on Host
    WriteInfoHighlighted "Getting Lab vSwitch ..."
    $extSwitch = Get-VMSwitch -SwitchType "External" -ErrorAction SilentlyContinue
    $intSwitch =  Get-VMSwitch -SwitchType "External" -ErrorAction SilentlyContinue   
    
    if($extSwitch)
    {
        WriteInfo "External Switch $($extSwitch.Name) already created!" -indent 1
    }
    else {
        $extSwitch = New-VMSwitch -Name "Lab" -NetAdapterName $nics[0].Name -AllowManagementOS $SharewithOS
        $extSwitch | Format-Table -AutoSize       
    }
    if($intSwitch)
    {
        WriteInfo "Internal Switch $($intSwitch.Name) already created!" -indent 1
    }
    else {
        $intSwitch = New-VMSwitch -Name "NLB" -NetAdapterName $nics[1].Name -AllowManagementOS $SharewithOS
        $intSwitch | Format-Table -AutoSize      
    } 
    $artifact.OSProfiles | ForEach-Object {
        New-VHDTemplate -Path "$($Ops.Root)\ParentDisks" -OSProfile $_
        }    
}
function ConvertTo-VHD{
<#
.DESCRIPTION
Convert Windows Installation Media(ISO) to virtual disk(VHDX)

.PARAMETER ISOFullName
ISO file full name.

.PARAMETER ImageIndex
image index in wim file.

.PARAMETER VHDPath
Path to save VHD

.PARAMETER VHDName
VHDName

.PARAMETER VHDSize
int64, VHDSize

#>
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $ISOFullName,
        [Parameter(Mandatory=$true)]
        [int]
        $ImageIndex,
        [Parameter(Mandatory=$true)]
        [string]
        $VHDPath,
        [Parameter(Mandatory=$true)]
        [string]
        $VHDName,
        [Parameter(Mandatory=$true)]
        [int64]
        $VHDSize,
        [Parameter(Mandatory=$true)]
        [string]
        $DiskLayout
    )
    if(Test-Path $ISOFullName)
    {
        WriteInfoHighlighted "Find ISO File $ISOFullName"
        WriteInfoHighlighted "Converting ISO Image to VHD Disks"
        $iso = Mount-DiskImage $ISOFullName -PassThru
        $isoDriverLetter = (Get-Volume -DiskImage $iso).DriveLetter
    }
    else {
        WriteError "The ISO File $ISOFullName doesn't exists, please dobule check"
    }
    WriteInfoHighlighted "Loading convert-WindowsImage.ps1 ..."
    . "$($Ops.Root)\tools\convert-windowsimage.ps1"
    
    if (!(Test-Path "$($isoDriverLetter):\sources\install.wim"))
    {
        WriteError "Install.wim no found in $($isoDriverLetter):\"
        WriteInfoHighlighted "Dismounting ISO file $ISOFullName"
        if($iso)
        {
            $iso | Dismount-DiskImage
        }
    }
    else {
        try {
            WriteInfo "Found install.wim file in $($isoDriverLetter):\"
            WriteInfo "Getting Image information from $($isoDriverLetter):\sources\install.wim"
            $images= Get-WindowsImage -ImagePath "$($isoDriverLetter):\sources\install.wim"
            foreach($image in $images)
            {
                WriteInfo ($image.ImageIndex.toString() + " - " + $image.ImageName)
            }            
            Convert-WindowsImage -SourcePath "$($isoDriverLetter):\sources\install.wim" -Edition $ImageIndex -VHDPath  "$VHDPath\$VHDName" `
            -SizeBytes $VHDSize -VHDFormat VHDX -Disklayout $DiskLayout            
        }
        catch {
            WriteError $_.Exception.Message
        }
        Finally{
            $iso | Dismount-DiskImage
        }        
    }
}
function New-VHDTemplate{
    param(        
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_})]
        [string]
        $Path,        
        [Parameter(Mandatory = $false)]
        [string]
        $VHDTemplate,        
        [Parameter(Mandatory = $false)]
        [string]
        $VHDSize,       
        [Parameter(Mandatory = $true)]
        [Object]
        $OSProfile
    ) 
    # 1 : Server 2019 Standard
    # 2 : Server 2019 Standard GUI
    # 3 : Server 2019 DataCenter
    # 4 : Server 2019 DataCenter GUI
    WriteInfo "Loading OSProfile - $($OSProfile.Profile)"
    WriteInfo "ISO - $($OSProfile.ISO)"
    #$iso = "{0}\{1}" -f $artifact.ISOStore,$OSProfile.ISO
    $iso = Get-FirstItem -Path $artifact.ISOStore -FileName $OSProfile.ISO
    WriteInfo "ISO Full Name - $iso"
    $enabledTemplates = $OSProfile.VHDTemplates | Where-Object {$_.Status -eq "enabled"}
    WriteInfo "VHDTemplates - $($OSProfile.VHDTemplates.Count)"    
    WriteInfo "Checking VHDTemplate in $Path"
    foreach($template in $enabledTemplates)
    {
        switch ($template.VHDTemplate) {
            "STD_Core_G2.vhdx" { $imageIndex = 1 }
            "STD_GUI_G2.vhdx" { $imageIndex = 2 }
            "DC_Core_G2.vhdx" { $imageIndex = 3 }
            "DC_GUI_G2.vhdx" { $imageIndex = 4 }
        Default { $imageIndex = 3}
        }
        $templatename = "{0}_{1}" -f $OSProfile.Profile,$template.VHDTemplate
        $templatefullname = "{0}\{1}" -f $Path,$templatename
        if(Test-Path $templatefullname)
        {
            Get-Item $templatefullname
            WriteInfo "Get pre-created VHDTemplate"            
        }
        else {
            WriteInfo "Creating VHDTemplate - $templatename"           
            $intVHDSize = [int64]$template.VHDSize.Replace('GB','')*1GB
            if($templatename -match "G2")
            {
                $DiskLayout = "UEFI"
            }
            else {
                $DiskLayout = "BIOS"
            }
            ConvertTo-VHD -ISOFullName $iso -ImageIndex $imageIndex -VHDPath $Path -VHDName $templatename -VHDSize $intVHDSize -Disklayout $Disklayout
        }        
    }
 }
 function Get-FirstItem {
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Path,
        [Parameter(Mandatory = $true)]
        [string]
        $FileName
    )
    $result = Get-ChildItem -Name $FileName -Path $Path -Recurse
    $resultfullname = "{0}\{1}" -f $Path,$result
    return $resultfullname
}
function Get-MachineProfile {
<#

.DESCRIPTION
Get Machine's HW,OS,SW Profiles from Artifacts and Lab files.

.PARAMETER Machine
Object

#>
    param (        
        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Object]
        $Machine,        
        [Parameter(Mandatory = $false)]
        [Object]
        $LabProfile
    )     
    $hw = $artifact.HardwareProfiles | Where-Object {$_.Profile -eq $Machine.HWProfile}
    $os_prof = $artifact.OSProfiles | Where-Object {$_.Profile -eq $Machine.OSProfile}
    $host_prof = $LabProfile.VirtualHosts | Where-Object {$_.Host -eq $Machine.Host}
    $tmpobj = $LabProfile.Components | Select-Object @{l="WindowsAD";e={$_.WindowsAD}}, @{l="Computers";e={$_.Computers}}
    $ad = ($tmpobj | ? {$_.Computers.Name -eq $($Machine.Name)}).WindowsAD    
    if(!$ad)
    {
        $ad = $LabProfile.WindowsAD    
    }   
    #$os_ver = $Machine.OSProfile.Split("_")[0]
    #$os_sku = $Machine.OSProfile.Split("_")[1]
    #$os_mode = $Machine.OSProfile.Split("_")[2]
    #$os_gen = $Machine.OSProfile.Split("_")[3]
    #$os_prof = ""
    #switch ($os_ver) {
    #    "WinSrv2019" { $os_prof = "WindowsServer2019" }
    #    "WinSrv2012R2" {$os_prof = "WindowsServer2012R2"}
    #    "WinSrv2008SP2" {$os_prof = "WindowsServer2008SP2"}
    #    Default {}
    #}
    $ram = [int64]$hw.MemoryStartupBytes.Replace('GB','')*1GB
    
    # Get VHDTemplat name
    #$vhd = "{0}_{1}_{2}_{3}.vhdx" -f $os_ver,$os_sku,$os_mode,$os_gen
    #if($Machine.OSProfile.Contains('\'))
    #{
    #    $vhd = $Machine.OSProfile
    #}
    
    $os = @{
        "OSVHDTemplate" = $Machine.OSVHDTemplate
        "OSVHDSize" = ($hw.Storage | Where-Object {$_.Label -eq "OS"}).Size
    }
    
    $storage = @()
    $disk = @{}
    $hw.Storage | ForEach-Object {                
                $disk.SizeinByte = [int64]$_.Size.Replace('GB','')*1GB
                if($_.Type){$disk.Type = $_.Type}
                else {$disk.Type = "New"}
                $disk.Label = $_.Label
                if($disk.Label -eq "OS")
                {
                    $disk.Template = $Machine.OSVHDTemplate
                    $disk.Name = "{0}_{1}" -f $Machine.Name,$disk.Template                
                } 
                else {
                   $disk.Template = "N/A"
                   $disk.Name = "{0}_data.vhdx" -f $Machine.Name                   
                }
                $disk.FullName =  "{1}\{2}\{3}" -f $Machine.Host,$host_prof.VMHome,$Machine.Name,$disk.Name         
                $storage += $disk.Clone()
                $disk.Clear() }

    $nic = @{}
    $networking = @()
    $Machine.Networking | ForEach-Object {
            $vSwitch = $_.vSwitch
            $vSwitchType = $_.vSwitchType
            if($vSwitch -eq "" -or !$vSwitch)
            {
                $vSwitch = ($host_prof.vSwitch | where-object {$_.Type -eq $vSwitchType}).Name
            }            
            $nic.vSwitch = $vSwitch
            $nic.Type = $_.Type
            $nic.IPAddress = $_.IPAddress
            $nic.PrefixLength = $_.PrefixLength
            $nic.Gateway = $_.Gateway
            if($_.DNSServer)
            {
                $nic.DNSServer = $_.DNSServer
            }
            elseif($ad.DNSServer){
                $nic.DNSServer = $ad.DNSServer
            }
            elseif($LabProfile.DNSServer){
                $nic.DNSServer = $LabProfile.DNSServer
            }
            $networking += $nic.Clone()
            $nic.Clear()}
    $vmGen = $HW.Generation
    if($Machine.OSProfile.Contains("2008SP2"))
    {
        $vmGen = 1
    }
    else {
        $vmGen = 2
    }
    if($Machine.TimeZone)
    {
        $timezone = $Machine.TimeZone
    }
    elseif($ad.TimeZone)
    {
        $timezone = $ad.TimeZone
    }
    elseif($LabProfile.TimeZone)
    {
        $timezone = $LabProfile.TimeZone
    }
    elseif(!$LabProfile.TimeZone)
    {
        $timezone = "China Standard Time"
    }
    #SQL
    $sql_prof = $artifact.SQLProfiles | Where-Object {$_.Profile -eq $machine.SQLProfile}
    $sql_prof | Add-Member -MemberType NoteProperty -Name "SQLSVCACCOUNT" -Value $ad.ServiceAccounts.SQLSVCACCOUNT
    $sql_prof | Add-Member -MemberType NoteProperty -Name "SQLSVCACCOUNTPASSWORD" -Value $ad.ServiceAccounts.SQLSVCACCOUNTPASSWORD
    $sql_prof | Add-Member -MemberType NoteProperty -Name "SQLAGTSVCACCOUNT" -Value $ad.ServiceAccounts.SQLAGTSVCACCOUNT
    $sql_prof | Add-Member -MemberType NoteProperty -Name "SQLAGTSVCACCOUNTPASSWORD" -Value $ad.ServiceAccounts.SQLAGTSVCACCOUNTPASSWORD

    $m = @{
        "Name" = $Machine.Name
        "Generation" = $vmGen
        "Role" = $Machine.Role
        "Host" = $Machine.Host
        "HostVMHome" = $host_prof.VMHome
        "HostCredential" = $host_prof.Credential
        "MemoryStartupBytes" = $ram
        "HW" = $hw
        "Networking" = $networking
        "Storage" = $Storage
        "OSProfile" = $os_prof
        "WindowsAD" = $ad
        "TimeZone" = $timezone
        "LocalAdministratorPassword" = $ad.LocalAdministratorPassword
        "SQLProfile" = $sql_prof
    } 
    $m += $os    
    return $m  
}
function New-VmVhd
{
    param(
        [Parameter(Mandatory = $true)]
        [object]
        $Disk,        
        [Parameter(Mandatory = $false)]
        [string]
        $ComputerName,        
        [Parameter(Mandatory = $false)]
        [guid]
        $VMID,        
        [Parameter(Mandatory = $false)]
        [Object]
        $OSProfile
    )
    $parent = "{0}\{1}" -f $Ops.VHDStore,$Disk.Template
    if(!(Test-Path $Ops.VHDStore))
    {
        New-Item -ItemType Directory -Name $Ops.VHDStore
    }
    if(!(Test-Path $parent))
    {
        New-VHDTemplate -Path "$($Ops.Root)\ParentDisks" -OSProfile $OSProfile
    }
    $IcalcArgs = @(
                "icacls.exe",
                "$($Disk.FullName)",
                "/inheritance:r",
                "/grant",
                "`"$VMID`":(F)",
                "/T",
                "/grant",
                "SYSTEM:(F)",
                "/T",
                "/grant",
                "Administrators:(F)",
                "/T"
                ) 
    try {
        if($ComputerName)
        {
            $pssession = New-PSSession -ComputerName $ComputerName        
        }    
        if(($Disk.Label -eq "OS") -and ($Disk.Type -eq "Different"))
        {
            if(Test-Path $Disk.FullName)
            {
                WriteInfo "$($Disk.FullName) exists, skip creating VHD..."
            }
            else
            {            
                if($pssession) 
                {                
                    Invoke-Command -Session $pssession -ScriptBlock {
                        New-VHD -ParentPath $Using:parent -Path $Using:Disk.FullName -SizeBytes $Using:Disk.SizeinByte -Differencing
                        & cmd.exe /c $Using:IcalcArgs
                    }                
                }           
            }     
        }
        if(($Disk.Label -eq "OS") -and ($Disk.Type -ne "Different")) 
        {       
            if($ComputerName)
            {            
                Invoke-Command -Session $pssession -ScriptBlock{
                    Copy-Item -Path $Using:parent -Destination $($Using:Disk.FullName)                
                    & cmd.exe /c $Using:IcalcArgs
                }
            }
            else {
                Copy-Item -Path $parent -Destination $($Disk.FullName)
            }        
        }
        if($Disk.Label -eq "Data")
        {
            if(Test-Path $Disk.FullName)
            {
                WriteInfo "$($Disk.FullName) exists, skip createing VHD..."
            }
            else {
                New-VHD -Path $Disk.FullName -BlockSizeBytes $Disk.SizeinByte                
            }
            Get-Item -Path $Disk.FullName
        }
    }
    catch{
        WriteError $_.Exception.Message
    }
    finally{
        Disconnect-PSSession $pssession
    }
}

function Copy-FileToVHD
{
<#
.DESCRIPTION
Inject files to VHD file

#>
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]
        $Files,
        [Parameter(Mandatory = $true)]
        [string]
        $VHDFile)
    try
    {
        WriteInfo "Copying files to $VHDFile, totally $($Files.Count) files"
        WriteInfo "Mounting VHD File $VHDFile to file system"
        $v = Mount-VHD -Path $VHDFile -Passthru -ErrorAction SilentlyContinue | Get-Disk | Get-Partition | Get-Volume | Where-Object {$_.FileSystemType -eq "NTFS"}
        $dst = "$($v.DriveLetter):\"
        WriteInfo "Copying $_ to $VHDFile"
        $Files | ForEach-Object {            
            Copy-Item $_ $dst
            WriteSuccess -Message "Copied $_" -Indent 2
        }
    }
    Catch
    {
        WriteError $_.Exception.Message
    }
    Finally
    {
        WriteInfo "Dismounting $VHDFile"
        Dismount-VHD $VHDFile -ErrorAction SilentlyContinue
        WriteInfo "Dismounted $VHDFile"
    }
} 

function New-LabVM
{
    param(
        # Parameter help description
        [Parameter(Mandatory=$true)]
        [Object]
        $VMProfile
    )
    
    $dtStart = Get-Date
    WriteInfo "The virtual machine deployment started at - $dtStart"
    # extract variable from $VM hashtable
    $vmName = $vmProfile.Name
    $vmRole = $vmProfile.Role
    $vmHost = $VMProfile.Host
    $vmHome = $VMProfile.HostVMHome
    $vmCpuCores = $VMProfile.HW.CpuCores
    $vmMemoryStartupBytes = $VMProfile.MemoryStartupBytes
    $TimeZone = $VMProfile.WindowsAD.TimeZone
    $logname = "{0}\{1}_Deployment.log" -f $($Ops.Root),$vmName
    Start-Transcript -Path $logname

    WriteInfo "Starting Deploy VM : $vmName"
    WriteInfo "Server role        : $vmRole"
    WriteInfo "CPU Cores are      : $vmCpuCores"
    WriteInfo "VM with RAM        : $vmMemoryStartupBytes"
    WriteInfo "VHDTemplate        : $($VMProfile.Storage[0].Template)"
    WriteInfo "VM Host            : $vmHost"
    WriteInfo "VM Home            : $vmHome"
    # code block for VM create    
    try
    {
        $vm = Get-VM -ComputerName $vmHost -Name $vmName -ErrorAction SilentlyContinue
        if(!$vm)
        {
            $user = $VMProfile.HostCredential.split(":")[0]
            $passwd = ConvertTo-SecureString -String $VMProfile.HostCredential.split(":")[-1] -AsPlainText -Force
            $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$passwd
            $vm = New-VM -ComputerName $vmHost -Name $vmName -MemoryStartupBytes $vmMemoryStartupBytes -SwitchName $($VMProfile.Networking[0].vSwitch) -Path $vmHome -Generation $VMProfile.Generation
            $vm | Set-VM -ProcessorCount $vmCpuCores -CheckpointType Disabled
            #Start VM to get MacAddress then shutdow.
            $vm | Start-VM 
            sleep 5 
            $vm | Stop-VM -Force
            $VMProfile.Storage | ForEach-Object {New-VmVhd -Disk $_ -ComputerName $vmHost -VMID $vm[0].Id -OSProfile $VMProfile.OSProfile}
            # Get MacAddress in format xxxxxxxxxxxx
            # https://docs.microsoft.com/en-us/dotnet/api/system.net.networkinformation.physicaladdress?view=netcore-3.1
            [System.Net.NetworkInformation.PhysicalAddress]$mac = $vm.NetworkAdapters[0].MacAddress
            # Convert MacAddress to xx-xx-xx-xx-xx-xx format
            # https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-tcpip-interfaces-interface-identifier
            $macBytes = $mac.GetAddressBytes()
            $macaddr = ""
            for($i=0;$i -lt $macBytes.Length;$i++)
            {
                $macbyte = $macBytes[$i].toString("X2")
                if($i -ne $macBytes.Length)
                {
                    $macaddr += $macbyte + "-"
                }
            }        
            # Create unattendfile, identify interface by MacAddress
            New-UnattendFile -VMProfile $VMProfile -MacAddress $macaddr.TrimEnd("-")
            New-FirstLogonScriptFile -VMProfile $VMProfile
            New-SetIPScriptFile -VMProfile $VMProfile
            $vmScriptFiles = Get-ChildItem -Path "$($Ops.Root)\*" -Include *.ps1,unattend.xml
            # Inject unattend and script files into vmOSVhd
            Copy-FileToVHD -Files $vmScriptFiles -VHDFile $($VMProfile.Storage[0].FullName)
            
            if($vmRole -eq "Hyper-V-Host")
            {
                $vm | Set-VMProcessor -ExposeVirtualizationExtensions $true
            }            
            $vm | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName $($VMProfile.Networking[0].vSwitch)

            # Add 2rd NIC as cluster network if required
            for($i=1;$i -lt $($VMProfile.Networking.Count);$i++)
            {
                WriteInfo "This VM $vmName has multiple NetAdapters"
                WriteInfo "Start create NetAdapter of $($VMProfile.Networking[$i].vSwitch)"
                $vm | Add-VMNetworkAdapter -Name $($VMProfile.Networking[$i].vSwitch) -SwitchName $($VMProfile.Networking[$i].vSwitch)                
            }            
            $VMProfile.Storage | ForEach-Object {
                WriteInfo "Attaching $($_.FullName) to Virtual Machine $vmName ..."
                $VM | Add-VMHardDiskDrive -Path $_.FullName -ErrorAction SilentlyContinue #-ControllerType SCSI
                WriteInfo "Attached $($_.FullName) to Virtual Machine $vmName ."} 
            #Change boot order
            $vm | Set-VMFirmware -BootOrder (Get-VMHardDiskDrive -VMName $vmName),(Get-VMNetworkAdapter -VMName $vmName)
            $vm | Start-VM  
        }
        else {
            WriteError "$vmName already exists, skip deployment."
        }
    }
    catch
    {
        WriteError "The deployment of Virtual Machine $vmName failed."
        Remove-VM -Name $vmName
        WriteErrorAndExit $_.Exception.Message
    }
    WriteInfo "Script Finished at $(Get-Date) and took $(((Get-date) - $dtStart).TotalSeconds) Seconds"
    Stop-Transcript    
}

function Build-Lab{
<#
.DESCRIPTION
Build Lab

.EXAMPLE
Build-Lab -LabProfileFile .\en03B\en03.json -Machine "FARM01-DB-02"

#>
    param(
        [Parameter(Mandatory = $true)]
        [Object]
        $LabProfileFile,
        [Parameter(Mandatory = $false)]
        [string]
        $Machine
    )
    # Build Domain Controllers
    #$dcs = $LabProfile.WindowsAD.Computers | Where-Object {$_.Role -eq "DomainController"}
    #foreach($dc in $dcs)
    #{
    #    if(!(Test-Connection $dc.Networking[0].IPAddress))
    #    {
    #        $dc_prof = Get-MachineProfile -Machine $dc
    #        $dc_vm = New-LabVM -VMProfile $dc_prof
    #    }        
    #} 
    # Build MDS Machines
    #$LabProfile = Get-LabProfile -LabProfileFile $LabProfileFile
    $lab = Get-LabProfile -LabProfileFile $LabProfileFile
    if($Machine)
    {
        WriteInfo "Looking for Machine $Machine in Lab Profile $LabProfile"
        if($lab.WindowsAD)
        {
            WriteInfo "Shared WindowsAD defiend in LAB Profile"
            $m = $lab.WindowsAD | % {$_.Computers} | Where-Object {$_.Name -eq $Machine}
        }
        else{
            WriteInfo "There isn't shared WindowsAD defined in LAB Profile, looking for it in Mediaroom Deployment..."
            $m = $lab.components | foreach {$_.Computers} | Where-Object {$_.Name -eq $Machine}  
        }
        if($m)
        {                
            WriteInfo "Loading Machine Profile of $Machine ......"
            $m_prof = Get-MachineProfile -Machine $m -LabProfile $lab
            WriteInfo "Start VM Deployment of $Machine"
            $m_vm = New-LabVM -VMProfile $m_prof
        }
        else {
            WriteError "Cannot find Machine $Machine in Lab Profile $LabProfile"
        }
    }
}

function Get-InstalledSoftware{
<#
.DESCRIPTION
Get Installed Software on Windows Computers.

.PARAMETER Computer
Get Installed software on this computer.

.PARAMETER SoftwareName
By SoftwareName to query installed software, mutliple name please split by comma

.OUTPUTS
Array

#>
    param(        
        [Parameter(Mandatory = $true)]
        [string]
        $Computer,        
        [Parameter(Mandatory = $false)]
        [string]
        $SoftwareName
    )    
    $softwares = @()
    foreach($software in $SoftwareName.split(","))
        {
            $obj = @()
            $filters = "'%{0}%'" -f $software
            $strQuery = "Select Name,Version,InstallSource,InstallLocation,LocalPackage,InstallDate,IdentifyingNumber from WIn32_Product where Name like $filters"
            $obj = Get-WmiObject -Query $strQuery -ComputerName $Computer
            $softwares += $obj
        }
    
    $arrayResult = @()    
    foreach($software in $softwares)
    {
        $obj = @{}
        $obj.Add("Name",$software.Name)
        $obj.Add("Version",$software.Version)
        $obj.Add("InstallSource",$software.InstallSource)
        $obj.Add("InstallLocation",$software.InstallLocation)
        $obj.Add("LocalPackage",$software.LocalPackage)
        $obj.Add("InstallDate",$software.InstallDate)
        $obj.Add("IdentifyingNumber",$software.IdentifyingNumber)
        $arrayResult += $obj
    }
    return $arrayResult
}

function Install-SQL
{
    param(        
        [Parameter(Mandatory = $true)]
        [hashtable]
        $SQLProfile
    )
    switch($SQLVersion)
	{
		"SQL2012SP1"{$SQLBits="$DataStore\DataStore\Products\Application\Server\SQL Server 2012 SP1\Enterprise\x64"}
		"SQL2012SP2"{$SQLBits="$DataStore\DataStore\Products\Application\Server\SQL Server 2012 SP2\Evaluation\x64"}
        "SQL2012SP2x86"{$SQLBits="$DataStore\DataStore\Products\Application\Server\SQL Server 2012 SP2\Evaluation\x86"}
        "SQL2014"{$SQLBits="$DataStore\DataStore\Products\Application\Server\SQL Server 2014"}
	}
	$OSVersion=Get-OSVersion
    if ($SQLVersion -eq "SQL2014"){$SQLPID="FKMGJ-WQ2H6-M462R-789GP-8FPQ6"}
    if (($SQLVersion -eq "SQL2012SP1") -or ($SQLVersion -eq "SQL2012SP2")){$SQLPID="W36BK-99V3B-KQRM4-GW4YX-JW4PW"}
	switch($OSVersion)
	{
		"6.3.9600" {$sxs="\\$DataStore\DataStore\Package\WindowsServer2012R2\sources\sxs"
					DISM /online /Enable-Feature /Featurename:NetFx3 /All /LimitAccess /Source:$sxs
					}
	}	
	$cmdargs=" /PID=$($SQLProfile.PID) /Q /Action=Install /IACCEPTSQLSERVERLICENSETERMS /UpdateEnabled=false /SQLSVCACCOUNT=$($SQLProfile.SQLSVCACCOUNT) /SQLSVCPASSWORD=$($SQLProfile.SQLSVCPASSWORD) /AGTSVCACCOUNT=$($SQLProfile.AGTSVCACCOUNT) /AGTSVCPASSWORD=$($SQLProfile.AGTSVCPASSWORD) /SQLSYSADMINACCOUNTS=$SQLSYSADMINACCOUNTS /ConfigurationFile=`"$SQLBits\ConfigurationFile.ini`""
		
	Write-Log " ... INSTALLING $SQLVersion ...  "
	$EXITCODE = ExecProcess "$SQLBits\SETUP.EXE" $cmdargs $LOGFILE
		 
    Switch ($EXITCODE)
	{
        0       { Write-Log $LOGFILE "  PASS:  SQL Installed"; Exit $EXITCODE }
        3010    { Write-Log "  PASS:  SQL Installed.  Needs reboot."; Exit $EXITCODE }
        default { Write-Log $LOGFILE "! FAIL:  SQL is not installed"; Exit $EXITCODE }
	}
}

###############################################################################
#  function ExecProcess([string]$cmdline, [string]$cmdargs)
#
#  in: [string]$cmdline - the path to the command to be executed
#  in: [string]$cmdargs - the arguments to be passed to the commandline
#  in: [string]$logFileName - logging content write to
#  out: [int]$process.ExitCode - the exit code from the external command
function ExecProcess([string]$cmdline, [string]$cmdargs,[string]$LogFile)
{
	$ret=-1;

	$logdata = "Entered ExecProcess`r`n"
	$logdata += "ExecProcess:: cmdline=" + $cmdline + "`r`n"
	$logdata += "ExecProcess:: cmdargs=" + $cmdargs + "`r`n"

	If (Test-Path $cmdline)
	{
		$psi = New-Object System.Diagnostics.ProcessStartInfo $cmdline, $cmdargs
		$psi.CreateNoWindow=1
		$psi.RedirectStandardOutput = 1
		$psi.UseShellExecute=0
		$process = New-Object System.Diagnostics.Process
		$process.StartInfo=$psi
		$process.Start() | Out-Null
		$process.WaitForExit()
		$out = $process.StandardOutput.ReadToEnd()
		$logdata += "ExecProcess:: " + $cmdline + " Exited with code " + $process.ExitCode + "`r`n"
		$logdata += "ExecProcess:: output:`r`n " + $out
		$ret = $process.ExitCode
		If ($Process.ExitCode -ne 0) {
			$Exception = [ComponentModel.Win32Exception]$Process.ExitCode
			$logdata += "ExecProcess::$($Exception.NativeErrorCode) = [$($Exception.Message)]"
		}

	}
	else
	{
		$logdata += "ExecProcess:: " + $cmdline + " was not found!!"
		$ret = -9009
	}

	if(![string]::IsNullOrEmpty($LogFile))
	{
		AppendToLogFile $LogFile $logdata
	}
	else{
		Write-Host $logdata
	}

	return $ret
}

function Get-MediaroomDBPatch{
    <#
    .DESCRIPTION
    Get Installed Software on Windows Computers.
    
    .PARAMETER Computer
    Get Installed software on this computer.
    
    .PARAMETER Database
    Get installed MR DB Patch in this Database.
    
    .OUTPUTS
    Array
    
    #>
        param(        
            [Parameter(Mandatory = $true)]
            [string]
            $Computer,        
            [Parameter(Mandatory = $true)]
            [string]
            $Database
        )
        $select = @"    
        SELECT [SchemaChangeLogId]
        ,[SchemaChangeDescription]
        ,[Status]     
        ,[SchemaFamilyId]
        ,[FamilyName]     
        ,[PackageName]
        ,[PackageDescription]
        ,[InstallDate]
        ,[InstalledBy]
        ,[InstallId]
    FROM [LiveBackend].[MSTVSchemaVersion].[view_SchemaChanges]
    Order By InstallDate
"@
    #Define connction string of database
	$connectionString = "Data Source=$Computer;Integrated Security=true;Initial Catalog=$Database;User ID=xxx\labagent;Password=xxx"
    # connection object initialization
	$conn = New-Object System.Data.SqlClient.SqlConnection($connectionString)
    #Open the Connection 
    try {
        $conn.Open()
        # Prepare the SQL 
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $select
        $reader = $cmd.ExecuteReader() 
        $rows = @()
        while($reader.Read())
        {
            $row = @{
                "SchemaChangeLogId" = $reader[0]
                "SchemaChangeDescription" = $reader[1]
                "Status" = $reader[2]
                "SchemaFamilyId" = $reader[3]
                "FamilyName" = $reader[4]
                "PackageName" = $reader[5]
                "PackageDescription" = $reader[6]
                "InstallDate" = $reader[7]
                "InstalledBy" = $reader[8]
                "InstallId" = $reader[9]
            }            
            $rows += $row
        }
        return $rows   
    }
    catch {
        WriteError $_.Exception.Message
    }
    finally{
        $conn.Close()
    }    
}
function  Uninstall-Software {
    param (
        
        [Parameter(AttributeValues)]
        [ParameterType]
        $ParameterName
    )
    #Symantec 14.0
    msiexec /uninstall {577FBFA6-33CB-4D9A-8286-0DF9236E5A59} /q /norestart
}