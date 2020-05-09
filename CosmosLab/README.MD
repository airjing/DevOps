# Guide of ConmosLab

1. Copy CosmosLab folder to Hyper-V host machine which will resides VM you are going to deploy.

2. Modify line 1457 in Main.ps1 file, according to VM's component , change to Branch, Backend, MDS for different condition in Where-Object command let.

    ``$mds = ($LabProfile.Components | Where-Object {$_.Product -eq ``"Branch"``}).Computers``

3. run powershell.exe .\Main.ps1 to deploy all VMs.

4. If you are going to re-deploy existing VM, please delete them from Hyper-V console and E:\VMHome filder, then start step3.

