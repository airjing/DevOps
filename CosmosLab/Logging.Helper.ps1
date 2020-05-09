function WriteInfo()
{
    param(        
        [Parameter(Mandatory = $false)]
        [String]
        $message,
        [byte]$indent = 0 
    )  
    $message = "`t"*$indent + $message
    Write-Host "INFO`t:"$message
}

function WriteInfoHighlighted($message)
{
    Write-Host "INFO`t:"$message -ForegroundColor Cyan
}

function WriteSuccess()
{
    param(        
        [Parameter(Mandatory = $false)]
        [String]
        $message,
        [byte]$indent = 0 
    )    
    $message = "`t"*$indent + $message
    write-host $message -ForegroundColor Green
}

function WriteError($message)
{
    write-host "Error`t:"$message -ForegroundColor Red
}

function WriteErrorAndExit($message)
{
    Write-Host $message -ForegroundColor Red
    Write-Host "Please enter to Continue ..."
    Stop-Transcript
    $exit = Read-Host
    Exit
}