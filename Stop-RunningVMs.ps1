Workflow Stop-RunningVMs
{
    [CmdletBinding()]
    param
    (
        # The name of the Resource Group
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ResourceGroupName
    )
    
    $connectionName = "AzureRunAsConnection"

    try
    {
        # Get the connection "AzureRunAsConnection "
        $servicePrincipalConnection = Get-AutomationConnection -Name $connectionName         

        "Logging in to Azure..."
        Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
    
    }
    catch
    {
        if (!$servicePrincipalConnection)
        {
            $ErrorMessage = "Connection $connectionName not found."
            throw $ErrorMessage
        }
        else
        {
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }

    $AzureVMs = Get-AzureRMVM -ResourceGroupName $ResourceGroupName | Select Name,Id
    foreach -Parallel ($AzureVM in $AzureVMs)
    {
        Stop-AzureRMVM -Name $AzureVM.Name -Id $AzureVM.Id -Force -ErrorAction SilentlyContinue
    }
}
