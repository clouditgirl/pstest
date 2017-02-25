#Stop the VM and Deallocate
Stop-AzureVM -ServiceName "rangervm001" -Name "rangervm001"

#Stop the VM and do not Deallocate
Stop-AzureVM -ServiceName "rangervm001" -Name "rangervm001" -StayProvisioned
 
#Stop the VM and Deallocate and no prompt if its the last VM
Stop-AzureVM -ServiceName "rangervm001" -Name "rangervm001" -Force 
