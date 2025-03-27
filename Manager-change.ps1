# Import Active Directory module
Import-Module ActiveDirectory

# Define the path to the CSV file
$csvPath = "C:\path\to\employees.csv"

# Specify the Distinguished Name (DN) of the new manager
$managerDN = "CN=John Smith,OU=Managers,DC=yourdomain,DC=com"

# Check if the file exists
if (-Not (Test-Path $csvPath)) {
    Write-Host "CSV file not found at $csvPath" -ForegroundColor Red
    exit
}

# Import CSV
$employees = Import-Csv -Path $csvPath

# Iterate through each employee in the CSV
foreach ($employee in $employees) {
    $userName = $employee.sAMAccountName

    # Fetch the user from Active Directory
    $adUser = Get-ADUser -Filter {sAMAccountName -eq $userName} -Properties Manager

    if ($adUser) {
        try {
            # Update the Manager attribute
            Set-ADUser -Identity $adUser.DistinguishedName -Manager $managerDN
            Write-Host "Updated manager for $userName to $managerDN" -ForegroundColor Green
        } catch {
            Write-Host "Failed to update manager for $userName. Error: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "User $userName not found in Active Directory." -ForegroundColor Yellow
    }
}

Write-Host "Bulk update process completed." -ForegroundColor Cyan
