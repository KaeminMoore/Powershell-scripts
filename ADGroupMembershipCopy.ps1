param(
    $CopyFrom = (Read-Host "Enter UserName to Copy Memberships From"),
    $CopyTo = (Read-Host "Enter UserName to Copy Memberships To")
    )


$a = Get-ADUser $CopyFrom -prop MemberOf

$b = Get-ADUser $CopyTo -prop MemberOf

$a.MemberOf | Where{$b.MemberOf -notcontains $_} | Add-ADGroupMember -Members $b