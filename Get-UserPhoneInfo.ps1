$UserName = (Read-Host "Enter User Name to Query")

get-aduser $username -properties * | Select-object CN, extensionattribute3, st, uSDAOfficeID, telephonenumber, PhysicalDeliveryOfficeName 