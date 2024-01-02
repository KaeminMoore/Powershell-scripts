$FilePath = Read-Host ("Enter File Path to Query")

Compress-Archive "$FilePath" -DestinationPath ("$FilePath" + (get-date -Format yyyyMMdd) + '.zip')