##This script will query the remote computer for the MAC addresses of all network adapters##

param(
    $PCname = (Read-host "Enter name of Computer to Query")
    )
Getmac /s $PCname /v