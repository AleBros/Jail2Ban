# Jail2Ban
Fail2ban version for windows in vb.net - inspired on wail2ban - json based -> jail :)

## What project does
Jail2Ban locks IP addresses using Windows Firewall

## How it works
- Search for failed login attempts into the windows event log
- Retrives the remote endpoint ip address from the log properties
- Creates multiple firewall rules if not existing grouping banned IPs using the first two block of IPv4 address
- Adds a locked IP address
- Shows into the console the "jail" status

## Improvements from base version
- Added a json configuration file 
- Added sql server ban
- Added simple feature for IIS W3Svc log inspection (now searches for php calls and 404 response)
- Added the OverallThreshold parameter for banning IP which reach a total amount of fails ever

## Future updates:
- Handle different operating systems
- Log every failed attempt (windows log does not retain a lot of data by default setting)
- Add a redemption time
- Create a webservice (maybe REST) to share between different server an IP reputation
- Add into the webservice project a web page showing IP reputation and logs
- Publish webservice for the community (source code of webservice will be shared in this repo)
