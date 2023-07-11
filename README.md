# netbox-nmap-scan
- from the netbox we get a list of prefixes with a specific tag.  
- scan with nmap received prefixes. use only -sn without port scan.  
- add found ip with a specific tag.  
- delete the ip that is in the netbox, but is no longer scanned. exception to remove the IP if the VM has a specific tag.  
