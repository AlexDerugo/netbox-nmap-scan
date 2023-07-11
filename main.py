import nmap
import pynetbox

# nebox connection
NETBOX_URL  = "http://netbox.url"
TOKEN       = "token"
nb          = pynetbox.api(url=NETBOX_URL, token=TOKEN)

# prefix tag, if assigned to a prefix, then scan
tag_prefix          = "tag_prefix_for_scan"
# tag that we assign to the found IP
tag_ip_addr         = "tag_assign_to_ip_addr"
# VM tag. if the tag is assigned to a VM we don't remove the IP even if it is no longer scanned
tag_VM_no_del_IP    = "tag_VM_no_del_IP"


# get list prefixes, who have tag tag_prefix
def prefixes_from_netbox():
    response_prefixes   = nb.ipam.prefixes.filter(tag = tag_prefix)
    prefixes_list       = []
    # change type to string
    for pref in response_prefixes:
        prefixes_list.append(str(pref))
    return prefixes_list

# scan prefixes who have tag tag_ip_addr. If ip is not in netbox then add. Return found scanned IPs will be added
def ip_from_nmap(var_prefixes_list):
    # an empty list to which the found scanned IPs will be added
    list_from_nmap = []
    # check tag in netbox. create tag if not present
    tag = nb.extras.tags.get(name = tag_ip_addr)
    if tag:
        tag_id  = tag.id
    else:
        tag     = nb.extras.tags.create({"name": tag_ip_addr, "slug": tag_ip_addr})
        tag_id  = tag.id

    # scan each prefix from the list
    for net in var_prefixes_list:
        # we define the mask, we will add it to the IP, because nmap returns ip with mask /32
        mask = net.split("/")[-1]
        # nmap process
        nm = nmap.PortScanner()
        # nmap parameters. network and arguments. use only -sn without port scan
        nm.scan(hosts=net, arguments='-sn')

        # each found IP in network
        for host in nm.all_hosts():
            # find active IP
            if nm[host].state() == "up":
                # change /32 to prefixes mask
                ip_up = host+"/"+mask
                # add scanned IP to global list
                list_from_nmap.append(ip_up)
                # if ip with tag tag_prefix is already in netbox, stop the loop and start from the beginning
                if nb.ipam.ip_addresses.filter(address=ip_up, tag = tag_ip_addr):
                    continue
                # if IP in netbox, but don`t have tag tag_prefix, then add tag
                elif nb.ipam.ip_addresses.filter(address=ip_up, tag__n = tag_ip_addr):
                    ipaddr = nb.ipam.ip_addresses.get(address=ip_up)
                    ipaddr.tags.append(tag_id)
                    ipaddr.save()
                # if IP isn`t in netbox, then add IP
                else:
                    ip = {"address":ip_up, "tags":[{"name":tag_ip_addr, "slug":tag_ip_addr}] }
                    nb.ipam.ip_addresses.create(ip)
    return list_from_nmap

# get from netbox a list of IP with tag tag_prefix
def ip_from_netbox():
    list_from_netbox = []
    response_ipaddr = nb.ipam.ip_addresses.filter(tag = tag_ip_addr)
    for pref in response_ipaddr:
        list_from_netbox.append(str(pref))
    return list_from_netbox

# delete the ip that is in the netbox, but which is not currently scanned. exception to remove the IP if the VM has a tag tag_VM_no_del_IP
def del_ip_from_netbox(list_no_scan):
    for ipaddr in list_no_scan:
        if nb.ipam.ip_addresses.filter(address=ipaddr, tag = tag_VM_no_del_IP):
            continue
        else:
            del_ip = nb.ipam.ip_addresses.get(address=ipaddr)
            del_ip.delete()

def main():
    var_prefixes_list = prefixes_from_netbox()
    # we start nmap and add new ip, then we get a list from netbox
    ip_from_nmap(var_prefixes_list)
    ip_from_netbox()
    # comparing two lists. We create a separate list with IPs that were previously available, but are not scanned now
    list_no_scan = list(set(ip_from_netbox()) - set(ip_from_nmap(var_prefixes_list)))
    del_ip_from_netbox(list_no_scan)

if __name__ == "__main__" :
    main()
