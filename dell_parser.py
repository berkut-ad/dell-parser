import argparse
import csv
import re
import ipaddress

from netmiko import ConnectHandler

def get_uplink_ip(connection):
    """
    Run 'show run interface Te 1/47' and extract the IP address.
    Also check if description contains 'UPL'.
    Returns the formatted output for CSV.
    """
    output = connection.send_command("show running-config interface Te 1/47")
    
    ip_line = None
    description_line = None

    for line in output.splitlines():
        if "ip address" in line:
            ip_line = line.strip().split()[-1]  # last word should be ip/subnet
        if "description" in line.lower():
            description_line = line.strip()

    if ip_line:
        if description_line and "UPL" in description_line.upper():
            return ip_line
        else:
            return f"{ip_line} (NO DESCRIPTION UPL)"
    else:
        return "NO IP FOUND"


def get_loopback_ip(connection):
    """
    Run 'show run interface loopback 0' and extract the IP address.
    Returns the formatted output for CSV.
    """
    output = connection.send_command("show running-config interface loopback 0")
    
    ip_line = None
    for line in output.splitlines():
        if "ip address" in line:
            ip_line = line.strip().split()[-1]  # last word should be ip/subnet
    
    if ip_line:
        return ip_line
    else:
        return "NO LOOPBACK IP FOUND"

def get_hostname(connection):
    """
    Run 'show running-config | grep hostname' and extract the hostname.
    """
    output = connection.send_command("show run | grep hostname")

    for line in output.splitlines():
        if line.strip().startswith("hostname"):
            parts = line.strip().split()
            if len(parts) > 1:
                return parts[1]
    return "NO HOSTNAME FOUND"

def get_snmp_location(connection):
    """
    Run 'sh run | grep "snmp-server location"' and extract the location.
    """
    output = connection.send_command("sh run | grep \"snmp-server location\"")

    for line in output.splitlines():
        if "snmp-server location" in line:
            parts = line.strip().split("snmp-server location", 1)
            if len(parts) > 1:
                return parts[1].strip()
    return "NO SNMP LOCATION FOUND"

def get_uplink_description(connection):
    """
    Run 'show running-config interface Te 1/47 | grep "^ description"' and extract the description.
    """
    output = connection.send_command('show running-config interface Te 1/47 | grep "^ description"')

    for line in output.splitlines():
        if line.strip().startswith("description"):
            return line.strip().replace("description", "", 1).strip()
    return "NO DESCRIPTION FOUND"

def get_logging_servers(connection):
    """
    Run 'show running-config | grep logging' and extract IP addresses.
    Returns a list of IPs; one per CSV row.
    """

    output = connection.send_command("show running-config | grep logging")
    ips = []

    # Regex to match IPv4 addresses
    ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    for line in output.splitlines():
        matches = re.findall(ip_regex, line)
        for ip in matches:
            ips.append(ip)

    if not ips:
        ips.append("NO LOGGING SERVER FOUND")
    
    return ips

def get_dhcp_servers(connection):
    """
    Run 'show running-config | grep helper-address' and extract IP addresses.
    Returns a deduplicated list of IPs; one per CSV row.
    """
    output = connection.send_command("show running-config | grep helper-address")
    ips = set()  # use a set to automatically deduplicate

    # Regex to match IPv4 addresses
    ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    for line in output.splitlines():
        matches = re.findall(ip_regex, line)
        for ip in matches:
            ips.add(ip)

    if not ips:
        return ["NO DHCP SERVER FOUND"]
    
    return list(ips)

def get_vlan_info(connection, vlan):
    """
    Parse 'show run int vlan X' and return a list of tuples:
    (Column 1, Column 2)
    """
    output = connection.send_command(f"show run interface vlan {vlan}")
    results = []

    ip_primary = None
    ip_secondary = None
    vrrp_ips = []

    # Track VRRP groups
    vrrp_groups = {}

    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        # Primary IP
        if line.startswith("ip address") and "secondary" not in line:
            ip_primary = line.split()[-1]
        # Secondary IP
        elif line.startswith("ip address") and "secondary" in line:
            parts = line.split()
            if len(parts) >= 3:
                ip_secondary = parts[2]  # second word is the IP/subnet
        # VRRP groups
        elif line.startswith("virtual-address"):
            vrrp_ips.append(line.split()[-1])

    # Determine which VRRP IP matches primary subnet
    vrrp_primary = None
    vrrp_secondary = None

    if ip_primary:
        net_primary = ipaddress.ip_network(ip_primary, strict=False)
        for vip in vrrp_ips:
            if ipaddress.ip_address(vip) in net_primary:
                vrrp_primary = vip
                break

    if ip_secondary:
        net_secondary = ipaddress.ip_network(ip_secondary, strict=False)
        for vip in vrrp_ips:
            if ipaddress.ip_address(vip) in net_secondary:
                vrrp_secondary = vip
                break

    results.append((f"Enter Vlan {vlan} Virtual IP", vrrp_primary or "NO VRRP IP FOUND"))
    results.append((f"Enter Vlan {vlan} IP address with Subnet", ip_primary or "NO IP FOUND"))
    results.append((f"Enter Vlan {vlan} IP address secondary with Subnet", ip_secondary or "NO SECONDARY IP FOUND"))
    results.append((f"Enter Vlan {vlan} Virtual IP address secondary", vrrp_secondary or "NO VRRP SECONDARY FOUND"))

    return results

def get_vlan_basic(connection, vlan):
    """
    Parse 'show run int vlan X' and return a list of tuples:
    (Column 1, Column 2)
    Only handles primary IP and VRRP virtual IP; no secondary IPs.
    """
    output = connection.send_command(f"show running-config interface vlan {vlan}")
    results = []

    ip_primary = None
    vrrp_primary = None
    vrrp_groups = {}

    for line in output.splitlines():
        line = line.strip()
        # Primary IP
        if line.startswith("ip address"):
            ip_primary = line.split()[2]  # second word after 'ip address' is the IP/subnet
        # VRRP groups
        elif line.startswith("vrrp-group"):
            group_number = line.split()[1]
            vrrp_groups[group_number] = None
        elif line.startswith("virtual-address"):
            vrrp_groups[list(vrrp_groups.keys())[-1]] = line.split()[-1]

    # VRRP primary: group number == vlan
    vrrp_primary = vrrp_groups.get(str(vlan), "NO VRRP IP FOUND")

    results.append((f"Enter Vlan {vlan} Virtual IP", vrrp_primary))
    results.append((f"Enter Vlan {vlan} IP address", ip_primary or "NO IP FOUND"))

    return results

def get_sonic_hosts(connection):
    """
    Returns a list of tuples for SONiC switches.
    Column 1: Enter SONiC SW01 .. SW29
    Column 2: parsed hostname from 'show lldp nei | grep Name:'
    """
    output = connection.send_command("show lldp nei det | grep Name:")
    remote_names = []

    # Regex to extract text after 'Remote System Name:'
    pattern = re.compile(r"Remote System Name:\s*(\S+)")

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            remote_names.append(match.group(1))

    # Prepare 29 rows, fill with empty string if LLDP output has fewer entries
    results = []
    for i in range(1, 30):  # SW01 to SW29
        col1 = f"Enter SONiC SW{i:02d}"
        col2 = remote_names[i-1] if i-1 < len(remote_names) else ""
        results.append((col1, col2))

    return results

def get_ospf_area(connection):
    """
    Parse 'show running-config | grep "^ area"' and return OSPF area number and type.
    Returns a list of tuples for CSV writing:
    (Column 1, Column 2)
    """
    output = connection.send_command('show running-config | grep "^ area"')
    area_number = ""
    area_type = ""

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("area"):
            parts = line.split()
            if len(parts) >= 2:
                area_number = parts[1]
                if len(parts) >= 3:
                    area_type = parts[2]
            break  # take first matching line only

    results = [
        ("Enter OSPF Area", area_number or "NO AREA FOUND"),
        ("Enter OSPF area type", area_type or "NO AREA TYPE FOUND")
    ]

    return results


def main():
    parser = argparse.ArgumentParser(description="Dell Switch Data Collector")
    parser.add_argument("host", help="Hostname or IP of switch")
    parser.add_argument("username", help="Username")
    parser.add_argument("password", help="Password")
    parser.add_argument("--enable", help="Enable password", default=None)
    parser.add_argument("--output", help="CSV output filename", default="output.csv")

    args = parser.parse_args()

    device = {
        "device_type": "dell_os10",  # adjust if using different Dell OS (ex: 'dell_force10')
        "ip": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.enable,
    }

    # Connect
    connection = ConnectHandler(**device)
    if args.enable:
        connection.enable()

    # List of commands (functions) to run
    commands = [
        ("Enter IP address uplink with subnet", get_uplink_ip),
        ("Enter Loopback IP address", get_loopback_ip),
        ("Enter Hostname", get_hostname),
        ("Enter SNMP Location", get_snmp_location),
        ("Enter uplink Description", get_uplink_description),
        ("Enter logging server", get_logging_servers),
        ("Enter DHCP server IP", get_dhcp_servers),
        ("VLAN 10 info", lambda conn: get_vlan_info(conn, 10)),
        ("VLAN 20 basic info", lambda conn: get_vlan_basic(conn, 20)),
        ("VLAN 30 info", lambda conn: get_vlan_info(conn, 30)),
        ("VLAN 40 info", lambda conn: get_vlan_info(conn, 40)),
        ("VLAN 500 info", lambda conn: get_vlan_info(conn, 500)),
        ("SONiC Switches", get_sonic_hosts),
        ("OSPF Area Info", get_ospf_area),
    ]

    # Run and write to CSV
    with open(args.output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
    
        for description, func in commands:
            result = func(connection)
            
            if isinstance(result, list):
                # Check if list contains tuples (VLAN info)
                if all(isinstance(r, tuple) and len(r) == 2 for r in result):
                    for col1, col2 in result:
                        writer.writerow([col1, col2])
                else:
                    # List of strings (logging servers, DHCP servers, etc.)
                    for item in result:
                        writer.writerow([description, item])
            else:
                # Single string result
                writer.writerow([description, result])

    connection.disconnect()


if __name__ == "__main__":
    main()
