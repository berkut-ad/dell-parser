import argparse
import csv
import re

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
    ]

    # Run and write to CSV
    with open(args.output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        for description, func in commands:
            result = func(connection)
            # Check if the result is a list (multiple entries)
            if isinstance(result, list):
                for item in result:
                    writer.writerow([description, item])
            else:
                writer.writerow([description, result])

    connection.disconnect()


if __name__ == "__main__":
    main()
