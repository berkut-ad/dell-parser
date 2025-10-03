import argparse
import csv
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
    Run 'show running-config | include hostname' and extract the hostname.
    """
    output = connection.send_command("show running-config | include hostname")

    for line in output.splitlines():
        if line.strip().startswith("hostname"):
            parts = line.strip().split()
            if len(parts) > 1:
                return parts[1]
    return "NO HOSTNAME FOUND"

def get_snmp_location(connection):
    """
    Run 'show running-config | include snmp-server location' and extract the location.
    """
    output = connection.send_command("show running-config | include snmp-server location")

    for line in output.splitlines():
        if "snmp-server location" in line:
            parts = line.strip().split("snmp-server location", 1)
            if len(parts) > 1:
                return parts[1].strip()
    return "NO SNMP LOCATION FOUND"

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
    ]

    # Run and write to CSV
    with open(args.output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        for description, func in commands:
            result = func(connection)
            writer.writerow([description, result])

    connection.disconnect()


if __name__ == "__main__":
    main()
