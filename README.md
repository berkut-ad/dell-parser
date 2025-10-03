# Dell Switch Data Collector

This Python script connects to Dell switches via SSH and collects specific configuration details.  
The output is written to a CSV file with **two columns**:  

1. A static description (e.g., "Enter IP address uplink with subnet")  
2. The parsed result from a show command  

The script is modular: each command is implemented as its own function, making it easy to add more data collection routines.

---

## Features

- Connects to Dell switches over SSH using [Netmiko](https://github.com/ktbyers/netmiko).  
- Supports **username, password, and enable password** (if required).  
- Collects uplink IP and Loopback0 IP by default.  
- Outputs results into a CSV file.  
- Modular design for easily adding new commands.  

---

## Requirements

- Python 3.8+  
- `netmiko` library  

Install dependencies:

```
pip install netmiko

or 

pip install -r requirements.txt
```
## Usage

```
python dell_parser.py <host> <username> <password> [--enable ENABLE] [--output OUTPUT.csv]
```

- `host` → Hostname or IP address of the Dell switch

- `username` → SSH username

- `password` → SSH password

- `enable` → (Optional) Enable/privileged exec password

- `output` → (Optional) Output CSV filename (default: output.csv)
