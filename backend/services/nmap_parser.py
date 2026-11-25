import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(file_path):
    """
    Parse an Nmap XML scan and return observed network information.
    Missing information is stored as None, not guessed.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Nmap XML file not found: {file_path}"
        )

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as error:
        raise ValueError(f"Invalid Nmap XML: {error}")

    if root.tag != "nmaprun":
        raise ValueError("File is not a valid Nmap XML document.")

    scan_info = {
        "scanner": root.get("scanner"),
        "nmap_version": root.get("version"),
        "scan_arguments": root.get("args"),
        "start_time": root.get("startstr"),
        "hosts": [],
        "summary": {
            "total_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "observed_ports": 0,
            "aggregate_port_count": 0,
            "total_ports_accounted_for": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0
        }
    }

    for host in root.findall("host"):

        status_element = host.find("status")
        host_status = (
            status_element.get("state")
            if status_element is not None
            else None
        )

        addresses = {
            "ipv4": None,
            "ipv6": None,
            "mac": None,
            "mac_vendor": None
        }

        for address in host.findall("address"):
            address_type = address.get("addrtype")
            address_value = address.get("addr")

            if address_type == "ipv4":
                addresses["ipv4"] = address_value

            elif address_type == "ipv6":
                addresses["ipv6"] = address_value

            elif address_type == "mac":
                addresses["mac"] = address_value
                addresses["mac_vendor"] = address.get("vendor")

        hostnames = [
            item.get("name")
            for item in host.findall("./hostnames/hostname")
            if item.get("name")
        ]

        # OS detection is optional. Do not infer it from a service.
        os_matches = []

        for match in host.findall("./os/osmatch"):
            os_matches.append({
                "name": match.get("name"),
                "accuracy": match.get("accuracy")
            })

        ports = []
        extraports = []

        for port in host.findall("./ports/port"):

            state_element = port.find("state")
            service_element = port.find("service")

            state = (
                state_element.get("state")
                if state_element is not None
                else None
            )

            service = {
                "name": None,
                "product": None,
                "version": None,
                "extrainfo": None,
                "ostype": None,
                "method": None,
                "confidence": None,
                "cpe": []
            }

            if service_element is not None:
                service.update({
                    "name": service_element.get("name"),
                    "product": service_element.get("product"),
                    "version": service_element.get("version"),
                    "extrainfo": service_element.get("extrainfo"),
                    "ostype": service_element.get("ostype"),
                    "method": service_element.get("method"),
                    "confidence": service_element.get("conf")
                })

                service["cpe"] = [
                    cpe.text
                    for cpe in service_element.findall("cpe")
                    if cpe.text
                ]

            port_record = {
                "protocol": port.get("protocol"),
                "port": int(port.get("portid")),
                "state": state,
                "reason": (
                    state_element.get("reason")
                    if state_element is not None
                    else None
                ),
                "service": service
            }

            ports.append(port_record)

            scan_info["summary"]["observed_ports"] += 1

            if state == "open":
                scan_info["summary"]["open_ports"] += 1
            elif state == "closed":
                scan_info["summary"]["closed_ports"] += 1
            elif state == "filtered":
                scan_info["summary"]["filtered_ports"] += 1

        # Nmap sometimes reports port counts without individual port IDs.
        for item in host.findall("./ports/extraports"):
            state = item.get("state")
            count = int(item.get("count", 0))

            extraports.append({
                "state": state,
                "count": count
            })

            scan_info["summary"]["aggregate_port_count"] += count

            if state == "closed":
               scan_info["summary"]["closed_ports"] += count
            elif state == "filtered":
               scan_info["summary"]["filtered_ports"] += count

        host_record = {
            "status": host_status,
            "addresses": addresses,
            "hostnames": hostnames,
            "os_matches": os_matches,
            "ports": ports,
            "extraports": extraports
        }

        scan_info["hosts"].append(host_record)
        scan_info["summary"]["total_hosts"] += 1

        if host_status == "up":
            scan_info["summary"]["hosts_up"] += 1
        elif host_status == "down":
            scan_info["summary"]["hosts_down"] += 1

        scan_info["summary"]["total_ports_accounted_for"] = (
            scan_info["summary"]["observed_ports"]
            + scan_info["summary"]["aggregate_port_count"]
        )
    return scan_info