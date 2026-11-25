
import re
from typing import Optional

from pydantic import ValidationError

from backend.models.network_asset import NetworkInventory
from backend.models.asset import Asset, Service


def _get_ip_address(host) -> Optional[str]:
    """
    Extract the primary IP address from an Nmap host.
    Prefer IPv4; use IPv6 if IPv4 is unavailable.
    """

    return (
        host.addresses.ipv4
        or host.addresses.ipv6
    )


def _get_hostname(host, ip_address: str) -> str:
    """
    Use the first discovered hostname.
    Fall back to the IP address if no hostname exists.
    """

    if host.hostnames:
        return host.hostnames[0]

    return ip_address


def _get_operating_system(host) -> Optional[str]:
    """
    Extract an OS name from Nmap OS matches,
    if one is available.
    """

    for os_match in host.os_matches:

        if isinstance(os_match, dict):
            os_name = os_match.get("name")

            if os_name:
                return str(os_name)

    return None


def _convert_services(host) -> list[Service]:
    """
    Convert Nmap ports and service information
    into Member 1's Service model.

    All discovered port states are preserved.
    """

    converted_services = []

    for port in host.ports:

        service = Service(
            service_name=port.service.name,
            product=port.service.product,
            vendor=None,
            version=port.service.version,
            port=port.port,
            protocol=port.protocol,
            state=port.state,
            cpe=port.service.cpe
        )

        converted_services.append(service)

    return converted_services


def _generate_asset_id(ip_address: str) -> str:
    """
    Generate a deterministic asset ID from its IP.
    """

    safe_ip = re.sub(
        r"[^A-Za-z0-9_-]",
        "-",
        ip_address
    )

    return f"asset-{safe_ip}"


def convert_network_inventory_to_assets(
    inventory: NetworkInventory,
    metadata_by_ip: Optional[dict] = None
) -> dict:
    """
    Convert Member 2's NetworkInventory into
    Member 1's Asset objects.

    Required business metadata is never invented.

    Assets with missing or invalid metadata are
    returned separately as pending assets.

    Hosts without an IP address are skipped.
    """

    if metadata_by_ip is None:
        metadata_by_ip = {}

    assets = []
    pending_assets = []
    skipped_hosts = []

    required_metadata = [
        "asset_type",
        "zone",
        "criticality"
    ]

    for host in inventory.hosts:

        # 1. Extract IP address
        ip_address = _get_ip_address(host)

        if not ip_address:
            skipped_hosts.append({
                "reason": "No IPv4 or IPv6 address found."
            })
            continue

        # 2. Extract hostname
        name = _get_hostname(
            host,
            ip_address
        )

        # 3. Convert services
        services = _convert_services(host)

        # 4. Extract available OS information
        operating_system = _get_operating_system(host)

        # 5. Retrieve verified business metadata
        metadata = metadata_by_ip.get(
            ip_address,
            {}
        )

        missing_metadata = [
            field
            for field in required_metadata
            if metadata.get(field) is None
        ]

        # 6. Keep incomplete assets pending
        if missing_metadata:

            pending_assets.append({
                "asset_id": _generate_asset_id(ip_address),
                "name": name,
                "ip_address": ip_address,
                "operating_system": operating_system,
                "services": [
                    service.model_dump()
                    for service in services
                ],
                "missing_metadata": missing_metadata
            })

            continue

        # 7. Construct Member 1's Asset
        try:

            asset = Asset(
                asset_id=_generate_asset_id(ip_address),
                name=name,
                ip_address=ip_address,
                asset_type=metadata["asset_type"],
                zone=metadata["zone"],
                criticality=metadata["criticality"],
                operating_system=operating_system,
                services=services
            )

            assets.append(asset)

        except ValidationError as error:

            pending_assets.append({
                "asset_id": _generate_asset_id(ip_address),
                "name": name,
                "ip_address": ip_address,
                "reason": "Invalid asset metadata.",
                "validation_errors": error.errors()
            })

    # 8. Return conversion results
    return {
        "total_hosts_received": len(inventory.hosts),
        "total_assets_created": len(assets),
        "total_pending_assets": len(pending_assets),
        "total_skipped_hosts": len(skipped_hosts),
        "assets": assets,
        "pending_assets": pending_assets,
        "skipped_hosts": skipped_hosts
    }
