
from backend.models.network_asset import (
    NetworkAddress,
    NetworkService,
    NetworkPort,
    NetworkAsset,
    NetworkInventory,
    NetworkScanSummary
)

from backend.services.asset_adapter import (
    convert_network_inventory_to_assets
)


# 1. Create sample Nmap host data
hosts = [

    NetworkAsset(
        status="up",

        addresses=NetworkAddress(
            ipv4="192.168.1.10"
        ),

        hostnames=["web-server"],

        os_matches=[
            {
                "name": "Linux 5.x",
                "accuracy": "95"
            }
        ],

        ports=[
            NetworkPort(
                protocol="tcp",
                port=80,
                state="open",

                service=NetworkService(
                    name="http",
                    product="Apache",
                    version="2.4",
                    cpe=["cpe:/a:apache:http_server:2.4"]
                )
            ),

            NetworkPort(
                protocol="tcp",
                port=443,
                state="open",

                service=NetworkService(
                    name="https",
                    product="Apache",
                    version="2.4",
                    cpe=[]
                )
            )
        ]
    ),

    NetworkAsset(
        status="up",

        addresses=NetworkAddress(
            ipv4="192.168.1.20"
        ),

        hostnames=["unknown-device"],

        ports=[
            NetworkPort(
                protocol="tcp",
                port=22,
                state="open",

                service=NetworkService(
                    name="ssh",
                    product="OpenSSH",
                    version="9.0",
                    cpe=[]
                )
            )
        ]
    )
]


# 2. Create NetworkInventory
inventory = NetworkInventory(
    scanner="Nmap",
    nmap_version="7.80",
    hosts=hosts,
    summary=NetworkScanSummary(
        total_hosts=2,
        hosts_up=2,
        hosts_down=0,
        observed_ports=3,
        open_ports=3
    )
)


# 3. Supply verified metadata for the first host
metadata_by_ip = {

    "192.168.1.10": {
        "asset_type": "server",
        "zone": "internal",
        "criticality": 8
    }

}


# 4. Convert NetworkInventory into Assets
result = convert_network_inventory_to_assets(
    inventory,
    metadata_by_ip
)


# 5. Display conversion summary
print("ASSET ADAPTER TEST")
print("------------------")

print(
    "Total hosts:",
    result["total_hosts_received"]
)

print(
    "Assets created:",
    result["total_assets_created"]
)

print(
    "Pending assets:",
    result["total_pending_assets"]
)

print(
    "Skipped hosts:",
    result["total_skipped_hosts"]
)


# 6. Display created assets
print("\nCREATED ASSETS")

for asset in result["assets"]:
    print(asset.model_dump())


# 7. Display pending assets
print("\nPENDING ASSETS")

for asset in result["pending_assets"]:
    print(asset)
