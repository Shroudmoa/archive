import json


local_net = input("Enter your local network (e.g., 192.168.25.0/24): ").strip()
user_input = input("Paste VPN configuration JSON: ")

try:
    data = json.loads(user_input)
except json.JSONDecodeError:
    print("Invalid JSON")
    exit(1)
params = {item['name']: item['value'] for item in data['parameters']}
tunnel_ip = params.get('localTunnelIp', '10.0.0.1')
p1_proposal = "aes128gcm16-prfsha512-ecp256"
p2_proposal = "aes128gcm16-prfsha512-ecp256"
iptables_rules = f"""
doas iptables -A FORWARD -s {local_net} -d {params['openFdNet']} -o eth0 -j ACCEPT
doas iptables -A FORWARD -s {local_net} -d {params['hskVkonNet']} -o eth0 -j ACCEPT
doas iptables -A FORWARD -s {params['hskVkonNet']} -d {local_net} -o eth0 -j ACCEPT
doas iptables -t nat -A POSTROUTING -s {local_net} -d {params['openFdNet']} -o eth0 -j SNAT --to-source {tunnel_ip}
doas iptables -t nat -A POSTROUTING -s {local_net} -d {params['hskVkonNet']} -o eth0 -j SNAT --to-source {tunnel_ip}
"""
swanctl_conf = f"""
connections {{
    ti-gw {{
        version = {params.get('ikeVersion', '2')}
        local_addrs = %any
        remote_addrs = {params['remoteGatewayIp']}
        proposals = {p1_proposal}
        vips = {tunnel_ip}
        encap = yes
        fragmentation = yes
        rekey_time = {params.get('p1KeyLifetime', '86400')}

        local-1 {{
            auth = {'eap-mschapv2' if params.get('eapAuthentication') == 'true' else 'psk'}
            id = {params['localId']}
            {'eap_id = ' + params['eapUserName'] if params.get('eapAuthentication') == 'true' else ''}
        }}

        remote-1 {{
            id = {params['peerId']}
            auth = psk
        }}

        children {{
            ti-gw-child {{
                esp_proposals = {p2_proposal}
                local_ts = {local_net}, {tunnel_ip}/32
                remote_ts = {params['openFdNet']}, {params['hskVkonNet']}
                rekey_time = {params.get('p2KeyLifetime', '43200')}
                mode = tunnel
                dpd_action = restart
                close_action = restart
            }}
        }}
    }}
}}

secrets {{
    ike-ti-gw {{
        id-1 = {params['localId']}
        id-2 = {params['peerId']}
        secret = {params['sharedPskSec']}
    }}
    eap-ti-gw {{
        secret = {params['eapPassword']}
        id = {params['eapUserName']}
    }}
}}
"""
with open("swanctl.conf", "w") as f:
    f.write(iptables_rules + "\n" + swanctl_conf)

print("swanctl.conf generated")
