#!/bin/bash
# Brings the OpenEO setup access point up/down. Must run as root (portal.py calls it
# via sudo) and is only called once portal.py has decided the portal is needed.
#
# The AP is WPA2-PSK using the passphrase in /etc/openeo/hotspot.psk (written by
# portal/setupfile.py from openeo-setup.txt). Without a valid passphrase the AP is
# NEVER started (no open network fallback).

PSK_FILE=/etc/openeo/hotspot.psk
AP_CON=openeo-AP
AP_ADDR=192.168.4.1

remove_redirect() {
	# Delete every copy of our wlan1-only 80 -> 81 redirect (idempotent)
	while iptables -t nat -C PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-ports 81 2>/dev/null; do
		iptables -t nat -D PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-ports 81
	done
}

if [ "$1" = "stop" ] ; then
	######
	# Shuts down captive portal
	remove_redirect
	nmcli conn del $AP_CON 2>/dev/null
	iw dev wlan1 del 2>/dev/null
	service dnsmasq stop
	exit 0
fi

############
# Validate the hotspot passphrase: 8-63 printable ASCII
if [ ! -r "$PSK_FILE" ]; then
	echo >&2 "openeo_portal: $PSK_FILE missing - not starting the access point"
	exit 3
fi
PSK=$(head -n 1 "$PSK_FILE")
if [ ${#PSK} -lt 8 ] || [ ${#PSK} -gt 63 ] || ! LC_ALL=C bash -c '[[ $1 =~ ^[\ -~]+$ ]]' _ "$PSK"; then
	echo >&2 "openeo_portal: hotspot passphrase invalid (need 8-63 printable ASCII) - not starting the access point"
	exit 3
fi

############
# Take a precaution and wait for the network to settle
sleep 15

echo "Creating virtual network interface"
iw dev wlan1 del 2>/dev/null
iw dev wlan0 interface add wlan1 type __ap

echo "NM Connections"
nmcli conn del $AP_CON 2>/dev/null
echo "Add and configure new connection (WPA2-PSK)"
nmcli radio wifi on
nmcli con add type wifi ifname wlan1 mode ap con-name $AP_CON ssid OpenEO autoconnect false
nmcli con modify $AP_CON wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn \
	wifi-sec.pairwise ccmp wifi-sec.group ccmp wifi-sec.psk "$PSK"
nmcli con modify $AP_CON ipv6.method disabled
nmcli con modify $AP_CON ipv4.method manual ipv4.address $AP_ADDR/24

# Fail closed: refuse to bring up the AP unless it is really configured for WPA-PSK
if [ "$(nmcli -g 802-11-wireless-security.key-mgmt con show $AP_CON)" != "wpa-psk" ]; then
	echo >&2 "openeo_portal: access point is not WPA-PSK - aborting"
	nmcli conn del $AP_CON 2>/dev/null
	iw dev wlan1 del 2>/dev/null
	exit 4
fi
nmcli con up id $AP_CON || exit 5

sleep 5
service dnsmasq start

####
# portal.py listens on port 81 of the AP address (192.168.4.1) only, deliberately to
# avoid clashing with tcp/80 on the main user interface. Captive-portal clients ask
# for tcp/80, so redirect that to 81 - on the AP interface wlan1 ONLY.
remove_redirect
iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-ports 81
