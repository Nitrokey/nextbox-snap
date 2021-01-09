

TOOL_NAME = "nextbox"

API_VERSION = 1

LOGGER_NAME = TOOL_NAME
MAX_LOG_SIZE = 2**30

NEXTBOX_HDD_LABEL = "NextBoxHardDisk"

GET_EXT_IP_URL = "http://ifconfig.me/ip"


CONFIG_PATH = "/var/snap/nextbox/current/nextbox.conf"
LOG_FILENAME = "/var/snap/nextbox/current/nextbox.log"

DDCLIENT_CONFIG_PATH = "/var/snap/ddclient-snap/current/etc/ddclient/ddclient.conf"
DDCLIENT_BIN = "/snap/bin/ddclient-snap.exec"
DDCLIENT_SERVICE = "snap.ddclient-snap.daemon.service"

DYNDNS_MODES = ["desec", "static", "config", "off"]
DYNDNS_CONFIGS = ["dns_mode", "desec_token", "email", "domain"]

SYSTEMCTL_BIN = "/bin/systemctl"


ENABLE_HTTPS_BIN = "/snap/bin/nextcloud-nextbox.enable-https"
DISABLE_HTTPS_BIN = "/snap/bin/nextcloud-nextbox.disable-https"
BACKUP_EXPORT_BIN = "/snap/bin/nextcloud-nextbox.export"
BACKUP_IMPORT_BIN = "/snap/bin/nextcloud-nextbox.import"

CERTBOT_CERTS_PATH = "/var/snap/nextcloud-nextbox/current/certs/certbot/config/live"
CERTBOT_BACKUP_PATH = "/var/snap/nextcloud-nextbox/current/certs/certbot/config/live.bak"

OCC_BIN = "/snap/bin/nextcloud-nextbox.occ"
MOUNT_BIN = "/bin/mount"
UMOUNT_BIN = "/bin/umount"