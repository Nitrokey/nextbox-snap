

TOOL_NAME = "nextbox"

API_VERSION = 1

LOGGER_NAME = TOOL_NAME
MAX_LOG_SIZE = 2**30

NEXTBOX_HDD_LABEL = "NextBoxHardDisk"

GET_EXT_IP4_URL = "http://v4.ipv6-test.com/api/myip.php"
GET_EXT_IP6_URL = "http://v6.ipv6-test.com/api/myip.php"

CONFIG_PATH = "/var/snap/nextbox/current/nextbox.conf"
LOG_FILENAME = "/var/snap/nextbox/current/nextbox.log"

DDCLIENT_CONFIG_PATH = "/var/snap/ddclient-snap/current/etc/ddclient/ddclient.conf"
DDCLIENT_BIN = "/snap/bin/ddclient-snap.exec"
DDCLIENT_SERVICE = "snap.ddclient-snap.daemon.service"

NEXTBOX_SERVICE = "nextbox-daemon.service"

DYNDNS_MODES = ["desec", "desec_2", "static", "config", "off",
                "desec_done", "config_done", "static_done"]

AVAIL_CONFIGS = ["dns_mode", "desec_token", "email", "domain", "nk_token",
                 "proxy_active", "proxy_domain"]

DYNDNS_DESEC_CAPTCHA = "https://desec.io/api/v1/captcha/"
DYNDNS_DESEC_REGISTER = "https://desec.io/api/v1/auth/"


SYSTEMD_RESOLVE_BIN = "/usr/bin/systemd-resolve"

SYSTEMCTL_BIN = "/bin/systemctl"

UPDATE_NEXTBOX_APP_CMD = ["/snap/bin/nextcloud-nextbox.occ",
                          "app:update", "-n", "nextbox", "--ansi"]
INSTALL_NEXTBOX_APP_CMD = ["/snap/bin/nextcloud-nextbox.occ",
                          "app:install", "-n", "nextbox", "--ansi"]



ENABLE_HTTPS_BIN = "/snap/bin/nextcloud-nextbox.enable-https"
DISABLE_HTTPS_BIN = "/snap/bin/nextcloud-nextbox.disable-https"
BACKUP_EXPORT_BIN = "/snap/bin/nextcloud-nextbox.export"
BACKUP_IMPORT_BIN = "/snap/bin/nextcloud-nextbox.import"

CERTBOT_CERTS_PATH = "/var/snap/nextcloud-nextbox/current/certs/certbot/config/live"
CERTBOT_BACKUP_PATH = "/var/snap/nextcloud-nextbox/current/certs/certbot/config/live.bak"

OCC_BIN = "/snap/bin/nextcloud-nextbox.occ"
MOUNT_BIN = "/bin/mount"
UMOUNT_BIN = "/bin/umount"