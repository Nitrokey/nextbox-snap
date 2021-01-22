import os
import yaml

import logging.handlers
import logging

from nextbox_daemon.consts import LOGGER_NAME, LOG_FILENAME, MAX_LOG_SIZE

class Config(dict):
    def __init__(self, config_path, *va, **kw):
        super().__init__(*va, **kw)

        self.config_path = config_path

        self.update({
            "config":    {
                "last_backup":  None,
                "last_restore": None,
                "http_port":    80,
                "https_port":   None,
                "hostname":     "NextBox",
                "log_lvl": logging.INFO,

                "domain":       None,
                "email":        None,
                "desec_token":  None,
                "nk_token":     None,
                "proxy_active": False,
                "proxy_domain": None,
                "dns_mode":     "off",
                "expert_mode":  False,
            }
        })
        self.load()

    def load(self):
        if not os.path.exists(self.config_path):
            print(f"config path: {self.config_path} not found...")
            return

        with open(self.config_path) as fd:
            loaded = yaml.safe_load(fd)
            try:
                self.update(loaded)
            except TypeError:
                pass

    def save(self):
        print(f"saving config to {self.config_path}")
        print(dict(self))
        with open(self.config_path, "w") as fd:
            yaml.safe_dump(dict(self), fd)


# logger setup + rotating file handler
log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)
log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILENAME, maxBytes=MAX_LOG_SIZE, backupCount=5)
log.addHandler(log_handler)
log_format = logging.Formatter("{asctime} {module} {levelname} => {message}", style='{')
log_handler.setFormatter(log_format)

log.info("starting nextbox-daemon")
