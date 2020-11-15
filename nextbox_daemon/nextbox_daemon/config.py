import os
import yaml


class Config(dict):
    def __init__(self, config_path, *va, **kw):
        super().__init__(*va, **kw)

        self.config_path = config_path

        self.update({
            "backup":    {
                "last_backup":  None,
                "last_restore": None
            },
            "nextcloud": {
                "http_port":  80,
                "https_port": None,
                "hostname":   "NextBox",
                "domain":     None,
                "email":      None
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
        with open(self.config_path, "w") as fd:
            yaml.safe_dump(dict(self), fd)

