import os
import sys
from pathlib import Path

import yaml

NEXTBOX_HDD_LABEL = "NextBoxHardDisk"

def load_config(config_path):
    """load config in given 'config_path' or return default"""

    if not os.path.exists(config_path):
        print(f"config path: {config_path} not found, returning default")
        return {
            "password": None,
            "user": None,
            "backup": {
                "last": None,
                "mount": None
            },
            "listen": {
                "host": "0.0.0.0",
                "port": 18585,
            },
            "nextcloud": {
                "http_port": 22,
                "https_port": None,
                "hostname": "NextBox",
            }
        }

    with open(config_path) as fd:
        cfg = yaml.safe_load(fd)

    return cfg

def save_config(cfg, config_path):
    """save config to given 'config_path'"""

    with open(config_path, "w") as fd:
        yaml.safe_dump(cfg, fd)

def get_partitions():
    alldevs = os.listdir("/dev/")
    alllabels  = os.listdir("/dev/disk/by-label")

    out = {
        "available": [],
        "mounted": {},
        "backup": None,
        "main": None

    }
    label_map = {}
    for label in alllabels:
        p = Path(f"/dev/disk/by-label/{label}")
        label_map[p.resolve().as_posix()] = p.as_posix()

    for dev in alldevs:
        if dev.startswith("sd"):
            path = f"/dev/{dev}"
            if label_map.get(path) == NEXTBOX_HDD_LABEL:
                out["main"] = path
            elif path[-1] in map(str, range(1, 10)):
                out["available"].append(path)

    with open("/proc/mounts", "rt") as fd:
        for line in fd:
            toks = line.split()
            dev, mountpoint = toks[0], toks[1]
            if dev in out["available"] or dev == out["main"]:
                out["mounted"][dev] = mountpoint
                if mountpoint == "/media/backup":
                    out["backup"] = dev
    return out
