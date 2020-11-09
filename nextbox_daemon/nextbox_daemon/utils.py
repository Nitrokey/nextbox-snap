import os
import sys
from pathlib import Path
import yaml
import logging
import socket

from flask import jsonify


log = logging.getLogger("nextbox")


NEXTBOX_HDD_LABEL = "NextBoxHardDisk"


def error(msg, data=None):
    msg = [msg]
    return jsonify({
        "result": "error",
        "msg": [msg],
        "data": data
    })


def success(msg=None, data=None):
    msg = [msg] if msg else []
    return jsonify({
        "result": "success",
        "msg": msg,
        "data": data
    })


def load_config(config_path):
    """load config in given 'config_path' or return default"""

    if not os.path.exists(config_path):
        print(f"config path: {config_path} not found, returning default")
        return {
            "token": {
                "value": None,
                "created": None,
                "ip": None
            },
            "backup": {
                "last_backup": None,
                "last_restore": None
            },
            "nextcloud": {
                "http_port": 80,
                "https_port": None,
                "hostname": "NextBox",
                "trusted_domains": None

            }
        }

    with open(config_path) as fd:
        cfg = yaml.safe_load(fd)

    return cfg

def save_config(cfg, config_path):
    """save config to given 'config_path'"""

    with open(config_path, "w") as fd:
        yaml.safe_dump(cfg, fd)


def local_ip():
    return socket.gethostbyname(socket.gethostname())

def get_partitions():
    alldevs = os.listdir("/dev/")
    alllabels = os.listdir("/dev/disk/by-label")

    # mounted: <dev> => <mount-point>
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
                elif mountpoint == "/media/nextcloud":
                    out["main"] = dev
    return out

def parse_backup_line(line, dct_data):
    toks = line.split()
    if len(toks) == 0:
        return

    # handle exporting line step
    if toks[0].lower() == "exporting" and len(toks) > 1:
        dct_data["step"] = toks[1].replace(".", "")
        if dct_data["step"] == "init":
            dct_data["target"] = " ".join(toks[2:])[1:-1]

    # handle importing line step
    elif toks[0].lower() == "importing" and len(toks) > 1:
        dct_data["step"] = toks[1].replace(".", "")

    elif len(toks) >= 3 and toks[0].lower() == "successfully":
        dct_data["success"] = " ".join(toks[2:])

    elif len(toks) >= 3 and toks[0].lower() == "unable":
        dct_data["unable"] = toks[-1]

    # handle progress (how many files are already done)
    elif len(toks) > 1 and "=" in toks[-1]:
        subtoks = toks[-1].split("=")
        if len(subtoks) > 1:
            try:
                lhs, rhs = subtoks[-1][:-1].split("/")
                ratio = (1 - (int(lhs) / int(rhs))) * 100
                dct_data["progress"] = f"{ratio:.1f}"
            except ValueError:
                dct_data["progress"] = None


def tail(filepath, num_lines=20):
    p = Path(filepath)
    try:
        lines = p.read_text("utf-8").split("\n")
        if num_lines is None or num_lines < 0:
            return lines
        return lines[-num_lines:]
    except OSError as e:
        log.error(f"read from file {filepath} failed, exception: {e}")
        return None



