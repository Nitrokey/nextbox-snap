import os
from pathlib import Path
import socket
import shutil

from flask import jsonify

from nextbox_daemon.consts import NEXTBOX_HDD_LABEL, API_VERSION, CERTBOT_BACKUP_PATH, \
    CERTBOT_CERTS_PATH

from nextbox_daemon.config import log


def error(msg, data=None):
    msg = [msg]
    return jsonify({
        "result": "error",
        "msg": msg,
        "data": data,
        "api": API_VERSION
    })


def success(msg=None, data=None):
    msg = [msg] if msg else []
    return jsonify({
        "result": "success",
        "msg": msg,
        "data": data,
        "api": API_VERSION
    })

def local_ip():
    return socket.gethostbyname(socket.gethostname())

def get_partitions():
    alldevs = os.listdir("/dev/")
    alllabels = os.listdir("/dev/disk/by-label")

    # mounted: <dev> => <mount-point>
    out = {
        "available": [],
        "mounted": {},
        "type": {},
        "backup": None,
        "main": None,
        "block_devs": {}
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

            block_dev = dev[:3]
            out["block_devs"].setdefault(block_dev, {})

    with open("/proc/mounts", "rt") as fd:
        for line in fd:
            toks = line.split()
            dev, mountpoint, ftype = toks[0], toks[1], toks[2]
            if dev in out["available"] or dev == out["main"]:
                out["mounted"][dev] = mountpoint
                if mountpoint == "/media/backup":
                    out["backup"] = dev
                elif mountpoint == "/media/nextcloud":
                    out["main"] = dev
                out["type"][dev] = ftype

    for block_dev in out["block_devs"]:
        try:
            p_base = Path("/sys/block") / block_dev / "device"
            vendor = (p_base / "vendor").read_text("utf-8").strip()
            model = (p_base / "model").read_text("utf-8").strip()
            out["block_devs"][block_dev]["name"] = f"{vendor} {model}"
        except OSError as e:
            out["block_devs"][block_dev]["name"] = "n/a"

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


def cleanup_certs():
    # remove any certificates in live dir
    bak = Path(CERTBOT_BACKUP_PATH)
    src = Path(CERTBOT_CERTS_PATH)
    if not bak.exists():
        os.makedirs(bak.as_posix())
        log.debug(f"creating certs backup directory: {bak}")

    contents = os.listdir(src.as_posix())
    if len(contents) > 1:
        log.debug("need to clean up certs directory")

    for path in contents:
        if path == "README":
            continue

        full_src_path = src / path
        full_bak_path = bak / path
        idx = 1
        while full_bak_path.exists():
            full_bak_path = Path((bak / path).as_posix() + f".{idx}")
            idx += 1

        log.debug(f"moving old cert: {full_src_path} to {full_bak_path}")
        shutil.move(full_src_path, full_bak_path)


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



