import os
import sys
from pathlib import Path
import subprocess
from functools import wraps
import select
import time
import threading
import shutil

# append proper (snap) site-packages path
sys.path.append("/snap/nextbox/current/lib/python3.6/site-packages")

import psutil
from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response

from utils import load_config, save_config, get_partitions, error, success, \
    NEXTBOX_HDD_LABEL


CONFIG_PATH = "/var/snap/nextbox/current/nextbox.conf"
#CONFIG_PATH = "/tmp/nextbox.conf"

MAX_TOKEN_AGE = 60 * 5

cfg = load_config(CONFIG_PATH)

app = Flask(__name__)
app.secret_key = "123456-nextbox-123456" #cfg["secret_key"]

# backup thread handler
backup_proc = None
backup_state = {}

#@app.before_request
#def limit_remote_addr():
#    if request.remote_addr != '10.20.30.40':
#        abort(403)  # Forbidden
#

### CORS section
@app.after_request
def after_request_func(response):
    origin = request.headers.get('Origin')
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Headers', 'x-csrf-token')
        response.headers.add('Access-Control-Allow-Methods',
                            'GET, POST, OPTIONS, PUT, PATCH, DELETE')
        if origin:
            response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        if origin:
            response.headers.add('Access-Control-Allow-Origin', origin)

    if not origin:
        response.headers.add('Access-Control-Allow-Origin', "192.168.10.129")

    return response
### end CORS section



# decorator for authenticated access
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # no auth token: 403
        if cfg["token"]["value"] is None:
            return error("not allowed")
        # auth token too old: 403
        if time.time() - cfg["token"]["created"] > MAX_TOKEN_AGE:
            return error("not allowed")
        # check for proper token
        if cfg["token"]["value"] != request.args.get("token"):
            return error("not allowed")
        return f(*args, **kwargs)
    return decorated


@app.route("/overview")
def show_overview():
    return jsonify({
        "storage": get_partitions(),
        "backup": check_for_backup_process()
    })
    
@app.route("/token/<token>/<allow_ip>")
def set_token(token, allow_ip):

    if request.remote_addr != "127.0.0.1":
        #abort(403)
        return error("not allowed")

    cfg["token"]["value"] = token
    cfg["token"]["created"] = time.time()
    cfg["token"]["ip"] = allow_ip
    save_config(cfg, CONFIG_PATH)

    return success()


@app.route("/storage")
@requires_auth
def storage():
    parts = get_partitions()
    return success(data=parts)


@app.route("/storage/mount/<device>/<name>")
@requires_auth
def mount_storage(device, name):

    if ".." in device or "/" in device or name == "nextcloud":
        return error("invalid device")
    if ".." in name or "/" in name:
        return error("invalid name")

    parts = get_partitions()

    mount_target = f"/media/{name}"
    mount_device = None
    for avail in parts["available"]:
        if Path(avail).name == device:
            mount_device = avail

    if not mount_device:
        return error("device to mount not found")

    if mount_device == parts["main"]:
        return error("will not mount main data partition")

    if mount_device in parts["mounted"]:
        return error("already mounted")

    if mount_target in parts["mounted"].values():
        return error(f"target {mount_target} has been already mounted")

    if not os.path.exists(mount_target):
        os.makedirs(mount_target)

    try:
        ret = subprocess.check_call(["mount", mount_device, mount_target])
    except subprocess.CalledProcessError as e:
        ret = e.returncode

    if ret != 0:
        return error(f"mount {mount_device} to {mount_target} failed (retcode: {ret})")

    return success(f"mounting successful ({mount_target})")


@app.route("/storage/umount/<name>")
@requires_auth
def umount_storage(name):
    if ".." in name or "/" in name or name == "nextcloud":
        return error("invalid name")

    mount_target = f"/media/{name}"
    parts = get_partitions()

    if name == "nextcloud":
        return error("will not umount main data partition")

    if mount_target not in parts["mounted"].values():
        return error("not mounted")

    try:
        ret = subprocess.check_call(["umount", mount_target])
    except subprocess.CalledProcessError as e:
        ret = e.returncode
    if ret != 0:
        return error(f"umounting {mount_target} failed (retcode: {ret})")

    return success(f"unmounting successful ({mount_target})")


def check_for_backup_process():
    global backup_proc, backup_state

    out = dict(cfg["backup"])
    if backup_proc is None:
        out["running"] =  False
        return out

    assert isinstance(backup_proc, subprocess.Popen)

    #for proc in psutil.process_iter():
    #    if proc.name() in ["export-data", "import-data"]:
    #        out["what"] = proc.name()
    #        out["started"] = proc.create_time()

    sel = select.poll()
    sel.register(backup_proc.stdout, select.POLLIN)

    line = None
    empty_line = False
    while line != b"":
        # max wait in milliseconds for new inputs
        if not sel.poll(1):
            break

        line = backup_proc.stdout.readline().decode("utf-8")
        toks = line.strip().split(r"\b")[-1].split()

        # empty line (we skip the 1st, but a 2nd leads to a break)
        if len(toks) == 0:
            if not empty_line:
                empty_line = True
                continue
            break

        # handle exporting line step
        if toks[0].lower() == "exporting" and len(toks) > 1:
            backup_state["step"] = toks[1].replace(".", "")
            if backup_state["step"] == "init":
                backup_state["target"] = " ".join(toks[2:])[1:-1]

        # handle importing line step
        elif toks[0].lower() == "importing" and len(toks) > 1:
            backup_state["step"] = toks[1].replace(".", "")

        elif len(toks) >= 3 and toks[0].lower() == "successfully":
            backup_state["success"] = " ".join(toks[2:])

        elif len(toks) >= 3 and toks[0].lower() == "unable":
            backup_state["unable"] = toks[-1]

        # handle progress (how many files are already done)
        elif len(toks) > 1 and "=" in toks[-1]:
            subtoks = toks[-1].split("=")
            if len(subtoks) > 1:
                try:
                    lhs, rhs = subtoks[-1][:-1].split("/")
                    ratio = (1 - (int(lhs) / int(rhs))) * 100
                    backup_state["progress"] = f"{ratio:.1f}"
                except ValueError:
                    backup_state["progress"] = None

    # check if we are already done
    if backup_proc.poll() is not None:
        ret = backup_proc.poll()

        if ret == 0:
            state = "finished"
            cfg["backup"]["last_" + backup_state["what"]] = backup_state["when"]
            save_config(cfg, CONFIG_PATH)
            out["last_" + backup_state["what"]] = backup_state["when"]

        else:
            state = "failed: " + backup_state.get("unable", "")
            if "target" in backup_state:
                shutil.rmtree(backup_state["target"])
                # @todo: log output

        out = dict(backup_state)
        out["state"] = state
        out["returncode"] = ret
        out["running"] = False

        backup_proc = None
        backup_state = {}
    else:
        out = dict(backup_state)
        out["running"] = True

    return out


@app.route("/backup")
@requires_auth
def backup():
    data = dict(cfg["backup"])
    data["operation"] = check_for_backup_process()
    data["found"] = []

    if get_partitions()["backup"] is not None:
        for name in os.listdir("/media/backup"):
            p = Path("/media/backup") / name
            size = (p / "size").open().read().strip().split()[0]
            data["found"].append({
                "name": name,
                "created": p.stat().st_ctime,
                "size": size
            })
            data["found"].sort(key=lambda x: x["created"], reverse=True)

    return success(data=data)


#@app.route("/backup/cancel")
#def backup_cancel(name):
#    global backup_proc
#
#    subprocess.check_call(["killall", "nextcloud-nextbox.export"])
#    #subprocess.check_call(["killall", "nextcloud-nextbox.import"])
#
#    pass


@app.route("/backup/start")
@requires_auth
def backup_start():
    global backup_proc
    backup_info = check_for_backup_process()
    parts = get_partitions()

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    if not parts["backup"]:
        return error("no 'backup' storage mounted")

    backup_proc = subprocess.Popen(["nextcloud-nextbox.export"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    backup_state["what"] = "backup"
    backup_state["when"] = time.time()

    return success("backup started", data=backup_info)


@app.route("/backup/restore/<name>")
@requires_auth
def backup_restore(name):
    global backup_proc
    backup_info = check_for_backup_process()

    if ".." in name or "/" in name:
        return error("invalid name", data=backup_info)

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    directory = f"/media/backup/{name}"
    backup_proc = subprocess.Popen(["nextcloud-nextbox.import", directory],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    backup_state["what"] = "restore"
    backup_state["when"] = time.time()

    return success("restore started", data=backup_info)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18585, debug=True, threaded=True, processes=1)


# @todo: CORS whitelist origins (and handle whitelist)
######### -> better: token should als get it's IP passed, and this ip is then CORS whitelisted

# @todo: hostname, nextcloud (http, https), listen
# @todo: derive secret key -> machine-id (maybe only as flask-secret, not for hashing?)
# @todo: handle multiple backup processes (needed?)
# @todo: validate (mount) name (partly done, enough?)
# @fixme: thread-locks ?
# @todo: logging!=!==!
# @todo: check for backup operation if unmounting backup
# @todo: move backup/restore line parsing to utils.py
# @todo: how to show the backup/restore progress during the maintainance mode (partly done)
# @todo: how to handle removed harddrive without prior umounting...
# @todo: JS: show filesystem type
# @todo: forward all API calls using PHP

# @todo: better handle missing origin
# @todo: default extra-apps to install during setup (nextcloud-nextbox)

#### done:
# @todo: append sys.paths
# @todo: decorate with requires_auth
