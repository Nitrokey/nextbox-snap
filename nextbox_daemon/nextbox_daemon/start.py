import os
import sys
from pathlib import Path
import subprocess
from functools import wraps
import select
import time
import threading

# append proper (snap) site-packages path
sys.path.append("/snap/nextbox/current/lib/python3.6/site-packages")

import psutil
from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response

from utils import load_config, save_config, get_partitions, NEXTBOX_HDD_LABEL


#CONFIG_PATH = "/var/snap/nextbox/current/nextbox.conf"
CONFIG_PATH = "/tmp/nextbox.conf"

cfg = load_config(CONFIG_PATH)

app = Flask(__name__)
app.secret_key = "123456-nextbox-123456" #cfg["secret_key"]

# backup thread handler
backup_proc = None
backup_state = {}




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

    return response
### end CORS section




def error(msg, data=None):
    msg = [msg]
    if cfg["user"] is None and cfg["password"] is None:
        msg.append("WARNING: No user and password set!")

    return jsonify({
        "result": "error",
        "msg": [msg],
        "data": data
    })


def success(msg=None, data=None):
    msg = [msg] if msg else []
    if cfg["user"] is None and cfg["password"] is None:
        msg.append("WARNING: No user and password set!")

    return jsonify({
        "result": "success",
        "msg": msg,
        "data": data
    })


def make_pass(pwd):
    # @todo: add hashed password here
    return pwd


def check_auth_global(username, password):
    return username == cfg["user"] and cfg["password"] == make_pass(password)


def http_authenticate():
    return Response("No access!", 401, {
      "WWW-Authenticate": 'Basic realm="Login Required"'}
    )


# decorator for authenticated access
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # only check user/password, if it's actually set in the config file
        if not (cfg["user"] is None and cfg["password"] is None):
            auth = request.authorization
            if not auth or not check_auth_global(auth.username, auth.password):
                return http_authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/logout")
def http_logout():
    return http_authenticate()


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
        return error("will not mount main data parititon")

    if mount_device in parts["mounted"]:
        return error("already mounted")

    if mount_target in parts["mounted"].values():
        return error(f"target {mount_target} has been already mounted")

    if not os.path.exists(mount_target):
        os.makedirs(mount_target)

    ret = subprocess.check_call(["mount", mount_device, mount_target])
    if ret != 0:
        return error(f"mount {mount_device} to {mount_target} failed")

    if name == "backup":
        cfg["backup"]["mount"] = mount_device
        save_config(cfg, CONFIG_PATH)

    return success(f"mounting successful ({mount_target})")


@app.route("/storage/umount/<name>")
@requires_auth
def umount_storage(name):
    if ".." in name or "/" in name or name == "nextcloud":
        return error("invalid name")

    mount_target = f"/media/{name}"
    parts = get_partitions()

    if mount_target not in parts["mounted"].values():
        return error("not mounted")

    ret = subprocess.check_call(["umount", mount_target])
    if ret != 0:
        return error(f"umounting {mount_target} failed")

    if name == "backup":
        cfg["backup"]["mount"] = None
        save_config(cfg, CONFIG_PATH)

    return success(f"unmounting successful ({mount_target})")


def check_for_backup_process():
    global backup_proc, backup_state

    if backup_proc is None:
        return {"running": False}

    out = {}
    for proc in psutil.process_iter():
        if proc.name() in ["export-data", "import-data"]:
            out["what"] = proc.name()
            out["started"] = proc.create_time()

    sel = select.poll()
    sel.register(backup_proc.stdout, select.POLLIN)

    line = None
    while line != b"":
        # max wait in milliseconds for new inputs
        if not sel.poll(1):
          break

        line = backup_proc.stdout.readline()
        toks = line.strip().split(rb"\b")[0].split()

        print (toks)
        print("-------------------------")
        print("-------------------------")
        print("-------------------------")
        print("-------------------------")
        print("-------------------------")

        # empty line
        if len(toks) == 0:
            continue

        # handle exporting line step
        if toks[0].lower() == b"exporting" and len(toks) > 1:
            backup_state["step"] = toks[0], toks[1].replace(b".", b"")

        # handle importing line step
        elif toks[0].lower() == b"importing" and len(toks) > 1:
            backup_state["step"] = toks[0], toks[1].replace(b".", b"")

        # handle progress (how many files are already done)
        elif len(toks) > 1 and b"=" in toks[-1]:
            subtoks = toks[-1].split(b"=")
            if len(subtoks) > 1:
                try:
                    lhs, rhs = subtoks[-1][:-1].split(b"/")
                    ratio = (int(lhs) / int(rhs)) * 100
                    backup_state["progress"] = f"{ratio:.1f}"
                except ValueError:
                    backup_state["progress"] = None

    # check if we are already done
    if backup_proc.poll() is not None:
        ret = backup_proc.poll()
        backup_proc = None
        backup_state = {}
        out = {"state": "finished", "returncode": ret, "running": False}
    else:
        out = dict(backup_state)
        out["running"] = True

    return out


@app.route("/backup")
@requires_auth
def backup():
    data = cfg["backup"]
    data["operation"] = check_for_backup_process()
    data["found"] = None

    if cfg["backup"]["mount"] is not None and get_partitions()["backup"] is not None:
        data["found"] = os.listdir("/media/backup")

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

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    backup_proc = subprocess.Popen(["nextcloud-nextbox.export"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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

    return success("restore started", data=backup_info)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18585, debug=True, threaded=True, processes=1)


# @todo: CORS whitelist origins
# @todo: password change
# @todo: hostname, nextcloud (http, https), listen
# @todo: derive secret key -> machine-id (maybe only as flask-secret, not for hashing?)
# @todo: decorate with requires_auth
# @todo: handle multiple backup processes (needed?)
# @todo: validate (mount) name (partly done, enough?)
# @fixme: thread-locks ?
# @todo: logging!=!==!
# @todo: check for backup operation if unmounting backup

# @todo: how to show the backup/restore progress during the maintainance mode
# from flask import abort, request
#
#@app.before_request
#def limit_remote_addr():
#    if request.remote_addr != '10.20.30.40':
#        abort(403)  # Forbidden
#
#### or we do a decorator which is checking for the remote address and allow any IP
#### for the backup/restore progress endpoint



#### done:
# @todo: append sys.paths
