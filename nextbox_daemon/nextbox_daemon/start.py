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

import logging
import logging.handlers

import psutil
from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response

from utils import load_config, save_config, get_partitions, error, success, \
    NEXTBOX_HDD_LABEL, tail, parse_backup_line

from command_runner import CommandRunner

# @todo: remove token in favor of php-forwarding (or keep it for later use)
MAX_TOKEN_AGE = 60 * 5
MAX_LOG_SIZE = 2**30

CONFIG_PATH = "/var/snap/nextbox/current/nextbox.conf"
LOG_FILENAME = "/var/snap/nextbox/current/nextbox.log"
DDCLIENT_CONFIG_PATH = "/var/snap/ddclient-snap/current/etc/ddclient/ddclient.conf"
DDCLIENT_BIN = "/snap/bin/ddclient-snap.exec"
DDCLIENT_SERVICE = "snap.ddclient-snap.daemon.service"

# logger setup + rotating file handler
log = logging.getLogger("nextbox")
log.setLevel(logging.DEBUG)
log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILENAME, maxBytes=MAX_LOG_SIZE, backupCount=5)
log.addHandler(log_handler)
log_format = logging.Formatter("{asctime} {name} {levelname}\n"
                       "    {message}", style='{')
log_handler.setFormatter(log_format)

log.info("starting nextbox-daemon")


# config load
cfg = load_config(CONFIG_PATH)

app = Flask(__name__)
app.secret_key = "123456-nextbox-123456" #cfg["secret_key"]

# backup thread handler
backup_proc = None
#backup_state = {}

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

@app.route("/log")
@app.route("/log/<num_lines>")
def show_log(num_lines=20):
    ret = tail(LOG_FILENAME, num_lines)
    return error(f"could not read log: {LOG_FILENAME}") if ret is None \
        else success(data=ret)

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

    cr = CommandRunner(["mount", mount_device, mount_target], block=True)
    return success(cr.info(), data=cr.output)

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

    cr = CommandRunner(["umount", mount_target], block=True)
    return success(cr.info(), data=cr.output)

def check_for_backup_process():
    global backup_proc

    out = dict(cfg["backup"])
    if backup_proc is None:
        out["running"] = False
        return out

    assert isinstance(backup_proc, CommandRunner)

    if backup_proc.finished:
        if backup_proc.returncode == 0:
            backup_proc.parsed["state"] = "finished"
            cfg["backup"]["last_" + backup_proc.user_info] = backup_proc.started
            save_config(cfg, CONFIG_PATH)
            out["last_" + backup_proc.user_info] = backup_proc.started
            log.info("backup/restore process finished successfully")
        else:
            backup_proc.parsed["state"] = "failed: " + backup_proc.parsed.get("unable", "")
            if "target" in backup_proc.parsed:
                shutil.rmtree(backup_proc.parsed["target"])
                log.error("backup/restore process failed, logging output: ")
                for line in backup_proc.output:
                    log.error(line)

    out.update(dict(backup_proc.parsed))
    out["returncode"] = backup_proc.returncode
    out["running"] = backup_proc.running
    out["what"] = backup_proc.user_info
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

    #backup_proc = subprocess.Popen(,
    #    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    backup_proc = CommandRunner(["nextcloud-nextbox.export"],
        cb_parse=parse_backup_line, block=False)
    backup_proc.user_info = "backup"

    #backup_state["what"] = "backup"
    #backup_state["when"] = time.time()

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
    backup_proc = CommandRunner(["nextcloud-nextbox.import", directory],
        cb_parse=parse_backup_line, block=False)
    backup_proc.user_info = "restore"

    #backup_state["what"] = "restore"
    #backup_state["when"] = time.time()

    return success("restore started", data=backup_info)



@app.route("/service/<name>/<operation>")
#@requires_auth
def service_operation(name, operation):
    if name not in ["ddclient"]:
        return error("not allowed")
    if operation not in ["stop", "start", "restart", "status"]:
        return error("not allowed")

    if name == "ddclient":
        cr = CommandRunner(["systemctl", operation, DDCLIENT_SERVICE], block=True)
        return success(f"service '{name}' => {operation} return-code: {cr.returncode}",
                       data=cr.output)

    return error("not allowed")


@app.route("/ddclient/config")
@requires_auth
def ddclient_config():
    if request.method == 'GET':

        pass
    if request.method == 'POST':
        form_data = request.form


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18585, debug=True, threaded=True, processes=1)


# @todo: CORS whitelist origins (and handle whitelist)
######### -> better: token should als get it's IP passed, and this ip is then CORS whitelisted

# @todo: hostname, nextcloud (http, https), listen
# @todo: derive secret key -> machine-id (maybe only as flask-secret, not for hashing?)
# @todo: handle multiple backup processes (needed?)
# @todo: validate (mount) name (partly done, enough?)
# @fixme: thread-locks ?

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
# @todo: logging!=!==! (jap use logging + log.bla(iofje))
# @todo: "executor"-class or handler, two types currently, should be just one with:
#        - background job (Popen)
#        - read/digest all outputs (Popen + select)
#        - get returncode + non-blocking
