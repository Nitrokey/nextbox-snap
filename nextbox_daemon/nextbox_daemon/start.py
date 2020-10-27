import os
import sys
from pathlib import Path
import time
import subprocess
import threading
import psutil
from functools import wraps

# append proper site-packages path
sys.path.append(Path(__file__).parent.parent)


from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify

from utils import load_config, save_config, get_partitions, NEXTBOX_HDD_LABEL



#CONFIG_PATH = "/var/snap/nextbox/current/nextbox.conf"
CONFIG_PATH = "/tmp/nextbox.conf"

cfg = load_config(CONFIG_PATH)

app = Flask(__name__)
app.secret_key = "123456-nextbox-123456" #cfg["secret_key"]

# backup thread handler
backup_thread = None
backup_output = None


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
    return (username == cfg["user"] and cfg["password"] == make_pass(password)) \
        or (cfg["user"] is None and cfg["password"] is None)

def http_authenticate():
    return Response("No access!", 401, {
      "WWW-Authenticate": 'Basic realm="Login Required"'}
    )

# decorator for authenticated access
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth_global(auth.username, auth.password):
            return http_authenticate()
        return f(*args, **kwargs)
    return decorated

# dummy decorator for non-authenticated access
def no_auth(f):
    return f


@app.route("/logout")
def http_logout():
    return http_authenticate()


@app.route("/storage")
def storage():
    parts = get_partitions()
    return success(data=parts)


@app.route("/storage/mount/<device>/<name>")
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


def backup_job():
    global backup_output
    backup_output = subprocess.getoutput(f"nextcloud-nextbox.export")


def make_restore_job(directory):
    def restore_job():
        global backup_output
        backup_output = subprocess.getoutput(f"nextcloud-nextbox.import {directory}")
    return restore_job


def check_for_backup_process():
    global backup_thread, backup_output
    out = {"running": backup_thread is not None}
    for proc in psutil.process_iter():
        if proc.name() in ["nextcloud-nextbox.export", "nextcloud-nextbox.import"]:
            out["what"] = proc.name()
            out["started"] = proc.create_time()


    # if no process is running, assume it's over -> thus join and empty backup_thread
    if "what" not in out:
        if backup_thread:
            assert isinstance(backup_thread, threading.Thread)
            backup_thread.join()
            out["log"] = backup_output
        backup_thread = None
        backup_output = None
        out["running"] = False

    return out


@app.route("/backup")
def backup():
    data = cfg["backup"]
    data["operation"] = check_for_backup_process()
    return success(data=data)

#@app.route("/backup/cancel")
#def backup_cancel(name):
#    global backup_thread
#
#    subprocess.check_call(["killall", "nextcloud-nextbox.export"])
#    #subprocess.check_call(["killall", "nextcloud-nextbox.import"])
#
#    pass

@app.route("/backup/start/<name>")
def backup_start(name):
    global backup_thread
    backup_info = check_for_backup_process()

    if ".." in name or "/" in name:
        return error("invalid name", data=backup_info)

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    backup_thread = threading.Thread(target=backup_job)
    backup_thread.start()
    return success("backup started", data=backup_info)

@app.route("/backup/restore/<name>")
def backup_restore(name):
    global backup_thread
    backup_info = check_for_backup_process()

    if ".." in name or "/" in name:
        return error("invalid name", data=backup_info)

    if backup_info["running"]:
        return error("backup/restore operation already running", data=backup_info)

    directory = f"/media/backup/{name}"
    backup_thread = threading.Thread(target=make_restore_job(directory))
    backup_thread.start()

    return success("restore started", data=backup_info)

print("NextBox daemon")

if __name__ == "__main__":
    app.run(host=cfg["listen"]["host"], port=cfg["listen"]["port"], debug=True)



# @todo: password change
# @todo: hostname, nextcloud (http, https), listen
# @todo: derive secret key -> machine-id ?
# @todo: decorate with requires_auth
# @todo: handle multiple backup processes
# @todo: join thread with timeout
# @todo: validate (mount) name
# @fixme: thread-locks ?
# @todo: logging!=!==!


#### done:
# @todo: append sys.paths