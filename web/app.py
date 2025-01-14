#!/usr/bin/env python3
import os
import json
import subprocess
from flask import Flask, request, jsonify, render_template
# (Optional) For improved logging or cross-origin resource sharing:
# from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
# CORS(app)  # Uncomment if you want to allow cross-origin requests during development

# Directory for scanning .o files (adjust as needed)
EBPF_SRC_DIR = os.path.abspath("ebpf/src")

def make_absolute_pin_path(pin_path):
    """
    If pin_path is not absolute (does not start with '/'), assume it's relative to /sys/fs/bpf
    """
    if not pin_path.startswith("/"):
        return os.path.join("/sys/fs/bpf", pin_path)
    return pin_path

@app.route("/")
def home():
    """Serve the advanced UI in index.html."""
    return render_template("index.html")

@app.route("/api/programs", methods=["GET"])
def list_programs():
    """
    Returns JSON:
    {
      "programs": [...],  # .o files from EBPF_SRC_DIR
      "loaded": [...],    # loaded programs from bpftool prog show --json
    }
    """
    try:
        programs = [
            f for f in os.listdir(EBPF_SRC_DIR)
            if f.endswith(".o") and os.path.isfile(os.path.join(EBPF_SRC_DIR, f))
        ]
        loaded_programs = get_loaded_programs()
        return jsonify({"programs": programs, "loaded": loaded_programs})
    except Exception as e:
        app.logger.error(f"Failed to list programs: {str(e)}")
        return jsonify({"error": f"Failed to list programs: {str(e)}"}), 500

@app.route("/api/programs/load", methods=["POST"])
def load_program():
    """
    Expects JSON like:
    {
      "program": "myprog.bpf.o",      # .o file in ebpf/src (with .bpf.o suffix)
      "pin_path": "myprog" or "/sys/fs/bpf/myprog"  
                                       (optional; if not absolute, will be relative to /sys/fs/bpf)
    }
    This endpoint always uses bpftool's loadall mode, so that all programs in the object file are loaded 
    and pinned under the provided pin_path (which is treated as a directory). The default pin name is derived 
    from the program name with the trailing ".bpf.o" removed.
    """
    data = request.get_json() or {}

    # Validate required parameter.
    program = data.get("program")
    if not program:
        return jsonify({"error": "Missing 'program' (.o file)"}), 400

    # Ensure the program file has the correct suffix.
    if not program.endswith(".bpf.o"):
        return jsonify({"error": "Invalid program file. Expected a .bpf.o file"}), 400

    # Build the full path to the .o file.
    program_path = os.path.join(EBPF_SRC_DIR, program)
    if not os.path.isfile(program_path):
        return jsonify({"error": f".o file not found: {program_path}"}), 404

    # Create a default pin name by removing the trailing '.bpf.o' from the program name.
    default_pin = program[:-len(".bpf.o")]

    # Get the pin_path parameter (if provided) or use default.
    # For loadall, the pin_path will be treated as a directory (prefix).
    pin_path = data.get("pin_path") or f"/sys/fs/bpf/{default_pin}"
    pin_path = make_absolute_pin_path(pin_path)

    # Ensure the pin_path directory exists.
    try:
        os.makedirs(pin_path, exist_ok=True)
    except OSError as e:
        app.logger.error(f"[LOAD PROGRAM ERROR] Failed to create pin path: {e}")
        return jsonify({"error": f"Failed to create pin path: {str(e)}"}), 500

    # Build the command using loadall.
    cmd = ["bpftool", "prog", "loadall", program_path, pin_path]

    app.logger.debug(f"Running command: {' '.join(['sudo'] + cmd)}")
    print(f"Running command: {' '.join(['sudo'] + cmd)}")
    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[LOAD PROGRAM] stdout: {result.stdout}")
        app.logger.debug(f"[LOAD PROGRAM] stderr: {result.stderr}")
        return jsonify({
            "message": f"Loaded {program} at {pin_path} using loadall mode"
        }), 200
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "Unknown error"
        app.logger.error(f"[LOAD PROGRAM ERROR] {error_message}")
        return jsonify({"error": f"Failed to load: {error_message}"}), 500

@app.route("/api/programs/unload", methods=["POST"])
def unload_program():
    """
    Expects JSON with either:
      { "program": "myprog.o" } => uses default pin path /sys/fs/bpf/<default_pin>
    or
      { "pin_path": "/sys/fs/bpf/myprog" }
    We'll run:
      bpftool prog unload <pin_path>
    """
    data = request.get_json() or {}
    pin_path = data.get("pin_path")
    program = data.get("program")

    if not pin_path and program:
        default_pin = os.path.splitext(program)[0]
        pin_path = f"/sys/fs/bpf/{default_pin}"

    if not pin_path:
        return jsonify({"error": "No pin_path or program provided"}), 400

    # Ensure the pin_path is absolute.
    pin_path = make_absolute_pin_path(pin_path)

    if not os.path.exists(pin_path):
        return jsonify({"error": f"Pin path not found: {pin_path}"}), 404

    cmd = ["bpftool", "prog", "unload", pin_path]
    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[UNLOAD PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({"message": f"Unloaded pinned program {pin_path}"}), 200
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "Unknown error"
        app.logger.error(f"[UNLOAD PROGRAM ERROR] {error_message}")
        return jsonify({"error": f"Failed to unload: {error_message}"}), 500

@app.route("/api/programs/attach", methods=["POST"])
def attach_program():
    """
    Expects JSON:
    {
      "pin_path": "/sys/fs/bpf/myprog",
      "attach_type": "tracepoint" or "xdp",
      "target": "...tracepoint path..." or interface for xdp
    }
    """
    data = request.get_json() or {}
    pin_path = data.get("pin_path")
    attach_type = data.get("attach_type", "")
    target = data.get("target", "")

    if not pin_path:
        return jsonify({"error": "Missing 'pin_path'"}), 400

    # Ensure the pin_path is absolute.
    pin_path = make_absolute_pin_path(pin_path)

    # Use default attach_type if not provided
    if not attach_type:
        attach_type = "tracepoint"

    # Provide a default target if not specified
    if not target:
        if attach_type == "tracepoint":
            target = "tracepoint/syscalls/sys_enter_execve"
        elif attach_type == "xdp":
            target = "eth0"

    # Construct bpftool command based on attach_type
    if attach_type == "tracepoint":
        cmd = [
            "bpftool", "prog", "attach",
            "pinned", pin_path,
            "tracepoint", target
        ]
    elif attach_type == "xdp":
        # Correct ordering: device first, then pinned
        cmd = [
            "bpftool", "net", "attach",
            "xdp", "dev", target,
            "pinned", pin_path
        ]
    else:
        return jsonify({"error": f"Unsupported attach_type: {attach_type}"}), 400

    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[ATTACH PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({"message": f"Attached {pin_path} => {attach_type}:{target}"}), 200
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "Unknown error"
        app.logger.error(f"[ATTACH PROGRAM ERROR] {error_message}")
        return jsonify({"error": f"Attach failed: {error_message}"}), 500

@app.route("/api/programs/detach", methods=["POST"])
def detach_program():
    """
    Expects JSON:
    {
      "pin_path": "/sys/fs/bpf/myprog",  # for tracepoint detach (required)
      "attach_type": "tracepoint" or "xdp",
      "target": "...tracepoint path..." or interface for xdp
    }
    For tracepoints, we'll run:
      bpftool prog detach pinned <pin_path> tracepoint <target>
    For XDP, we'll run:
      bpftool net detach xdp dev <target>
    """
    data = request.get_json() or {}
    pin_path = data.get("pin_path")
    attach_type = data.get("attach_type", "")
    target = data.get("target", "")

    if not pin_path:
        return jsonify({"error": "Missing 'pin_path'"}), 400

    if not attach_type:
        return jsonify({"error": "Missing 'attach_type'"}), 400

    # Ensure the pin_path is absolute.
    pin_path = make_absolute_pin_path(pin_path)

    # Provide a default target if not specified
    if not target:
        if attach_type == "tracepoint":
            target = "tracepoint/syscalls/sys_enter_execve"
        elif attach_type == "xdp":
            target = "eth0"

    if attach_type == "tracepoint":
        cmd = [
            "bpftool", "prog", "detach",
            "pinned", pin_path,
            "tracepoint", target
        ]
    elif attach_type == "xdp":
        # bpftool net detach xdp for a device does not use 'pinned'
        cmd = [
            "bpftool", "net", "detach",
            "xdp", "dev", target
        ]
    else:
        return jsonify({"error": f"Unsupported attach_type: {attach_type}"}), 400

    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[DETACH PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({"message": f"Detached {pin_path} from {attach_type}:{target}"}), 200
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "Unknown error"
        app.logger.error(f"[DETACH PROGRAM ERROR] {error_message}")
        return jsonify({"error": f"Detach failed: {error_message}"}), 500

def get_loaded_programs():
    """Return loaded eBPF programs with detailed information."""
    try:
        cmd = ["bpftool", "prog", "show", "--json"]
        result = subprocess.run(["sudo"] + cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        loaded = []
        for prog in data:
            loaded.append({
                "id": prog.get("id"),
                "name": prog.get("name"),
                "type": prog.get("type"),
                "pinned": prog.get("pinned"),  # Some programs might have a pinned path
                "tag": prog.get("tag"),
                "gpl_compatible": prog.get("gpl_compatible", False),
                "loaded_at": prog.get("loaded_at"),
                "uid": prog.get("uid"),
                "orphaned": prog.get("orphaned", False),
                "bytes_xlated": prog.get("bytes_xlated"),
                "jited": prog.get("jited", False),
                "bytes_jited": prog.get("bytes_jited"),
                "bytes_memlock": prog.get("bytes_memlock"),
                "map_ids": prog.get("map_ids", []),
                "btf_id": prog.get("btf_id")
            })
        return loaded
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.strip() if e.stderr else "Unknown error"
        app.logger.error(f"[ERROR] bpftool prog show: {error_message}")
        return []
    except json.JSONDecodeError as e:
        app.logger.error(f"[ERROR] JSON decode: {str(e)}")
        return []

if __name__ == "__main__":
    # For production, consider using a proper production server like gunicorn
    app.run(host="127.0.0.1", port=5000, debug=True)
