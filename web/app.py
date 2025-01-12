#!/usr/bin/env python3
import os
import json
import subprocess
from flask import Flask, request, jsonify, render_template
# (Optional) For improved logging or cross-origin resource sharing:
# from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
# CORS(app)  # If you want to allow cross-origin requests for dev

EBPF_SRC_DIR = os.path.abspath("ebpf/src")  # Directory for scanning .o files

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
      "loaded": [...],    # from bpftool prog show --json
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
      "program": "myprog.o",       # .o file in ebpf/src
      "pin_path": "/sys/fs/bpf/myprog" (optional),
      "type": "tracepoint" (optional)
    }
    We'll run:
      bpftool prog load <ebpf/src/program> <pin_path> [type <type>]
    """
    data = request.get_json() or {}
    program = data.get("program")
    if not program:
        return jsonify({"error": "Missing 'program' (.o file)"}), 400

    program_path = os.path.join(EBPF_SRC_DIR, program)
    if not os.path.isfile(program_path):
        return jsonify({"error": f".o file not found: {program_path}"}), 404

    pin_path = data.get("pin_path") or f"/sys/fs/bpf/{program}"
    prog_type = data.get("type")

    # If pinned file already exists, it's often an error, but depends on your logic
    if os.path.exists(pin_path):
        return jsonify({"error": f"Program is already pinned at {pin_path}"}), 400

    cmd = ["bpftool", "prog", "load", program_path, pin_path]
    if prog_type:
        cmd += ["type", prog_type]

    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[LOAD PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({
            "message": f"Loaded {program} at {pin_path} (type={prog_type or 'auto'})"
        }), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"[LOAD PROGRAM ERROR] {e.stderr.strip()}")
        return jsonify({"error": f"Failed to load: {e.stderr.strip()}"}), 500

@app.route("/api/programs/unload", methods=["POST"])
def unload_program():
    """
    Expects JSON with either:
      { "program": "myprog.o" } => pin path /sys/fs/bpf/<program>
    or
      { "pin_path": "/sys/fs/bpf/myprog" }
    We'll run:
      bpftool prog unload <pin_path>
    """
    data = request.get_json() or {}
    pin_path = data.get("pin_path")
    program = data.get("program")

    if not pin_path and program:
        pin_path = f"/sys/fs/bpf/{program}"

    if not pin_path:
        return jsonify({"error": "No pin_path or program provided"}), 400

    if not os.path.exists(pin_path):
        return jsonify({"error": f"Pin path not found: {pin_path}"}), 404

    cmd = ["bpftool", "prog", "unload", pin_path]
    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[UNLOAD PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({"message": f"Unloaded pinned program {pin_path}"}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"[UNLOAD PROGRAM ERROR] {e.stderr.strip()}")
        return jsonify({"error": f"Failed to unload: {e.stderr.strip()}"}), 500

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

    if not attach_type:
        # Provide a default attach_type
        attach_type = "tracepoint"

    if not target:
        if attach_type == "tracepoint":
            target = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve"
        elif attach_type == "xdp":
            target = "eth0"

    if attach_type == "tracepoint":
        cmd = [
            "bpftool", "prog", "attach",
            "pinned", pin_path,
            "tracepoint", target
        ]
    elif attach_type == "xdp":
        cmd = [
            "bpftool", "net", "attach",
            "xdp", "pinned", pin_path,
            "dev", target
        ]
    else:
        return jsonify({"error": f"Unsupported attach_type: {attach_type}"}), 400

    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[ATTACH PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({"message": f"Attached {pin_path} => {attach_type}:{target}"}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"[ATTACH PROGRAM ERROR] {e.stderr.strip()}")
        return jsonify({"error": f"Attach failed: {e.stderr.strip()}"}), 500

@app.route("/api/programs/detach", methods=["POST"])
def detach_program():
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

    if not attach_type:
        return jsonify({"error": "Missing 'attach_type'"}), 400

    if not target:
        if attach_type == "tracepoint":
            target = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve"
        elif attach_type == "xdp":
            target = "eth0"

    if attach_type == "tracepoint":
        cmd = [
            "bpftool", "prog", "detach",
            "pinned", pin_path,
            "tracepoint", target
        ]
    elif attach_type == "xdp":
        cmd = [
            "bpftool", "net", "detach",
            "xdp", "dev", target,
            "pinned", pin_path
        ]
    else:
        return jsonify({"error": f"Unsupported attach_type: {attach_type}"}), 400

    try:
        result = subprocess.run(["sudo"] + cmd, check=True, capture_output=True, text=True)
        app.logger.debug(f"[DETACH PROGRAM] cmd: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return jsonify({"message": f"Detached {pin_path} from {attach_type}:{target}"}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"[DETACH PROGRAM ERROR] {e.stderr.strip()}")
        return jsonify({"error": f"Detach failed: {e.stderr.strip()}"}), 500

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
        app.logger.error(f"[ERROR] bpftool prog show: {e.stderr.strip()}")
        return []
    except json.JSONDecodeError as e:
        app.logger.error(f"[ERROR] JSON decode: {str(e)}")
        return []

if __name__ == "__main__":
    # For production, consider using a proper production server like gunicorn
    app.run(host="127.0.0.1", port=5000, debug=True)
