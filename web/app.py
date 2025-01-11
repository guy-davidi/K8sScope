#!/usr/bin/env python3
import os
import subprocess
import json
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates')

# Adjust this path as needed
EBPF_DIR = os.path.abspath("../ebpf")

@app.route('/')
def home():
    """Render the main web page."""
    return render_template("index.html")

@app.route('/api/programs', methods=['GET'])
def list_programs():
    """
    Returns a JSON with two arrays:
    - programs: eBPF object files found in EBPF_DIR
    - loaded: structured list of loaded eBPF programs from bpftool
    """
    try:
        # List local .o files
        programs = [f for f in os.listdir(EBPF_DIR) if f.endswith('.o')]
        
        # Get loaded programs as a structured list
        loaded_programs = get_loaded_programs()
        
        return jsonify({"programs": programs, "loaded": loaded_programs})
    except Exception as e:
        return jsonify({"error": f"Error listing programs: {str(e)}"}), 500

@app.route('/api/programs/load', methods=['POST'])
def load_program():
    """
    Loads (pins) an eBPF program into /sys/fs/bpf/<program>.
    Expects JSON with {"program": "my_program.o"}.
    """
    data = request.get_json()
    if not data or 'program' not in data:
        return jsonify({"error": "Missing 'program' field in request"}), 400

    program = data['program']
    program_path = os.path.join(EBPF_DIR, program)

    # Check if the file actually exists
    if not os.path.isfile(program_path):
        return jsonify({"error": f"Program file not found: {program}"}), 404

    # Check if the program is already pinned/loaded
    pinned_path = f"/sys/fs/bpf/{program}"
    if os.path.exists(pinned_path):
        return jsonify({"error": f"Program '{program}' is already pinned at {pinned_path}"}), 400

    # Attempt to load the program
    try:
        subprocess.run(
            ["bpftool", "prog", "load", program_path, pinned_path],
            check=True,
            capture_output=True,
            text=True
        )
        return jsonify({"message": f"Program '{program}' loaded successfully."}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to load '{program}': {e.stderr.strip()}"}), 500

@app.route('/api/programs/unload', methods=['POST'])
def unload_program():
    """
    Unloads (removes pin) for an eBPF program at /sys/fs/bpf/<program>.
    Expects JSON with {"program": "my_program.o"} or the pinned name.
    """
    data = request.get_json()
    if not data or 'program' not in data:
        return jsonify({"error": "Missing 'program' field in request"}), 400

    program = data['program']
    pinned_path = os.path.join("/sys/fs/bpf", program)

    if not os.path.exists(pinned_path):
        return jsonify({"error": f"No pinned program found at {pinned_path}"}), 404

    # Attempt to unload the program
    try:
        subprocess.run(
            ["bpftool", "prog", "unload", pinned_path],
            check=True,
            capture_output=True,
            text=True
        )
        return jsonify({"message": f"Program '{program}' unloaded successfully."}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to unload '{program}': {e.stderr.strip()}"}), 500

def get_loaded_programs():
    """
    Get a structured list of loaded eBPF programs using bpftool prog show --json.
    Returns a list of dicts with keys like:
      ["id", "tag", "type", "pinned", "name", "loaded_at", "run_time", ...]
    """
    try:
        result = subprocess.run(
            ["bpftool", "prog", "show", "--json"],
            capture_output=True,
            text=True,
            check=True
        )
        # Parse the JSON output from bpftool
        bpftool_data = json.loads(result.stdout)
        
        loaded_programs = []
        for prog in bpftool_data:
            loaded_programs.append({
                "id": prog.get("id"),
                "name": prog.get("name"),
                "type": prog.get("type"),
                "tag": prog.get("tag"),
                "pinned": prog.get("pinned"),
                "run_time_ns": prog.get("run_time_ns"),
                "run_cnt": prog.get("run_cnt")
            })
        return loaded_programs
    except subprocess.CalledProcessError:
        # bpftool might fail if no programs are loaded, etc.
        return []
    except json.JSONDecodeError:
        # If bpftool doesn't return valid JSON
        return []

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
