#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template
import os
import subprocess

app = Flask(__name__, template_folder='templates')
EBPF_DIR = os.path.abspath("../ebpf")

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/programs', methods=['GET'])
def list_programs():
    try:
        programs = [f for f in os.listdir(EBPF_DIR) if f.endswith('.o')]
        loaded_programs = get_loaded_programs()
        return jsonify({"programs": programs, "loaded": loaded_programs})
    except Exception as e:
        return jsonify({"programs": [], "loaded": [], "error": str(e)}), 500

@app.route('/api/programs/load', methods=['POST'])
def load_program():
    program = request.json.get('program')
    program_path = os.path.join(EBPF_DIR, program)

    if not os.path.isfile(program_path):
        return jsonify({"error": "Program not found"}), 404

    try:
        subprocess.run(["bpftool", "prog", "load", program_path, "/sys/fs/bpf/" + program], check=True)
        return jsonify({"message": f"Program {program} loaded successfully"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to load program {program}: {str(e)}"}), 500

@app.route('/api/programs/unload', methods=['POST'])
def unload_program():
    program = request.json.get('program')
    try:
        subprocess.run(["bpftool", "prog", "unload", "/sys/fs/bpf/" + program], check=True)
        return jsonify({"message": f"Program {program} unloaded successfully"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to unload program {program}: {str(e)}"}), 500

def get_loaded_programs():
    """Get a list of loaded eBPF programs using bpftool."""
    try:
        result = subprocess.run(["bpftool", "prog", "show"], capture_output=True, text=True, check=True)
        return result.stdout.splitlines() if result.stdout else []
    except subprocess.CalledProcessError:
        return []

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
