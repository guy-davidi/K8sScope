#!/usr/bin/python3
import os
import subprocess
from datetime import datetime

def log_message(message):
    """Log messages with timestamps."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")

def run_command(command, description):
    """Run a shell command with logging."""
    try:
        log_message(f"Starting: {description}")
        subprocess.run(command, shell=True, check=True)
        log_message(f"Completed: {description}")
    except subprocess.CalledProcessError as e:
        log_message(f"Error during {description}: {e}")

def set_permissions_recursively():
    """Set 755 permissions recursively for the parent directory."""
    try:
        parent_dir = os.path.abspath(os.path.join(os.getcwd(), "../"))
        log_message(f"Setting 755 permissions for all files and directories in: {parent_dir}")
        
        for root, dirs, files in os.walk(parent_dir):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)
            for f in files:
                os.chmod(os.path.join(root, f), 0o755)
        
        log_message("Permissions set successfully.")
    except Exception as ex:
        log_message(f"Unexpected error during permission setting: {ex}")

def copy_library_file():
    """Copy libbpf.so.1 to /usr/lib/x86_64-linux-gnu/."""
    try:
        source = "/usr/lib64/libbpf.so.1"
        destination = "/usr/lib/x86_64-linux-gnu/"
        
        log_message(f"Copying {source} to {destination}")
        
        # Ensure source file exists before copying
        if not os.path.exists(source):
            raise FileNotFoundError(f"Source file does not exist: {source}")
        
        run_command(f"sudo cp {source} {destination}", "Copying libbpf.so.1 library")
        
        log_message("Library file copied successfully.")
    except FileNotFoundError as fnf_error:
        log_message(str(fnf_error))
    except Exception as ex:
        log_message(f"Unexpected error during library file copy: {ex}")

def upgrade_system_and_install_dependencies():
    """Upgrade the system and install required dependencies."""
    run_command("sudo apt upgrade -y", "Upgrading the system")
    
    dependencies = (
        "git build-essential clang gcc make libelf-dev zlib1g-dev libcap-dev pkg-config"
    )
    
    run_command(f"sudo apt install -y {dependencies}", "Installing additional dependencies")

def install_flask():
    """Install Flask."""
    run_command("pip3 install Flask", "Installing Flask")

def install_bpftool():
    """Install bpftool and add it to PATH."""
    run_command(
        "sudo apt update && sudo apt install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)",
        "Installing bpftool"
    )
    
    bpftool_path = f"/usr/lib/linux-tools/{os.uname().release}/bpftool"
    if os.path.exists(bpftool_path):
        os.environ["PATH"] += os.pathsep + bpftool_path
        with open(os.path.expanduser("~/.bashrc"), "a") as bashrc:
            bashrc.write(f"\nexport PATH=$PATH:{bpftool_path}\n")
        log_message(f"bpftool added to PATH: {bpftool_path}")
    else:
        log_message(f"bpftool binary not found at {bpftool_path}.")

def install_clang():
    """Install Clang."""
    run_command("sudo apt update && sudo apt install -y clang", "Installing Clang")

def update_git_submodules():
    """Run 'git submodule update --init --recursive' from '../' path."""
    try:
        target_path = os.path.abspath(os.path.join(os.getcwd(), "../"))
        log_message(f"Changing directory to: {target_path}")
        
        os.chdir(target_path)
        
        run_command("git submodule update --init --recursive", "Updating git submodules")
    except Exception as ex:
        log_message(f"Unexpected error during git submodule update: {ex}")

def build_and_install_libbpf():
    """Navigate to libbpf/src and run 'sudo make install'."""
    try:
        libbpf_src_path = os.path.abspath(os.path.join(os.getcwd(), "libs/libbpf/src"))
        log_message(f"Changing directory to: {libbpf_src_path}")
        
        os.chdir(libbpf_src_path)
        
        run_command("sudo make install", "Building and installing libbpf")
        
        log_message("libbpf installed successfully.")
    except Exception as ex:
        log_message(f"Unexpected error during libbpf installation: {ex}")

def main():
    """Main function to execute all tasks."""
    upgrade_system_and_install_dependencies()
    install_flask()
    install_bpftool()
    install_clang()
    update_git_submodules()
    build_and_install_libbpf()
    set_permissions_recursively()
    copy_library_file()
    log_message("Setup completed.")

if __name__ == "__main__":
    main()
