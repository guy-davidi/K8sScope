# eBPF Program Manager

This project provides an intuitive and feature-rich web-based UI to manage eBPF programs. It allows users to load, unload, attach, and detach eBPF programs with ease, and displays detailed information about currently loaded eBPF programs.

## Features

1. **Dynamic Listing of eBPF Programs**:
   - Automatically lists available `.o` files from the `ebpf/src` directory.
   - Shows currently loaded eBPF programs with detailed information.

2. **Comprehensive Management**:
   - Supports loading eBPF programs with optional pin paths and types.
   - Enables attaching and detaching eBPF programs to/from tracepoints and XDP.
   - Provides options to unload pinned eBPF programs.

3. **Expandable Program Details**:
   - Displays key fields (ID, name, type, pinned status) in a table.
   - Expands rows to show additional details, such as `bytes_xlated`, `map_ids`, and `btf_id`.

4. **Interactive UI**:
   - Bootstrap 5-based design for a responsive and modern look.
   - Toast notifications for success and error messages.
   - Loading spinner for better user experience.

## Getting Started

### Prerequisites

- **Python 3.8+**
- **Flask**
- **bpftool** (must be installed and available in the system's PATH)
- **eBPF Source Directory**: Ensure `.o` files are placed in the `ebpf/src` directory.

### Installation

1. Clone the repository:
   ```bash
   git clone git@github.com:guy-davidi/K8sScope.git
   cd eBPF-Program-Manager
   ```

2. Install the required Python packages:
   ```bash
   pip install Flask
   ```

3. Ensure `bpftool` is installed and accessible:
   ```bash
   sudo apt install bpftool
   ```

4. Create the `ebpf/src` directory and add your compiled eBPF `.o` files.

### Running the Application

1. Start the Flask server:
   ```bash
   python3 app.py
   ```

2. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

## Usage

### Load an eBPF Program
- Select or type the name of the `.o` file.
- Specify an optional pin path.
- Select the program type (e.g., `tracepoint`, `xdp`).
- Click **Execute**.

### Attach an eBPF Program
- Provide the pin path of the loaded program.
- Specify the attach type (`tracepoint`, `xdp`).
- Specify the target (e.g., tracepoint path or network interface).
- Click **Execute**.

### Unload an eBPF Program
- Provide the program name or pin path.
- Click **Execute**.

### Detach an eBPF Program
- Provide the pin path and attach type.
- Specify the target.
- Click **Execute**.

## File Structure

```plaintext
.
├── app.py               # Main Flask application
├── static
│   ├── main.js          # JavaScript for UI interactivity
│   └── style.css        # Custom styles (optional)
├── templates
│   └── index.html       # HTML template for the UI
└── ebpf
    └── src              # Directory for eBPF `.o` files
```

## Screenshots

### Home Page
![Home Page Screenshot](screenshots/home_page.png)

### Loaded Programs
![Loaded Programs Screenshot](screenshots/loaded_programs.png)

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your feature description"
   ```
4. Push the branch:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Bootstrap](https://getbootstrap.com/) for the UI framework.
- [Flask](https://flask.palletsprojects.com/) for the backend framework.
- [bpftool](https://man7.org/linux/man-pages/man8/bpftool.8.html) for managing eBPF programs.

---
Happy eBPFing!

