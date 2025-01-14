// main.js

// Run once the DOM is fully loaded
document.addEventListener("DOMContentLoaded", () => {
  console.log("[DEBUG] DOM Content Loaded. Fetching programs...");
  fetchPrograms();

  // Set up form submission handler explicitly in case it’s not guaranteed in HTML
  const ebpfForm = document.getElementById("ebpf-form");
  if (ebpfForm) {
    ebpfForm.addEventListener("submit", handleFormSubmit);
  } else {
    console.error("[DEBUG] ebpf-form element not found.");
  }
});

// Show or hide the loading spinner
function showLoading(show) {
  const spinner = document.querySelector(".loading");
  if (!spinner) return;
  spinner.style.display = show ? "block" : "none";
}

// Show a Bootstrap 5 toast message
function showToast(message, isError = false) {
  console.log(`[DEBUG] Toast: ${message} (isError=${isError})`);
  const toastContainer = document.getElementById("toastContainer");
  if (!toastContainer) {
    console.error("[DEBUG] toastContainer element not found.");
    return;
  }

  const toastEl = document.createElement("div");
  toastEl.className =
    "toast align-items-center text-bg-" + (isError ? "danger" : "success");
  toastEl.role = "alert";
  toastEl.ariaLive = "assertive";
  toastEl.ariaAtomic = "true";

  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        ${message}
      </div>
      <button
        type="button"
        class="btn-close btn-close-white me-2 m-auto"
        data-bs-dismiss="toast"
        aria-label="Close"
      ></button>
    </div>
  `;

  toastContainer.appendChild(toastEl);

  // Automatically remove the toast from the DOM after it's hidden
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();
  bsToast._element.addEventListener("hidden.bs.toast", () => {
    toastEl.remove();
  });
}

// Fetch the list of .o files & loaded eBPF programs
async function fetchPrograms() {
  console.log("[DEBUG] fetchPrograms() called");
  showLoading(true);
  try {
    const res = await fetch("/api/programs");
    console.log("[DEBUG] fetchPrograms response status:", res.status);
    if (!res.ok) {
      const errorMsg = await res.text();
      showToast(`Failed to fetch programs: ${errorMsg}`, true);
      return;
    }
    const data = await res.json();
    console.log("[DEBUG] fetchPrograms data:", data);
    updateOFileList(data.programs || []);
    updateLoadedTable(data.loaded || []);
  } catch (err) {
    console.error("[DEBUG] fetchPrograms error:", err);
    showToast("Error fetching programs: " + err.message, true);
  } finally {
    showLoading(false);
  }
}

// Populate the .o file list
function updateOFileList(programs) {
  const listEl = document.getElementById("o-file-list");
  if (!listEl) return;

  listEl.innerHTML = "";
  if (programs.length === 0) {
    const li = document.createElement("li");
    li.className = "list-group-item text-muted";
    li.textContent = "No .o files found in ebpf/src.";
    listEl.appendChild(li);
    return;
  }

  // Create a list item for each .o file
  programs.forEach((prog) => {
    const li = document.createElement("li");
    li.className =
      "list-group-item d-flex justify-content-between align-items-center";
    li.textContent = prog;
    li.style.cursor = "pointer";

    // On click, fill the program input field with the file name
    li.addEventListener("click", () => {
      document.getElementById("programInput").value = prog;
    });

    listEl.appendChild(li);
  });
}

// Populate the loaded eBPF program table with collapsible details
function updateLoadedTable(loaded) {
  const tbody = document.getElementById("loaded-table-body");
  if (!tbody) return;

  tbody.innerHTML = "";

  if (loaded.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No loaded programs found.";
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }

  loaded.forEach((prog, index) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${prog.id}</td>
      <td>${prog.name}</td>
      <td>${prog.type}</td>
      <td>${prog.pinned || "Not pinned"}</td>
      <td>
        <button class="btn btn-sm btn-info" data-bs-toggle="collapse" data-bs-target="#details-${index}">
          Details
        </button>
      </td>
    `;

    const detailsRow = document.createElement("tr");
    detailsRow.innerHTML = `
      <td colspan="5">
        <div id="details-${index}" class="collapse">
          <ul class="list-group list-group-flush">
            <li class="list-group-item"><strong>Tag:</strong> ${prog.tag}</li>
            <li class="list-group-item">
              <strong>GPL Compatible:</strong>
              <span class="badge bg-${prog.gpl_compatible ? "success" : "danger"}">
                ${prog.gpl_compatible ? "Yes" : "No"}
              </span>
            </li>
            <li class="list-group-item">
              <strong>Loaded At:</strong> 
              ${new Date(prog.loaded_at * 1000).toLocaleString()}
            </li>
            <li class="list-group-item"><strong>UID:</strong> ${prog.uid}</li>
            <li class="list-group-item">
              <strong>Orphaned:</strong> 
              <span class="badge bg-${prog.orphaned ? "warning" : "secondary"}">
                ${prog.orphaned ? "Yes" : "No"}
              </span>
            </li>
            <li class="list-group-item">
              <strong>Bytes Translated:</strong> ${prog.bytes_xlated}
            </li>
            <li class="list-group-item">
              <strong>JITed:</strong> 
              <span class="badge bg-${prog.jited ? "primary" : "secondary"}">
                ${prog.jited ? "Yes" : "No"}
              </span>
            </li>
            <li class="list-group-item">
              <strong>Bytes JITed:</strong> ${prog.bytes_jited}
            </li>
            <li class="list-group-item">
              <strong>Bytes Memlock:</strong> ${prog.bytes_memlock}
            </li>
            <li class="list-group-item">
              <strong>Map IDs:</strong> ${prog.map_ids.join(", ") || "None"}
            </li>
            <li class="list-group-item">
              <strong>BTF ID:</strong> ${prog.btf_id}
            </li>
          </ul>
        </div>
      </td>
    `;

    tbody.appendChild(row);
    tbody.appendChild(detailsRow);
  });
}

// Single form submission handler
async function handleFormSubmit(e) {
  e.preventDefault();
  showLoading(true);
  console.log("[DEBUG] Form submission triggered");
  const action = document.getElementById("action").value;
  const program = document.getElementById("programInput").value.trim();
  const pinPath = document.getElementById("pinPath").value.trim();
  const typeVal = document.getElementById("typeInput").value.trim();
  const targetVal = document.getElementById("targetInput").value.trim();

  try {
    if (action === "load") {
      console.log("[DEBUG] Calling doLoad with:", { program, pinPath, typeVal });
      await doLoad(program, pinPath, typeVal);
    } else if (action === "unload") {
      console.log("[DEBUG] Calling doUnload with:", { program, pinPath });
      await doUnload(program, pinPath);
    } else if (action === "attach") {
      console.log("[DEBUG] Calling doAttach with:", { pinPath, typeVal, targetVal });
      await doAttach(pinPath, typeVal, targetVal);
    } else if (action === "detach") {
      console.log("[DEBUG] Calling doDetach with:", { pinPath, typeVal, targetVal });
      await doDetach(pinPath, typeVal, targetVal);
    } else {
      showToast("Unknown action: " + action, true);
      console.error("[DEBUG] Unknown action:", action);
    }

    // Refresh the .o files and loaded programs
    await fetchPrograms();
  } catch (err) {
    console.error("[DEBUG] Error in form submission:", err);
    showToast("Error: " + err.message, true);
  } finally {
    showLoading(false);
  }
}

// Action Helpers

async function doLoad(program, pinPath, progType) {
  console.log("[DEBUG] doLoad called with:", { program, pinPath, progType });
  if (!program) {
    showToast("Please select or type a .o file name", true);
    throw new Error("No program specified");
  }
  
  const body = { program };
  if (pinPath) body.pin_path = pinPath;
  if (progType) body.type = progType;

  console.log("[DEBUG] Sending load request body:", body);
  
  const res = await fetch("/api/programs/load", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  console.log("[DEBUG] doLoad response:", data);
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Load failed");
  }
  showToast(data.message || "Program loaded");
}

async function doUnload(program, pinPath) {
  console.log("[DEBUG] doUnload called with:", { program, pinPath });
  const body = {};
  if (pinPath) {
    body.pin_path = pinPath;
  } else if (program) {
    body.program = program;
  } else {
    showToast("Provide a pinPath or program name to unload", true);
    throw new Error("No unload path or program");
  }

  console.log("[DEBUG] Sending unload request with body:", body);
  
  const res = await fetch("/api/programs/unload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  console.log("[DEBUG] doUnload response:", data);
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Unload failed");
  }
  showToast(data.message || "Program unloaded");
}

async function doAttach(pinPath, attachType, target) {
  console.log("[DEBUG] doAttach called with:", { pinPath, attachType, target });
  
  // If no pinPath is provided, attempt to derive one from the program input.
  if (!pinPath) {
    const program = document.getElementById("programInput").value.trim();
    if (program) {
      let defaultPin = program;
      if (defaultPin.endsWith(".bpf.o")) {
        defaultPin = defaultPin.slice(0, -6); // Remove trailing ".bpf.o"
      } else {
        defaultPin = defaultPin.split('.')[0];
      }
      pinPath = "/sys/fs/bpf/" + defaultPin;
      console.log("[DEBUG] Using fallback pinPath:", pinPath);
    } else {
      showToast("Pin path required for attach", true);
      throw new Error("No pin path");
    }
  }

  // Set default attachType if not provided.
  if (!attachType) {
    attachType = "xdp"; // Default to xdp if not specified
    console.log("[DEBUG] Defaulting attachType to 'xdp'");
  }

  // Set default target based on attachType if target is not provided.
  if (!target) {
    if (attachType.toLowerCase() === "xdp") {
      target = "eth0";
      console.log("[DEBUG] Defaulting target to 'eth0' for xdp");
    } else if (attachType.toLowerCase() === "tracepoint") {
      target = "tracepoint/syscalls/sys_enter_execve";
      console.log("[DEBUG] Defaulting target to 'tracepoint/syscalls/sys_enter_execve' for tracepoint");
    }
  }
  
  const body = { pin_path: pinPath, attach_type: attachType, target: target };
  console.log("[DEBUG] Sending attach request with body:", body);
  
  const res = await fetch("/api/programs/attach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  console.log("[DEBUG] doAttach response:", data);
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Attach failed");
  }
  showToast(data.message || "Program attached");
}

async function doDetach(pinPath, attachType, target) {
  console.log("[DEBUG] doDetach called with:", { pinPath, attachType, target });
  if (!pinPath) {
    showToast("Pin path required for detach", true);
    throw new Error("No pin path");
  }
  if (!attachType) {
    showToast("attach_type required for detach", true);
    throw new Error("No attach type");
  }
  const body = { pin_path: pinPath, attach_type: attachType };
  if (target) body.target = target;
  
  console.log("[DEBUG] Sending detach request with body:", body);
  
  const res = await fetch("/api/programs/detach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  console.log("[DEBUG] doDetach response:", data);
  if (!res.ok || data.error) {
    showToast(data.error || data.message || "Unknown error", true);
    throw new Error(data.error || data.message || "Detach failed");
  }
  showToast(data.message || "Program detached");
}
