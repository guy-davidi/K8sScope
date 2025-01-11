// main.js

document.addEventListener("DOMContentLoaded", () => {
    fetchPrograms();
  });
  
  // Show or hide the loading spinner
  function showLoading(show) {
    const loadingEl = document.querySelector(".loading");
    loadingEl.style.display = show ? "block" : "none";
  }
  
  // Fetch the list of programs
  async function fetchPrograms() {
    showLoading(true);
    try {
      const response = await fetch("/api/programs");
      const data = await response.json();
  
      if (data.error) {
        alert("Error: " + data.error);
        return;
      }
  
      const programs = data.programs || [];
      const loaded = data.loaded || [];
  
      updateProgramList(programs);
      updateLoadedPrograms(loaded);
    } catch (error) {
      alert("Error fetching programs: " + error.message);
    } finally {
      showLoading(false);
    }
  }
  
  // Populate the available eBPF programs list (the .o files)
  function updateProgramList(programs) {
    const programList = document.getElementById("program-list");
    programList.innerHTML = "";
    if (programs.length === 0) {
      programList.innerHTML =
        '<li class="list-group-item">No available programs found.</li>';
      return;
    }
    programs.forEach((program) => {
      const li = document.createElement("li");
      li.className = "list-group-item d-flex justify-content-between align-items-center";
      li.textContent = program;
  
      const button = document.createElement("button");
      button.className = "btn btn-primary btn-sm";
      button.textContent = "Load";
      button.onclick = () => loadProgram(program);
  
      li.appendChild(button);
      programList.appendChild(li);
    });
  }
  
  // Populate the loaded programs table with structured data
  function updateLoadedPrograms(loaded) {
    const tableBody = document.querySelector("#loaded-programs tbody");
    tableBody.innerHTML = "";
    if (loaded.length === 0) {
      const emptyRow = document.createElement("tr");
      const emptyCell = document.createElement("td");
      emptyCell.colSpan = 7;
      emptyCell.textContent = "No loaded programs found.";
      emptyRow.appendChild(emptyCell);
      tableBody.appendChild(emptyRow);
      return;
    }
  
    loaded.forEach((prog) => {
      const tr = document.createElement("tr");
  
      // ID
      const tdId = document.createElement("td");
      tdId.textContent = prog.id ?? "";
      tr.appendChild(tdId);
  
      // Program Name
      const tdName = document.createElement("td");
      tdName.textContent = prog.name ?? "";
      tr.appendChild(tdName);
  
      // Type
      const tdType = document.createElement("td");
      tdType.textContent = prog.type ?? "";
      tr.appendChild(tdType);
  
      // Pinned Path
      const tdPinned = document.createElement("td");
      tdPinned.textContent = prog.pinned ?? "";
      tr.appendChild(tdPinned);
  
      // Run Count
      const tdRunCount = document.createElement("td");
      tdRunCount.textContent = prog.run_cnt ?? "";
      tr.appendChild(tdRunCount);
  
      // Run Time (ns)
      const tdRunTime = document.createElement("td");
      tdRunTime.textContent = prog.run_time_ns ?? "";
      tr.appendChild(tdRunTime);
  
      // Action (Unload button)
      const tdAction = document.createElement("td");
      const unloadButton = document.createElement("button");
      unloadButton.className = "btn btn-danger btn-sm";
      unloadButton.textContent = "Unload";
  
      // Extract the pinned name from '/sys/fs/bpf/my_program.o'
      let pinnedPathSplit = prog.pinned ? prog.pinned.split("/") : [];
      let pinnedName = pinnedPathSplit[pinnedPathSplit.length - 1] || "";
  
      unloadButton.onclick = () => unloadProgram(pinnedName);
      tdAction.appendChild(unloadButton);
      tr.appendChild(tdAction);
  
      tableBody.appendChild(tr);
    });
  }
  
  // Load a program
  async function loadProgram(program) {
    showLoading(true);
    try {
      const response = await fetch("/api/programs/load", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ program }),
      });
  
      const data = await response.json();
      if (data.error) {
        alert("Error: " + data.error);
      } else {
        alert(data.message);
      }
      fetchPrograms();
    } catch (error) {
      alert("Error loading program: " + error.message);
    } finally {
      showLoading(false);
    }
  }
  
  // Unload a program
  async function unloadProgram(program) {
    showLoading(true);
    try {
      const response = await fetch("/api/programs/unload", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ program }),
      });
  
      const data = await response.json();
      if (data.error) {
        alert("Error: " + data.error);
      } else {
        alert(data.message);
      }
      fetchPrograms();
    } catch (error) {
      alert("Error unloading program: " + error.message);
    } finally {
      showLoading(false);
    }
  }
  