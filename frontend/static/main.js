document.addEventListener("DOMContentLoaded", () => {
    const programSelect = document.getElementById("program-select");
    const loadButton = document.getElementById("load-button");
    const unloadButton = document.getElementById("unload-button");
    const statusDiv = document.getElementById("status");

    // Fetch the list of available programs
    fetch("/programs")
        .then(response => response.json())
        .then(programs => {
            programs.forEach(program => {
                const option = document.createElement("option");
                option.value = program;
                option.textContent = program;
                programSelect.appendChild(option);
            });
        });

    loadButton.addEventListener("click", () => {
        const selectedProgram = programSelect.value;
        fetch("/programs/load", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ program: selectedProgram })
        })
            .then(response => response.json())
            .then(data => {
                statusDiv.textContent = data.message || data.error;
            });
    });

    unloadButton.addEventListener("click", () => {
        const selectedProgram = programSelect.value;
        fetch("/programs/unload", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ program: selectedProgram })
        })
            .then(response => response.json())
            .then(data => {
                statusDiv.textContent = data.message || data.error;
            });
    });
});