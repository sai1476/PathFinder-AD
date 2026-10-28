// PathFinder AD Client Scripts
document.addEventListener("DOMContentLoaded", () => {
    // Quick search filter for tables
    const searchInput = document.getElementById("quick-search");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            const query = e.target.value.toLowerCase();
            const rows = document.querySelectorAll(".searchable-table tbody tr");
            rows.forEach((row) => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? "" : "none";
            });
        });
    }

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll(".alert");
    alerts.forEach((alert) => {
        setTimeout(() => {
            alert.style.opacity = "0";
            alert.style.transition = "opacity 0.5s ease";
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    });
});
