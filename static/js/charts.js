// Draws the dashboard charts from the JSON embedded in the page.
document.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("chart-data");
  if (!el || typeof Chart === "undefined") return;
  const data = JSON.parse(el.textContent);

  Chart.defaults.color = "#8a98ad";
  Chart.defaults.borderColor = "#1f2c40";
  const palette = ["#00e0a4", "#7cc8ff", "#ffd75e", "#ff7b8a", "#b48cff", "#ff9f6b"];

  function draw(id, type, obj) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const labels = Object.keys(obj);
    if (labels.length === 0) {
      canvas.replaceWith(Object.assign(document.createElement("p"), {
        className: "text-secondary mb-0", textContent: "No data yet.",
      }));
      return;
    }
    new Chart(canvas, {
      type,
      data: {
        labels,
        datasets: [{
          data: Object.values(obj),
          backgroundColor: palette,
          borderWidth: 0,
        }],
      },
      options: {
        plugins: { legend: { display: type === "doughnut" } },
        scales: type === "bar"
          ? { y: { beginAtZero: true, ticks: { precision: 0 } } }
          : {},
      },
    });
  }

  draw("chart-dns", "bar", data.dns);
  draw("chart-tech", "doughnut", data.tech);
  draw("chart-wayback", "bar", data.wayback);
});