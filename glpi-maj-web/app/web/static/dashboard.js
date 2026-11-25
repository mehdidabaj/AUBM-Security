(function () {
  var node = document.getElementById("chart-data");
  if (!node || !window.Chart) {
    return;
  }
  var data = JSON.parse(node.textContent);
  var logiciels = document.getElementById("chart-logiciels");
  if (logiciels) {
    new window.Chart(logiciels, {
      type: "bar",
      data: {
        labels: data.logiciels.labels,
        datasets: [{ label: "Actions", data: data.logiciels.values, backgroundColor: "#0f6e6b" }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: {
              maxRotation: 40,
              minRotation: 0,
              callback: function (value) {
                var label = this.getLabelForValue(value);
                return label.length > 24 ? label.slice(0, 22) + "…" : label;
              }
            }
          },
          y: { beginAtZero: true, ticks: { precision: 0 } }
        }
      }
    });
  }
  var evolution = document.getElementById("chart-evolution");
  if (evolution) {
    new window.Chart(evolution, {
      type: "line",
      data: {
        labels: data.evolution.labels,
        datasets: [{ label: "Actions", data: data.evolution.actions, borderColor: "#9f1239", tension: 0.2 }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }
})();
