(() => {
  const validViews = new Set(["overview", "analytics", "profiles", "resolvers", "diagnostics"]);
  const originalNavigate = navigate;

  function storedView() {
    const hashView = window.location.hash.replace(/^#\/?/, "");
    if (validViews.has(hashView)) return hashView;
    const saved = window.localStorage.getItem("dns-dashboard-view");
    return validViews.has(saved) ? saved : "overview";
  }

  navigate = function stableNavigate(view, options = {}) {
    const target = validViews.has(view) ? view : "overview";
    originalNavigate(target);
    window.localStorage.setItem("dns-dashboard-view", target);
    if (window.location.hash !== `#${target}`) {
      window.history.replaceState(null, "", `#${target}`);
    }
    if (options.scroll !== false) {
      window.requestAnimationFrame(() => window.scrollTo({ top: 0, left: 0 }));
    }
  };

  document.querySelectorAll(".nav-button").forEach((button) => {
    button.addEventListener("click", () => {
      window.localStorage.setItem("dns-dashboard-view", button.dataset.view || "overview");
    });
  });

  window.addEventListener("hashchange", () => {
    navigate(storedView());
  });

  function finiteValue(value) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function pointHasActivity(point) {
    return ["queries", "blocked", "errors", "failovers"].some(
      (key) => (finiteValue(point[key]) || 0) > 0
    ) || finiteValue(point.latency_ms) !== null;
  }

  function compactHistory(points) {
    if (!Array.isArray(points) || points.length === 0) return [];
    const firstActivity = points.findIndex(pointHasActivity);
    if (firstActivity < 0) return points.slice(-30);
    const start = Math.max(0, Math.min(firstActivity - 3, points.length - 30));
    return points.slice(start);
  }

  drawChart = function stableDrawChart(canvas, points, series) {
    if (!canvas || canvas.offsetParent === null) return;

    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(280, Math.round(rect.width || canvas.clientWidth || 600));
    const height = Number(canvas.getAttribute("height")) || 240;

    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);

    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;

    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    const palette = chartPalette();
    ctx.fillStyle = palette.background;
    ctx.fillRect(0, 0, width, height);

    const padding = { left: 44, right: 12, top: 12, bottom: 30 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const values = [];

    for (const point of points) {
      for (const item of series) {
        const value = finiteValue(point[item.key]);
        if (value !== null) values.push(value);
      }
    }

    const maxValue = Math.max(1, ...values);
    ctx.font = "11px system-ui";
    ctx.lineWidth = 1;

    for (let index = 0; index <= 4; index += 1) {
      const y = padding.top + (plotHeight * index) / 4;
      ctx.strokeStyle = palette.grid;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();
      ctx.fillStyle = palette.text;
      ctx.fillText(String(Math.round(maxValue * (1 - index / 4))), 4, y + 4);
    }

    const count = Math.max(points.length, 2);
    for (const item of series) {
      ctx.strokeStyle = item.color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.beginPath();
      let segmentOpen = false;

      points.forEach((point, index) => {
        const value = finiteValue(point[item.key]);
        if (value === null) {
          segmentOpen = false;
          return;
        }
        const x = padding.left + (index / (count - 1)) * plotWidth;
        const y = padding.top + plotHeight - (value / maxValue) * plotHeight;
        if (!segmentOpen) {
          ctx.moveTo(x, y);
          segmentOpen = true;
        } else {
          ctx.lineTo(x, y);
        }
      });
      ctx.stroke();
    }

    if (points.length) {
      ctx.fillStyle = palette.text;
      const first = new Date(points[0].time);
      const last = new Date(points[points.length - 1].time);
      const firstLabel = first.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const lastLabel = last.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      ctx.fillText(firstLabel, padding.left, height - 7);
      ctx.fillText(lastLabel, width - padding.right - ctx.measureText(lastLabel).width, height - 7);
    }
  };

  renderHistory = function stableRenderHistory(points) {
    const compact = compactHistory(points);
    const palette = chartPalette();
    drawChart(fields.trafficChart, compact, [
      { key: "queries", color: palette.query },
      { key: "blocked", color: palette.blocked },
      { key: "errors", color: palette.error },
    ]);
    drawChart(fields.latencyChart, compact, [
      { key: "latency_ms", color: palette.latency },
    ]);
    if (fields.trafficChartRange) {
      fields.trafficChartRange.textContent = `${compact.length || 0} min shown`;
    }
  };

  const restored = storedView();
  window.requestAnimationFrame(() => navigate(restored));
})();
