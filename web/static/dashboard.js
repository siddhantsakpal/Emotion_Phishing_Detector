// FIX: All decision comparisons use lowercase trim to avoid casing bugs

function getRiskDetails(decision) {
    const d = (decision || "").trim().toLowerCase();
    if (d === "phishing")   return { color: "#ff3d57" };
    if (d === "suspicious") return { color: "#ffaa00" };
    if (d === "unknown")    return { color: "#a855f7" };
    return { color: "#00e096" }; // legitimate
}

document.addEventListener("DOMContentLoaded", () => {
    if (!window.RESULT_DATA) {
        console.error("RESULT_DATA missing");
        return;
    }

    const result = window.RESULT_DATA;
    const dec    = (result.decision || "").trim().toLowerCase();
    const riskInfo = getRiskDetails(dec);

    // FIX: Use final overridden percentages instead of raw ml_probs_combined
    const confidence = {
        phishing:   (result.phishing_pct   || 0) / 100,
        suspicious: (result.suspicious_pct || 0) / 100,
        legitimate: (result.legit_pct      || 0) / 100
    };

    const emotions = result.emotions || {};

    // FIX: Gauge shows dominant probability based on final decision
    // Uses lowercase comparison to avoid casing bugs
    let gaugePercent;
    if      (dec === "phishing")   gaugePercent = Math.round(confidence.phishing   * 100);
    else if (dec === "suspicious") gaugePercent = Math.round(confidence.suspicious * 100);
    else if (dec === "unknown")    gaugePercent = 50;
    else                           gaugePercent = Math.round(confidence.legitimate * 100);

    const displayPercent = Math.max(gaugePercent, 5); // min visible fill

    /* =============================
       CENTER TEXT PLUGIN
    ============================= */
    const centerTextPlugin = {
        id: "centerText",
        afterDraw(chart, args, options) {
            const { ctx, chartArea } = chart;
            if (!chartArea) return;
            ctx.save();
            ctx.font      = "bold 28px Arial";
            ctx.fillStyle = riskInfo.color;
            ctx.textAlign = "center";
            ctx.fillText(
                options.text,
                (chartArea.left + chartArea.right) / 2,
                chartArea.bottom - 30
            );
            ctx.restore();
        }
    };

    /* =============================
       RISK GAUGE
    ============================= */
    const gaugeData   = dec === "unknown" ? [50, 50] : [displayPercent, 100 - displayPercent];
    const gaugeColors = [riskInfo.color, "#e0e0e0"];
    const gaugeCenterText = dec === "unknown" ? "?" : `${gaugePercent}%`;

    new Chart(document.getElementById("riskGauge"), {
        type: "doughnut",
        data: {
            datasets: [{
                data:            gaugeData,
                backgroundColor: gaugeColors,
                borderWidth:     0,
                borderRadius:    0
            }]
        },
        options: {
            rotation:      -90,
            circumference: 180,
            cutout:        "70%",
            plugins: {
                legend:     { display: false },
                tooltip:    { enabled: false },
                centerText: { text: gaugeCenterText }
            },
            animation: { animateRotate: true, duration: 1000 }
        },
        plugins: [centerTextPlugin]
    });

    /* =============================
       BAR GRAPH
    ============================= */
    const barCanvas = document.getElementById("decisionBars");

    if (dec === "unknown") {
        barCanvas.parentElement.innerHTML =
            "<div class='card-title'>▸ DECISION CONFIDENCE</div>" +
            "<p style='color:#a855f7; text-align:center; padding:20px; font-family:monospace;'>" +
            "⚠️ No confidence data — sender unknown to system.</p>";
    } else {
        new Chart(barCanvas, {
            type: "bar",
            data: {
                labels: ["Phishing", "Suspicious", "Legitimate"],
                datasets: [{
                    data: [
                        Math.round(confidence.phishing   * 100),
                        Math.round(confidence.suspicious * 100),
                        Math.round(confidence.legitimate * 100)
                    ],
                    backgroundColor: ["#ff3d57", "#ffaa00", "#00e096"],
                    borderRadius: 8
                }]
            },
            options: {
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        ticks: { callback: v => v + "%" }
                    }
                },
                plugins: {
                    legend:  { display: false },
                    tooltip: {
                        callbacks: {
                            label: ctx => `${ctx.label}: ${ctx.parsed.y}%`
                        }
                    }
                }
            }
        });
    }

    /* =============================
       EMOTION RADAR
    ============================= */
    const radarCanvas = document.getElementById("emotionRadar");

    if (dec === "unknown" || Object.keys(emotions).length === 0) {
        radarCanvas.parentElement.innerHTML =
            "<div class='card-title'>▸ EMOTION RADAR</div>" +
            "<p style='color:#a855f7; text-align:center; padding:20px; font-family:monospace;'>" +
            "⚠️ No emotion data available.</p>";
    } else {
        new Chart(radarCanvas, {
            type: "radar",
            data: {
                labels: Object.keys(emotions),
                datasets: [{
                    data:                 Object.values(emotions),
                    backgroundColor:      "rgba(0,229,255,0.15)",
                    borderColor:          "#00e5ff",
                    pointBackgroundColor: "#00e5ff"
                }]
            },
            options: {
                scales: {
                    r: {
                        min: 0,
                        max: 1,
                        ticks: { callback: v => Math.round(v * 100) + "%" }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
});
