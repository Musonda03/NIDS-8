let trafficChart;

function logout() {
    window.location.href = '/logout';
}

function fetchTrafficData() {
    fetch('/traffic_data')
        .then(response => response.json())
        .then(data => {
            updateChart(data);
        });
}

function createChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packet Count',
                data: [],
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1,
                fill: false
            }]
        },
        options: {
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(tooltipItem) {
                            return 'Packet Count: ' + tooltipItem.parsed.y;
                        }
                    }
                },
                legend: {
                    display: true,
                    labels: {
                        color: 'rgb(75, 192, 192)'
                    }
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'second',
                        tooltipFormat: 'HH:mm:ss',
                        displayFormats: {
                            second: 'HH:mm:ss'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Packet Count'
                    }
                }
            }
        }
    });
}

function updateChart(data) {
    trafficChart.data.labels = data.time;
    trafficChart.data.datasets[0].data = data.packet_count;
    trafficChart.update();
}

// Initialize chart on page load
createChart();

// Fetch traffic data every 5 seconds
setInterval(fetchTrafficData, 5000);

