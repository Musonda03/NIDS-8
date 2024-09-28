function logout() {
    window.location.href = '/logout';
}

function navigateToTraffic() {
    window.location.href = '/traffic';
}

function navigateToUserGuide() {
    window.location.href = '/user_guide';
}

function naviageteToCapturedData() {
    window.location.href = '/captured_data';
}

function fetchAnomalies() {
    fetch('/anomalies')
        .then(response => response.json())
        .then(data => {
            const anomaliesContainer = document.getElementById('anomalies-container');
            const anomalyCount = document.getElementById('anomaly-count');
            anomaliesContainer.innerHTML = '';
            anomalyCount.textContent = data.length;
            
            data.forEach(anomaly => {
                const anomalyCard = document.createElement('div');
                anomalyCard.className = 'anomaly-card';
                anomalyCard.innerHTML = `
                    <div class="anomaly-header">
                        <span class="anomaly-timestamp">${new Date(anomaly.timestamp * 1000).toLocaleString()}</span>
                    </div>
                    <div class="anomaly-body">
                        <p><strong>Source IP:</strong> ${anomaly.ip_src}</p>
                        <p><strong>Destination IP:</strong> ${anomaly.ip_dst}</p>
                        <p><strong>Protocol:</strong> ${anomaly.ip_proto}</p>
                        <p><strong>Source Port:</strong> ${anomaly.sport}</p>
                        <p><strong>Destination Port:</strong> ${anomaly.dport}</p>
                        <p><strong>TCP Flags:</strong> ${anomaly.tcp_flags}</p>
                    </div>
                `;
                anomaliesContainer.appendChild(anomalyCard);
            });
        });
}


setInterval(fetchAnomalies, 5000);

fetchAnomalies();

 /*const anomalyDiv = document.createElement('div');*/
                /*anomalyDiv.textContent = anomaly;*/
