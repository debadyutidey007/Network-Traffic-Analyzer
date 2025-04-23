
/**
 * Dashboard-specific JavaScript functions
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    let protocolChart = null;
    let timelineChart = null;
    let severityChart = null;
    
    // Initialize event listeners for admin controls
    if (document.getElementById('start-analyzer')) 
    {
        document.getElementById('start-analyzer').addEventListener('click', startAnalyzer);
    }
    
    if (document.getElementById('stop-analyzer')) 
    {
        document.getElementById('stop-analyzer').addEventListener('click', stopAnalyzer);
    }
    
    // Load initial chart data
    refreshCharts();
    
    // Set up real-time updates via Socket.IO
    if (window.socket) 
    {
        // Listen for status updates
        window.socket.on('analyzer_status', function(data) 
        {
            updateAnalyzerStatus(data.status);
        });
        
        // Listen for new incidents
        window.socket.on('new_incident', function(incident) 
        {
            updateIncidentTable(incident);
            // Also refresh charts when we get new data
            refreshCharts();
        });
        
        // Request recent incidents
        window.socket.emit('request_incidents');
        
        // Update incident table when we receive incident data
        window.socket.on('incidents_update', function(incidents) 
        {
            updateIncidentsTable(incidents);
        });
    }
    
    // Periodically refresh charts
    setInterval(refreshCharts, 30000); // Every 30 seconds
    
    /**
     * Refresh all charts with latest data
     */
    function refreshCharts() 
    {
        // Fetch protocol distribution data
        fetch('/api/stats/protocols')
            .then(response => response.json())
            .then(data => {
                updateProtocolChart(data.labels, data.data);
            })
            .catch(error => console.error('Error fetching protocol stats:', error));
        
        // Fetch timeline data
        fetch('/api/stats/timeline')
            .then(response => response.json())
            .then(data => {
                updateTimelineChart(data.labels, data.data);
            })
            .catch(error => console.error('Error fetching timeline stats:', error));
        
        // Fetch severity distribution data
        fetch('/api/stats/severity')
            .then(response => response.json())
            .then(data => {
                updateSeverityChart(data.labels, data.data);
            })
            .catch(error => console.error('Error fetching severity stats:', error));
    }
    
    /**
     * Update the protocol distribution chart
     */
    function updateProtocolChart(labels, data)
    {
        const ctx = document.getElementById('protocolChart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (protocolChart) 
        {
            protocolChart.destroy();
        }
        
        // Create new chart
        protocolChart = new Chart(ctx, {
            type: 'pie',
            data: 
            {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: getChartColors(labels.length),
                    borderWidth: 1
                }]
            },
            options: 
            {
                responsive: true,
                maintainAspectRatio: false,
                plugins: 
                {
                    legend: 
                    {
                        position: 'right',
                    },
                    title: 
                    {
                        display: true,
                        text: 'Incidents by Protocol'
                    }
                }
            }
        });
    }
    
    /**
     * Update the timeline chart
     */
    function updateTimelineChart(labels, data) 
    {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (timelineChart) 
        {
            timelineChart.destroy();
        }
        
        // Create new chart
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: 
            {
                labels: labels,
                datasets: [{
                    label: 'Incidents',
                    data: data,
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: 
            {
                responsive: true,
                maintainAspectRatio: false,
                scales: 
                {
                    y: 
                    {
                        beginAtZero: true,
                        ticks: 
                        {
                            precision: 0
                        }
                    }
                },
                plugins: 
                {
                    title: 
                    {
                        display: true,
                        text: 'Incident Timeline (Last 24 Hours)'
                    }
                }
            }
        });
    }
    
    /**
     * Update the severity distribution chart
     */
    function updateSeverityChart(labels, data) 
    {
        if (!document.getElementById('severityChart')) 
        {
            return;  // Chart element doesn't exist
        }
        
        const ctx = document.getElementById('severityChart').getContext('2d');
        
        // Map severity levels to colors
        const backgroundColors = labels.map(label => {
            if (label.toLowerCase() === 'high') return 'rgba(255, 99, 132, 0.8)';
            if (label.toLowerCase() === 'medium') return 'rgba(255, 206, 86, 0.8)';
            return 'rgba(75, 192, 192, 0.8)';
        });
        
        // Destroy existing chart if it exists
        if (severityChart) 
        {
            severityChart.destroy();
        }
        
        // Create new chart
        severityChart = new Chart(ctx, {
            type: 'bar',
            data: 
            {
                labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
                datasets: [{
                    label: 'Incidents',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderColor: backgroundColors.map(color => color.replace('0.8', '1')),
                    borderWidth: 1
                }]
            },
            options: 
            {
                responsive: true,
                maintainAspectRatio: false,
                scales: 
                {
                    y: 
                    {
                        beginAtZero: true,
                        ticks: 
                        {
                            precision: 0
                        }
                    }
                },
                plugins: 
                {
                    title: 
                    {
                        display: true,
                        text: 'Incidents by Severity'
                    }
                }
            }
        });
    }
    
    /**
     * Update the analyzer status display
     */
    function updateAnalyzerStatus(status) 
    {
        const statusDisplay = document.getElementById('analyzer-display-status');
        const iconDisplay = document.getElementById('analyzer-display-icon');
        const startButton = document.getElementById('start-analyzer');
        const stopButton = document.getElementById('stop-analyzer');
        
        if (!statusDisplay || !iconDisplay) return;
        
        if (status === 'running') 
        {
            statusDisplay.innerHTML = '<span class="text-success">Running</span>';
            iconDisplay.innerHTML = '<i class="fas fa-play-circle text-success fa-3x"></i>';
            
            if (startButton && stopButton) 
            {
                startButton.disabled = true;
                stopButton.disabled = false;
            }
        } 
        else 
        {
            statusDisplay.innerHTML = '<span class="text-danger">Stopped</span>';
            iconDisplay.innerHTML = '<i class="fas fa-stop-circle text-danger fa-3x"></i>';
            
            if (startButton && stopButton) 
            {
                startButton.disabled = false;
                stopButton.disabled = true;
            }
        }
    }
    
    /**
     * Start the analyzer
     */
    function startAnalyzer() 
    {
        fetch('/api/start_analyzer', {
            method: 'POST',
            headers: 
            {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'running') {
                updateAnalyzerStatus('running');
            }
        })
        .catch(error => console.error('Error starting analyzer:', error));
    }
    
    /**
     * Stop the analyzer
     */
    function stopAnalyzer() 
    {
        fetch('/api/stop_analyzer', {
            method: 'POST',
            headers: 
            {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'stopped') {
                updateAnalyzerStatus('stopped');
            }
        })
        .catch(error => console.error('Error stopping analyzer:', error));
    }
    
    /**
     * Update the incidents table with a new incident
     */
    function updateIncidentTable(incident) 
    {
        const tableBody = document.getElementById('incidents-table-body');
        if (!tableBody) return;
        
        // Format the timestamp
        const timestamp = new Date(incident.timestamp);
        const formattedTimestamp = timestamp.toLocaleString();
        
        // Create badge for severity
        let severityBadge = '';
        if (incident.severity === 'high') 
        {
            severityBadge = '<span class="badge bg-danger">High</span>';
        } 
        else if (incident.severity === 'medium') 
        {
            severityBadge = '<span class="badge bg-warning">Medium</span>';
        } 
        else 
        {
            severityBadge = '<span class="badge bg-info">Low</span>';
        }
        
        // Create new row HTML
        const newRow = document.createElement('tr');
        newRow.className = `incident-${incident.severity}`;
        newRow.innerHTML = `
            <td>${formattedTimestamp}</td>
            <td>${incident.src_ip}</td>
            <td>${incident.protocol}</td>
            <td>${severityBadge}</td>
            <td>${incident.details}</td>
            <td>
                <a href="/incidents/${incident.id}" class="btn btn-sm btn-outline-info">
                    <i class="fas fa-eye"></i>
                </a>
            </td>
        `;
        
        // Add to the beginning of the table
        if (tableBody.firstChild) 
        {
            tableBody.insertBefore(newRow, tableBody.firstChild);
        } 
        else 
        {
            tableBody.appendChild(newRow);
        }
        
        // Remove the last row if we have too many rows
        if (tableBody.children.length > 10) 
        {
            tableBody.removeChild(tableBody.lastChild);
        }
    }
    
    /**
     * Update the incidents table with multiple incidents
     */
    function updateIncidentsTable(incidents) 
    {
        const tableBody = document.getElementById('incidents-table-body');
        if (!tableBody) return;
        
        // Clear existing entries
        tableBody.innerHTML = '';
        
        // Add each incident
        incidents.forEach(incident => {
            updateIncidentTable(incident);
        });
    }
});
