
/**
 * Socket.IO connection and event handling
 */
document.addEventListener('DOMContentLoaded', function() {
    if (typeof io !== 'undefined') 
    {
        // Connect to Socket.IO server
        const socket = io();
        
        // Store socket in window for global access
        window.socket = socket;
        
        // Connection event
        socket.on('connect', function() 
        {
            console.log('Connected to Socket.IO server');
        });
        
        // Disconnection event
        socket.on('disconnect', function() 
        {
            console.log('Disconnected from Socket.IO server');
        });
        
        // Error event
        socket.on('connect_error', function(error) 
        {
            console.error('Socket.IO connection error:', error);
        });
        
        // Update analyzer status indicator
        const statusIndicator = document.getElementById('analyzer-status-indicator');
        
        if (statusIndicator) 
        {
            socket.on('analyzer_status', function(data) 
            {
                if (data.status === 'running') 
                {
                    statusIndicator.innerHTML = '<i class="fas fa-circle text-success me-1"></i> Running';
                } 
                else if (data.status === 'stopped') 
                {
                    statusIndicator.innerHTML = '<i class="fas fa-circle text-danger me-1"></i> Stopped';
                } 
                else if (data.status === 'error') 
                {
                    statusIndicator.innerHTML = '<i class="fas fa-circle text-warning me-1"></i> Error';
                }
            });
        }
        
        // Listen for new incidents if we're on the dashboard
        if (document.getElementById('incidents-table-body')) 
        {
            socket.on('new_incident', function(incident) 
            {
                // This will be handled by dashboard.js
                console.log('New incident received:', incident);
            });
        }
        
        // Listen for statistics updates
        socket.on('statistics_update', function(data) 
        {
            console.log('Statistics update received:', data);
            // Update any live statistics displays
            updateLiveStatistics(data);
        });
    }
    
    /**
     * Update live traffic statistics
     */
    function updateLiveStatistics(data) 
    {
        const statsContainer = document.getElementById('live-traffic-stats');
        if (!statsContainer) return;
        
        // If we have stats array
        if (data.stats && Array.isArray(data.stats)) 
        {
            // Clear "waiting for data" message if it exists
            if (statsContainer.querySelector('.spinner-border')) 
            {
                statsContainer.innerHTML = '';
            }
            
            // Create or update stats table
            let statsTable = statsContainer.querySelector('table');
            
            if (!statsTable) 
            {
                statsTable = document.createElement('table');
                statsTable.className = 'table table-sm table-hover';
                statsTable.innerHTML = `
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Packets</th>
                            <th>Bytes</th>
                            <th>Ports</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                `;
                statsContainer.appendChild(statsTable);
            }
            
            const tbody = statsTable.querySelector('tbody');
            
            // Update or add rows
            data.stats.forEach(stat => {
                // Look for existing row for this IP
                let row = tbody.querySelector(`tr[data-ip="${stat.ip_address}"]`);
                
                // Create new row if not found
                if (!row) 
                {
                    row = document.createElement('tr');
                    row.setAttribute('data-ip', stat.ip_address);
                    tbody.appendChild(row);
                }
                
                // Update row content
                row.innerHTML = `
                    <td>${stat.ip_address}</td>
                    <td>${formatNumber(stat.packet_count)}</td>
                    <td>${formatBytes(stat.byte_count)}</td>
                    <td>${stat.port_count}</td>
                `;
            });
        }
    }
});
