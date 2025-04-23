
/**
 * Utility functions for charts and data visualization
 */
function getChartColors(count = 10) 
{
    // Collection of colors for charts
    const colors = [
        'rgba(54, 162, 235, 0.8)',    // blue
        'rgba(255, 99, 132, 0.8)',    // red
        'rgba(255, 206, 86, 0.8)',    // yellow
        'rgba(75, 192, 192, 0.8)',    // green
        'rgba(153, 102, 255, 0.8)',   // purple
        'rgba(255, 159, 64, 0.8)',    // orange
        'rgba(199, 199, 199, 0.8)',   // gray
        'rgba(83, 102, 255, 0.8)',    // indigo
        'rgba(78, 205, 196, 0.8)',    // teal
        'rgba(255, 99, 71, 0.8)',     // tomato
    ];
    // If more colors are needed, generate them
    if (count <= colors.length) 
    {
        return colors.slice(0, count);
    }
    // Generate additional colors
    const additionalColors = [];
    for (let i = 0; i < count - colors.length; i++) 
    {
        const r = Math.floor(Math.random() * 255);
        const g = Math.floor(Math.random() * 255);
        const b = Math.floor(Math.random() * 255);
        additionalColors.push(`rgba(${r}, ${g}, ${b}, 0.8)`);
    }
    return [...colors, ...additionalColors];
}
function formatNumber(num) 
{
    if (num >= 1000000) 
    {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) 
    {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num;
}
function formatBytes(bytes, decimals = 2) 
{
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
function formatTimestamp(timestamp) 
{
    const date = new Date(timestamp);
    return date.toLocaleString();
}
