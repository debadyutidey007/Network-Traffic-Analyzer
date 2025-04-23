
/**
 * Reports page JavaScript functions
 */
document.addEventListener('DOMContentLoaded', function() {
    // Handle report generation form
    const reportForm = document.getElementById('report-form');
    
    if (reportForm) 
    {
        reportForm.addEventListener('submit', function(event) {
            const submitButton = reportForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';
            
            // Form will be submitted normally, this just updates the UI
        });
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
