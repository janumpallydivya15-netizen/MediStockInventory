/* ============================================
   MediStock - Custom JavaScript
   ============================================ */

// ========== Initialize on Page Load ==========
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    initializeAnimations();
    initializeSearchFunctionality();
    initializeFormValidation();
    initializeTooltips();
    initializeCharts();
});

// ========== Main Initialization ==========
function initializeApp() {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Add active class to current page nav link
    highlightCurrentPage();

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Set current date as max for date inputs
    setDateRestrictions();
}

// ========== Highlight Current Page in Navigation ==========
function highlightCurrentPage() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        const linkPath = new URL(link.href).pathname;
        if (linkPath === currentPath) {
            link.classList.add('active');
        }
    });
}

// ========== Date Input Restrictions ==========
function setDateRestrictions() {
    const today = new Date().toISOString().split('T')[0];
    const expirationDateInputs = document.querySelectorAll('input[name="expiration_date"]');
    
    expirationDateInputs.forEach(input => {
        input.setAttribute('min', today);
    });
}

// ========== Animations ==========
function initializeAnimations() {
    // Fade in elements on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    document.querySelectorAll('.card, .stat-card').forEach(el => {
        observer.observe(el);
    });

    // Counter animation for stat cards
    animateCounters();
}

// ========== Counter Animation ==========
function animateCounters() {
    const counters = document.querySelectorAll('.stat-card h2');
    
    counters.forEach(counter => {
        const target = parseInt(counter.textContent.replace(/[^0-9]/g, ''));
        if (isNaN(target)) return;
        
        const duration = 2000;
        const step = target / (duration / 16);
        let current = 0;
        
        const updateCounter = () => {
            current += step;
            if (current < target) {
                counter.textContent = Math.floor(current).toLocaleString();
                requestAnimationFrame(updateCounter);
            } else {
                counter.textContent = target.toLocaleString();
            }
        };
        
        updateCounter();
    });
}

// ========== Search Functionality ==========
function initializeSearchFunctionality() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;

    searchInput.addEventListener('keyup', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        const tableRows = document.querySelectorAll('#medicinesTable tbody tr');
        
        let visibleCount = 0;
        tableRows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const isVisible = text.includes(searchTerm);
            row.style.display = isVisible ? '' : 'none';
            if (isVisible) visibleCount++;
        });

        // Show no results message
        updateSearchResults(visibleCount, tableRows.length);
    });
}

// ========== Update Search Results Display ==========
function updateSearchResults(visibleCount, totalCount) {
    let resultDiv = document.getElementById('searchResults');
    
    if (!resultDiv) {
        resultDiv = document.createElement('div');
        resultDiv.id = 'searchResults';
        resultDiv.className = 'alert alert-info mt-2';
        document.getElementById('searchInput').parentNode.appendChild(resultDiv);
    }
    
    if (visibleCount === 0) {
        resultDiv.innerHTML = '<i class="bi bi-info-circle"></i> No medicines found matching your search.';
        resultDiv.style.display = 'block';
    } else if (visibleCount < totalCount) {
        resultDiv.innerHTML = `<i class="bi bi-funnel"></i> Showing ${visibleCount} of ${totalCount} medicines`;
        resultDiv.style.display = 'block';
    } else {
        resultDiv.style.display = 'none';
    }
}

// ========== Form Validation ==========
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Password matching validation
    const confirmPassword = document.getElementById('confirm_password');
    const password = document.getElementById('password');
    
    if (confirmPassword && password) {
        confirmPassword.addEventListener('input', function() {
            if (this.value !== password.value) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
    }

    // Quantity validation
    const quantityInput = document.querySelector('input[name="quantity"]');
    const thresholdInput = document.querySelector('input[name="threshold"]');
    
    if (quantityInput && thresholdInput) {
        const validateStock = () => {
            const quantity = parseInt(quantityInput.value);
            const threshold = parseInt(thresholdInput.value);
            
            if (quantity <= threshold) {
                showWarning('Stock is below or at threshold level!');
            }
        };
        
        quantityInput.addEventListener('change', validateStock);
        thresholdInput.addEventListener('change', validateStock);
    }
}

// ========== Show Warning Message ==========
function showWarning(message) {
    const warningDiv = document.createElement('div');
    warningDiv.className = 'alert alert-warning alert-dismissible fade show mt-2';
    warningDiv.innerHTML = `
        <i class="bi bi-exclamation-triangle"></i> ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const form = document.querySelector('form');
    if (form) {
        form.insertBefore(warningDiv, form.firstChild);
        setTimeout(() => warningDiv.remove(), 5000);
    }
}

// ========== Delete Confirmation ==========
function deleteMedicine(medicineId, medicineName) {
    const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
    document.getElementById('medicineName').textContent = medicineName;
    document.getElementById('deleteForm').action = `/medicines/delete/${medicineId}`;
    modal.show();
}

// ========== Quick Stock Update ==========
function updateStock(medicineId, action) {
    const quantityInput = document.getElementById(`quantity_${medicineId}`);
    const quantity = parseInt(quantityInput.value);
    
    if (!quantity || quantity < 1) {
        showNotification('Please enter a valid quantity', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('quantity_change', quantity);
    formData.append('action', action);
    
    fetch(`/medicines/update-stock/${medicineId}`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showNotification(data.message, 'danger');
        }
    })
    .catch(error => {
        showNotification('Error updating stock', 'danger');
        console.error('Error:', error);
    });
}

// ========== Show Notification Toast ==========
function showNotification(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="bi bi-check-circle me-2"></i>${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    setTimeout(() => toast.remove(), 5000);
}

// ========== Create Toast Container ==========
function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

// ========== Export Table to CSV ==========
function exportTableToCSV(filename) {
    const table = document.getElementById('reportTable');
    if (!table) {
        showNotification('No table found to export', 'warning');
        return;
    }
    
    let csv = [];
    const rows = table.querySelectorAll('tr');
    
    rows.forEach(row => {
        const cols = row.querySelectorAll('td, th');
        const rowData = Array.from(cols).map(col => {
            let data = col.textContent.replace(/(\r\n|\n|\r)/gm, '').trim();
            data = data.replace(/"/g, '""');
            return `"${data}"`;
        });
        csv.push(rowData.join(','));
    });
    
    downloadCSV(csv.join('\n'), filename);
    showNotification('Report exported successfully', 'success');
}

// ========== Download CSV File ==========
function downloadCSV(csvContent, filename) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    
    if (navigator.msSaveBlob) {
        navigator.msSaveBlob(blob, filename);
    } else {
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}

// ========== Print Report ==========
function printReport() {
    window.print();
}

// ========== Initialize Tooltips ==========
function initializeTooltips() {
    const tooltips = document.querySelectorAll('[title]');
    tooltips.forEach(element => {
        element.setAttribute('data-bs-toggle', 'tooltip');
        new bootstrap.Tooltip(element);
    });
}

// ========== Initialize Charts (Simple Canvas Charts) ==========
function initializeCharts() {
    const chartCanvas = document.getElementById('categoryChart');
    if (!chartCanvas) return;
    
    // Simple category distribution chart (placeholder)
    drawCategoryChart(chartCanvas);
}

// ========== Draw Simple Category Chart ==========
function drawCategoryChart(canvas) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    // Sample data - replace with actual data from backend
    const categories = ['Tablet', 'Capsule', 'Syrup', 'Injection', 'Other'];
    const values = [35, 25, 20, 15, 5];
    const colors = ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
    
    let startAngle = 0;
    const total = values.reduce((a, b) => a + b, 0);
    
    values.forEach((value, index) => {
        const sliceAngle = (value / total) * 2 * Math.PI;
        
        ctx.beginPath();
        ctx.fillStyle = colors[index];
        ctx.moveTo(width / 2, height / 2);
        ctx.arc(width / 2, height / 2, Math.min(width, height) / 2 - 10, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fill();
        
        startAngle += sliceAngle;
    });
}

// ========== Filter Table by Category ==========
function filterByCategory(category) {
    const rows = document.querySelectorAll('#medicinesTable tbody tr');
    
    rows.forEach(row => {
        const rowCategory = row.querySelector('td:nth-child(2)').textContent.trim();
        if (category === 'all' || rowCategory === category) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// ========== Sort Table ==========
function sortTable(columnIndex, type = 'text') {
    const table = document.getElementById('medicinesTable');
    if (!table) return;
    
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    rows.sort((a, b) => {
        const aValue = a.querySelectorAll('td')[columnIndex].textContent.trim();
        const bValue = b.querySelectorAll('td')[columnIndex].textContent.trim();
        
        if (type === 'number') {
            return parseFloat(aValue) - parseFloat(bValue);
        } else {
            return aValue.localeCompare(bValue);
        }
    });
    
    rows.forEach(row => tbody.appendChild(row));
}

// ========== Real-time Stock Status Update ==========
function updateStockStatus() {
    const quantityInputs = document.querySelectorAll('input[name="quantity"]');
    const thresholdInputs = document.querySelectorAll('input[name="threshold"]');
    
    quantityInputs.forEach((qInput, index) => {
        const tInput = thresholdInputs[index];
        if (!tInput) return;
        
        const updateStatus = () => {
            const quantity = parseInt(qInput.value) || 0;
            const threshold = parseInt(tInput.value) || 0;
            
            let statusBadge = qInput.closest('tr')?.querySelector('.status-badge');
            if (statusBadge) {
                if (quantity <= threshold) {
                    statusBadge.className = 'badge bg-danger status-badge';
                    statusBadge.textContent = 'Low Stock';
                } else {
                    statusBadge.className = 'badge bg-success status-badge';
                    statusBadge.textContent = 'In Stock';
                }
            }
        };
        
        qInput.addEventListener('input', updateStatus);
        tInput.addEventListener('input', updateStatus);
    });
}

// ========== Auto-save Form Data (Local Storage) ==========
function enableAutoSave(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, textarea, select');
    
    // Load saved data
    inputs.forEach(input => {
        const savedValue = localStorage.getItem(`${formId}_${input.name}`);
        if (savedValue && input.type !== 'password') {
            input.value = savedValue;
        }
    });
    
    // Save on input
    inputs.forEach(input => {
        input.addEventListener('input', function() {
            if (this.type !== 'password') {
                localStorage.setItem(`${formId}_${this.name}`, this.value);
            }
        });
    });
    
    // Clear on submit
    form.addEventListener('submit', function() {
        inputs.forEach(input => {
            localStorage.removeItem(`${formId}_${input.name}`);
        });
    });
}

// ========== Keyboard Shortcuts ==========
document.addEventListener('keydown', function(e) {
    // Ctrl + S to save form
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        const submitBtn = document.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.click();
    }
    
    // Ctrl + F to focus search
    if (e.ctrlKey && e.key === 'f') {
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            e.preventDefault();
            searchInput.focus();
        }
    }
});

// ========== Confirmation Before Leaving Page ==========
window.addEventListener('beforeunload', function(e) {
    const forms = document.querySelectorAll('form.was-validated');
    if (forms.length > 0) {
        e.preventDefault();
        e.returnValue = '';
    }
});

// ========== Utility Functions ==========
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-IN', {
        style: 'currency',
        currency: 'INR'
    }).format(amount);
}

function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('en-IN', options);
}

function calculateDaysUntilExpiry(expiryDate) {
    const today = new Date();
    const expiry = new Date(expiryDate);
    const diffTime = expiry - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}

// ========== Console Welcome Message ==========
console.log('%c MediStock ', 'background: #2563eb; color: white; font-size: 20px; font-weight: bold; padding: 10px;');
console.log('%c Medicine Inventory Management System ', 'color: #2563eb; font-size: 14px;');
console.log('%c Version 1.0.0 ', 'color: #10b981; font-size: 12px;');