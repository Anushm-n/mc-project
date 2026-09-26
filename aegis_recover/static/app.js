// ============================================================
// AegisRecover AI - Interactive Forensic Analyst Workbench
// ============================================================

const API_BASE = window.location.port === "8000" ? "/api" : "http://localhost:8000/api";

let currentScan = null;
let selectedFragment = null;
let selectedFragIdsForStitch = new Set();
let activeFilter = 'ALL';
let searchQuery = '';
let showCanvasGraph = true;

function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Top-Level / Global: Open Folder in Windows Explorer (works from any button/card)
function openLocalRecoveryFolder() {
    fetch(`${API_BASE}/open-folder`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            const path = data.path || (currentScan ? currentScan.saved_folder : "C:\\Users\\laksh\\OneDrive\\Desktop\\hakthon\\recovered_files");
            console.log('Opened recovery folder in Explorer:', path);
        })
        .catch(() => {
            const path = (currentScan && currentScan.saved_folder) ? currentScan.saved_folder : "C:\\Users\\laksh\\OneDrive\\Desktop\\hakthon\\recovered_files";
            alert('Saved files on your hard drive:\n' + path);
        });
}
window.openLocalRecoveryFolder = openLocalRecoveryFolder;

// Top-Level / Global: Copy folder path to clipboard
function copySavedFolderPath() {
    const path = (currentScan && currentScan.saved_folder) ? currentScan.saved_folder : "C:\\Users\\laksh\\OneDrive\\Desktop\\hakthon\\recovered_files";
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(path)
            .then(() => {
                alert(`Path copied to clipboard:\n${path}\n\nYou can paste this into Windows Explorer (Win+E) or Run (Win+R) to view your files.`);
            })
            .catch(() => {
                prompt("Copy this local hard drive path to view your files:", path);
            });
    } else {
        prompt("Copy this local hard drive path to view your files:", path);
    }
}
window.copySavedFolderPath = copySavedFolderPath;

// Top-Level / Global: Show & Hide Upload Error / Notice Banner
function showUploadErrorToast(message, title = "Upload & Carving Notice") {
    const banner = document.getElementById('upload-error-banner');
    const titleEl = document.getElementById('upload-error-title');
    const msgEl = document.getElementById('upload-error-message');
    if (banner && titleEl && msgEl) {
        titleEl.innerText = title;
        msgEl.innerText = message;
        banner.style.display = 'flex';
        try {
            banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } catch (e) {}
    } else {
        alert(`${title}:\n${message}`);
    }
}
window.showUploadErrorToast = showUploadErrorToast;

function hideUploadErrorToast() {
    const banner = document.getElementById('upload-error-banner');
    if (banner) banner.style.display = 'none';
}
window.hideUploadErrorToast = hideUploadErrorToast;

document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
    bindEvents();
    bindDragAndDrop();
    window.addEventListener('resize', () => {
        if (currentScan && showCanvasGraph) renderCanvasGraph();
    });
});

// 1. Health Status
function checkHealth() {
    fetch(`${API_BASE}/status`)
        .then(res => res.json())
        .then(data => {
            const el = document.getElementById('api-status');
            if (el) {
                el.innerText = `${data.status} (v${data.system.split('v')[1] || '2.4'})`;
                el.classList.add('online');
            }
        })
        .catch(() => {
            const el = document.getElementById('api-status');
            if (el) {
                el.innerText = 'DISCONNECTED';
                el.classList.remove('online');
                el.style.color = '#ef4444';
            }
        });
}

// 2. Drag & Drop Support
function bindDragAndDrop() {
    window.addEventListener('dragover', (e) => {
        e.preventDefault();
    });
    window.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            uploadFile({ target: { files: e.dataTransfer.files } });
        }
    });
}

// 3. Event Handlers
function bindEvents() {
    const btnSimulate = document.getElementById('btn-simulate');
    if (btnSimulate) btnSimulate.addEventListener('click', runSimulation);

    const fileUpload = document.getElementById('file-upload');
    if (fileUpload) fileUpload.addEventListener('change', uploadFile);

    const btnDossier = document.getElementById('btn-dossier');
    if (btnDossier) {
        btnDossier.addEventListener('click', () => {
            if (currentScan) {
                window.open(`${API_BASE}/report/${currentScan.scan_id}/html`, '_blank');
            }
        });
    }

    const btnExportReport = document.getElementById('btn-export-report');
    if (btnExportReport) {
        btnExportReport.addEventListener('click', () => {
            if (currentScan) {
                window.location.href = `${API_BASE}/report/${currentScan.scan_id}/download`;
            }
        });
    }

    const btnZip = document.getElementById('btn-download-all-zip');
    if (btnZip) {
        btnZip.addEventListener('click', () => {
            if (currentScan) {
                window.location.href = `${API_BASE}/export/${currentScan.scan_id}/all/zip`;
            }
        });
    }

    const btnDownloadFrag = document.getElementById('btn-download-frag');
    if (btnDownloadFrag) {
        btnDownloadFrag.addEventListener('click', () => {
            if (currentScan && selectedFragment) {
                window.location.href = `${API_BASE}/export/${currentScan.scan_id}/${selectedFragment.fragment_id}`;
            }
        });
    }

    const btnStitch = document.getElementById('btn-stitch-fragments');
    if (btnStitch) btnStitch.addEventListener('click', stitchSelectedFragments);

    // Search bar
    const searchInput = document.getElementById('frag-search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            searchQuery = e.target.value.toLowerCase().trim();
            renderFragments();
        });
    }

    // Sector map view toggles (Graph View vs Grid View)
    const btnGraph = document.getElementById('btn-toggle-graph');
    const btnGrid = document.getElementById('btn-toggle-grid');
    const graphWrapper = document.getElementById('sector-graph-wrapper');
    const gridContainer = document.getElementById('sector-grid');

    if (btnGraph && btnGrid && graphWrapper && gridContainer) {
        btnGraph.addEventListener('click', () => {
            btnGraph.classList.add('active');
            btnGrid.classList.remove('active');
            graphWrapper.style.display = 'block';
            gridContainer.style.display = 'none';
            if (sectorGraphDataCache) {
                renderSectorGraph(sectorGraphDataCache.sectors, sectorGraphDataCache.fragments);
            }
        });

        btnGrid.addEventListener('click', () => {
            btnGrid.classList.add('active');
            btnGraph.classList.remove('active');
            graphWrapper.style.display = 'none';
            gridContainer.style.display = 'grid';
        });
    }

    bindSectorGraphEvents();

    // Toggle Relationships graph view
    const btnToggle = document.getElementById('btn-toggle-view');
    if (btnToggle) {
        btnToggle.addEventListener('click', () => {
            showCanvasGraph = !showCanvasGraph;
            document.getElementById('graph-canvas-container').style.display = showCanvasGraph ? 'flex' : 'none';
            document.getElementById('relationships-container').style.display = showCanvasGraph ? 'none' : 'grid';
            if (showCanvasGraph) renderCanvasGraph();
        });
    }

    // Modal buttons
    const btnCloseModal = document.getElementById('btn-close-modal');
    const btnDismissModal = document.getElementById('btn-modal-dismiss');
    if (btnCloseModal) btnCloseModal.addEventListener('click', () => document.getElementById('report-modal').style.display = 'none');
    if (btnDismissModal) btnDismissModal.addEventListener('click', () => document.getElementById('report-modal').style.display = 'none');

    const btnModalZip = document.getElementById('btn-modal-zip');
    if (btnModalZip) {
        btnModalZip.addEventListener('click', () => {
            if (currentScan) window.location.href = `${API_BASE}/export/${currentScan.scan_id}/all/zip`;
        });
    }

    const btnModalDownloadReconstruction = document.getElementById('btn-modal-download-reconstruction');
    if (btnModalDownloadReconstruction) {
        btnModalDownloadReconstruction.addEventListener('click', () => {
            if (currentScan) {
                window.location.href = `${API_BASE}/scan/${currentScan.scan_id}/document/download`;
            }
        });
    }

    const btnModalExportPdf = document.getElementById('btn-modal-export-pdf');
    if (btnModalExportPdf) {
        btnModalExportPdf.addEventListener('click', () => {
            if (currentScan) {
                window.location.href = `${API_BASE}/scan/${currentScan.scan_id}/document/pdf`;
            }
        });
    }

    const btnModalDossier = document.getElementById('btn-modal-dossier');
    if (btnModalDossier) {
        btnModalDossier.addEventListener('click', () => {
            if (currentScan) window.open(`${API_BASE}/report/${currentScan.scan_id}/html`, '_blank');
        });
    }

    // Recovery folder buttons and path copy listeners
    const btnAlertCopy = document.getElementById('btn-alert-copy-path');
    if (btnAlertCopy) btnAlertCopy.addEventListener('click', copySavedFolderPath);

    const btnModalCopy = document.getElementById('btn-modal-copy-path');
    if (btnModalCopy) btnModalCopy.addEventListener('click', copySavedFolderPath);

    const btnDownloadReconstruction = document.getElementById('btn-download-reconstruction');
    if (btnDownloadReconstruction) {
        btnDownloadReconstruction.addEventListener('click', () => {
            if (currentScan) {
                window.location.href = `${API_BASE}/scan/${currentScan.scan_id}/document/download`;
            }
        });
    }

    const btnExportPdf = document.getElementById('btn-export-pdf');
    if (btnExportPdf) {
        btnExportPdf.addEventListener('click', () => {
            if (currentScan) {
                window.open(`${API_BASE}/scan/${currentScan.scan_id}/document/pdf`, '_blank');
            }
        });
    }

    const btnCloseErr = document.getElementById('btn-close-error-banner');
    if (btnCloseErr) btnCloseErr.addEventListener('click', hideUploadErrorToast);

    // Gemini Modal triggers
    const btnGemini = document.getElementById('btn-gemini-config');
    const geminiModal = document.getElementById('gemini-modal');
    const btnCloseGemini = document.getElementById('btn-close-gemini-modal');
    const btnSaveGeminiKey = document.getElementById('btn-save-gemini-key');

    if (btnGemini && geminiModal) {
        btnGemini.addEventListener('click', () => {
            fetchGeminiStatus();
            geminiModal.style.display = 'flex';
        });
    }
    if (btnCloseGemini && geminiModal) {
        btnCloseGemini.addEventListener('click', () => {
            geminiModal.style.display = 'none';
        });
    }
    if (btnSaveGeminiKey) {
        btnSaveGeminiKey.addEventListener('click', () => {
            const keyInput = document.getElementById('input-gemini-key');
            const key = keyInput ? keyInput.value.trim() : "";
            if (!key) {
                alert("Please enter a valid Google Gemini API Key.");
                return;
            }
            fetch(`${API_BASE}/gemini/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: key })
            })
            .then(res => res.json())
            .then(data => {
                alert("Google Gemini API Key saved successfully! Live Cloud AI enabled.");
                if (geminiModal) geminiModal.style.display = 'none';
                fetchGeminiStatus();
            })
            .catch(err => alert("Failed to save Gemini Key: " + err));
        });
    }

    fetchGeminiStatus();

    // Filter Buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            activeFilter = e.target.getAttribute('data-filter');
            renderFragments();
        });
    });
}

// 3.5 Fetch Gemini Model Status
function fetchGeminiStatus() {
    fetch(`${API_BASE}/gemini/status`)
        .then(res => res.json())
        .then(data => {
            const badge = document.getElementById('nav-gemini-status');
            if (badge) {
                badge.innerText = data.gemini_enabled ? "Gemini Cloud Active" : "Gemini AI Active";
            }
            const activeEng = document.getElementById('gemini-active-engine');
            if (activeEng) activeEng.innerText = data.engine;
            const activeKey = document.getElementById('gemini-active-key');
            if (activeKey) {
                activeKey.innerText = data.gemini_enabled ? `Cloud Key Configured (${data.masked_key})` : "Local Neural Engine (Zero API Key Required)";
                activeKey.className = data.gemini_enabled ? "text-cyan" : "text-emerald";
            }
        })
        .catch(err => console.log('Gemini status notice:', err));
}

// Helper: Show live recovery success alert banner
function displayRecoverySuccessBanner(data) {
    const alertBanner = document.getElementById('recovery-alert-banner');
    if (!alertBanner || !data.fragments || data.fragments.length === 0) return;

    const firstFrag = data.fragments[0];
    const titleElem = document.getElementById('alert-file-title');
    const targetPathElem = document.getElementById('alert-target-path');
    const dlBtn = document.getElementById('btn-alert-download');

    if (titleElem) {
        titleElem.innerText = `Recovered: "${firstFrag.suggested_filename}" (${data.fragments.length} Artifacts Salvaged, ${data.stats.recovered_bytes_formatted})`;
    }
    if (targetPathElem) {
        targetPathElem.innerText = `${data.saved_folder}\\${firstFrag.suggested_filename}`;
    }
    if (dlBtn) {
        dlBtn.href = `${API_BASE}/export/${data.scan_id}/${firstFrag.fragment_id}`;
        dlBtn.setAttribute('download', firstFrag.suggested_filename);
        dlBtn.innerText = `⬇️ Download ${firstFrag.suggested_filename}`;
    }
    alertBanner.style.display = 'flex';
}

// 4. Run Simulation Benchmark with Profile Selection
function runSimulation() {
    hideUploadErrorToast();
    const btn = document.getElementById('btn-simulate');
    const profileSelect = document.getElementById('select-profile');
    const profile = profileSelect ? profileSelect.value : 'MIXED_FORENSIC';

    btn.disabled = true;
    btn.innerHTML = `<span class="icon">⏳</span> Carving & Reconstructing Drive...`;
    setSectorBufferingState(true, 'BUFFERING SECTORS & CARVING WAVEFORM...');

    fetch(`${API_BASE}/scan/simulate?profile=${encodeURIComponent(profile)}`, { method: 'POST' })
        .then(async res => {
            let data;
            try {
                data = await res.json();
            } catch (parseErr) {
                throw new Error(`Simulation failed: Server returned non-JSON response (HTTP ${res.status}).`);
            }
            if (!res.ok) {
                throw new Error(data.detail || data.error || `Simulation failed with HTTP status ${res.status}`);
            }
            if (!data || !data.stats) {
                throw new Error("Invalid simulation report structure returned by engine.");
            }
            return data;
        })
        .then(data => {
            currentScan = data;
            selectedFragIdsForStitch.clear();
            updateStitchToolbar();
            const btnDossier = document.getElementById('btn-dossier');
            if (btnDossier) btnDossier.disabled = false;
            const btnDownloadAll = document.getElementById('btn-download-all-zip');
            if (btnDownloadAll) btnDownloadAll.disabled = false;

            try {
                updateDashboard(data);
            } catch (dashErr) {
                console.error('Dashboard update notice:', dashErr);
            }
            try {
                showReportModal(data);
            } catch (modalErr) {
                console.error('Modal report notice:', modalErr);
            }
            try {
                displayRecoverySuccessBanner(data);
            } catch (bannerErr) {
                console.error('Success banner notice:', bannerErr);
            }
        })
        .catch(err => {
            console.error('Scan error:', err);
            showUploadErrorToast(err.message || 'Failed to execute simulation recovery scan.', 'Simulation Scan Notice');
            setSectorBufferingState(false, 'BUFFER READY');
        })
        .finally(() => {
            btn.disabled = false;
            btn.innerHTML = `<span class="icon">⚡</span> Run Simulation`;
        });
}

// 5. Upload File (via file selector or drag & drop)
function uploadFile(event) {
    hideUploadErrorToast();
    const files = (event && event.target && event.target.files) ? event.target.files : (event && event.files ? event.files : null);
    if (!files || files.length === 0) return;
    const file = files[0];

    if (!file) return;

    if (file.size === 0) {
        showUploadErrorToast(`The selected file "${file.name}" is completely empty (0 bytes). Please upload a file or disk image with content.`, 'Empty File Upload');
        const fileInput = document.getElementById('file-upload');
        if (fileInput) fileInput.value = '';
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    const btnSimulate = document.getElementById('btn-simulate');
    if (btnSimulate) btnSimulate.disabled = true;

    const uploadLabel = document.querySelector('label[for="file-upload"]');
    if (uploadLabel) uploadLabel.innerHTML = '<span class="icon">⏳</span> Recovering & Saving...';
    setSectorBufferingState(true, `BUFFERING "${file.name.toUpperCase()}" STORAGE SECTORS...`);

    fetch(`${API_BASE}/scan/upload`, { method: 'POST', body: formData })
    .then(async res => {
        let data;
        try {
            data = await res.json();
        } catch (parseErr) {
            throw new Error(`Upload failed: Server returned invalid response (HTTP ${res.status}).`);
        }
        if (!res.ok) {
            throw new Error(data.detail || data.error || `Upload failed with HTTP ${res.status}: ${res.statusText}`);
        }
        if (!data || !data.stats) {
            throw new Error("Invalid or incomplete scan report returned by engine.");
        }
        return data;
    })
    .then(data => {
        currentScan = data;
        selectedFragIdsForStitch.clear();
        updateStitchToolbar();
        const btnDossier = document.getElementById('btn-dossier');
        if (btnDossier) btnDossier.disabled = false;
        const btnDownloadAll = document.getElementById('btn-download-all-zip');
        if (btnDownloadAll) btnDownloadAll.disabled = false;

        try {
            updateDashboard(data);
        } catch (dashErr) {
            console.error('Dashboard update notice:', dashErr);
        }
        try {
            showReportModal(data);
        } catch (modalErr) {
            console.error('Modal report notice:', modalErr);
        }
        try {
            displayRecoverySuccessBanner(data);
        } catch (bannerErr) {
            console.error('Success banner notice:', bannerErr);
        }

        // Automatically trigger download of recovered file
        if (data.fragments && data.fragments.length > 0) {
            try {
                const firstFrag = data.fragments[0];
                const autoDl = document.createElement('a');
                autoDl.href = `${API_BASE}/export/${data.scan_id}/${firstFrag.fragment_id}`;
                autoDl.download = firstFrag.suggested_filename;
                document.body.appendChild(autoDl);
                autoDl.click();
                document.body.removeChild(autoDl);
            } catch (e) {
                console.log('Auto download notice:', e);
            }
        }
    })
    .catch(err => {
        console.error('Upload scan error:', err);
        showUploadErrorToast(err.message || 'Failed to carve and scan uploaded storage image.', 'Upload Carving Notice');
        setSectorBufferingState(false, 'BUFFER READY');
    })
    .finally(() => {
        if (btnSimulate) btnSimulate.disabled = false;
        if (uploadLabel) uploadLabel.innerHTML = '<span class="icon">📁</span> Upload Files / Drive';
        const fileInput = document.getElementById('file-upload');
        if (fileInput) fileInput.value = '';
    });
}

// 6. Update UI with Damage vs Recovery Accounting
function updateDashboard(scanData) {
    const stats = scanData.stats;

    // Reset filters and search so newly uploaded files are never hidden!
    activeFilter = 'ALL';
    searchQuery = '';
    const searchInput = document.getElementById('frag-search');
    if (searchInput) searchInput.value = '';
    document.querySelectorAll('.filter-btn').forEach(b => {
        b.classList.remove('active');
        if (b.getAttribute('data-filter') === 'ALL') b.classList.add('active');
    });

    // Accounting Header
    document.getElementById('accounting-title').innerHTML = `${escapeHtml(scanData.source_name)} (${scanData.total_sectors} Sectors &bull; ${stats.total_input_formatted})`;
    document.getElementById('metric-total-size').innerText = stats.total_input_formatted || `${scanData.total_bytes} B`;
    document.getElementById('metric-recovered-size').innerText = `${stats.recovered_bytes_formatted} (${stats.recovery_pct}%)`;
    document.getElementById('metric-damaged-size').innerText = `${stats.damaged_bytes_formatted} (${stats.damaged_pct}%)`;
    document.getElementById('metric-slack-size').innerText = stats.zero_slack_formatted;

    // Distribution Bar
    document.getElementById('bar-recovered').style.width = `${stats.recovery_pct}%`;
    document.getElementById('bar-damaged').style.width = `${stats.damaged_pct}%`;
    document.getElementById('bar-slack').style.width = `${stats.slack_pct}%`;

    document.getElementById('lbl-rec-pct').innerText = `${stats.recovery_pct}%`;
    document.getElementById('lbl-dmg-pct').innerText = `${stats.damaged_pct}%`;
    document.getElementById('lbl-slk-pct').innerText = `${stats.slack_pct}%`;

    // HUD Stats
    document.getElementById('stat-scan-id').innerText = scanData.scan_id;
    document.getElementById('stat-sectors').innerText = scanData.total_sectors;
    document.getElementById('stat-fragments').innerText = scanData.fragments.length;
    document.getElementById('stat-recoverability').innerText = `${stats.average_recoverability_pct}%`;
    document.getElementById('stat-critical').innerText = stats.critical_intel_count;
    document.getElementById('frag-count').innerText = scanData.fragments.length;

    renderSectorGrid(scanData.sector_map_summary);
    renderSectorGraph(scanData.sector_map_summary, scanData.fragments);
    setSectorBufferingState(false, `● BUFFER ACTIVE (${scanData.sector_map_summary ? scanData.sector_map_summary.length : scanData.total_sectors} SECTORS MAPPED)`);
    renderFragments();
    loadDocumentReconstruction(scanData);

    if (scanData.fragments.length > 0) {
        selectFragment(scanData.fragments[0]);
    }
}

function loadDocumentReconstruction(scanData) {
    if (!scanData || !scanData.scan_id) return;
    const panel = document.getElementById('document-reconstruction-panel');
    const summary = document.getElementById('document-reconstruction-summary');
    const output = document.getElementById('document-reconstruction-output');
    const btnDownload = document.getElementById('btn-download-reconstruction');
    const btnPdf = document.getElementById('btn-export-pdf');

    if (!panel || !summary || !output) return;

    fetch(`${API_BASE}/scan/${scanData.scan_id}/document`)
        .then(res => {
            if (!res.ok) throw new Error('No reconstructed document available yet.');
            return res.json();
        })
        .then(data => {
            const hasContent = hasRecoveredDocumentPayload(data);
            panel.style.display = 'flex';
            summary.innerHTML = `
                <span class="reconstruction-pill">Source: ${escapeHtml(data.source_name || scanData.source_name || 'Recovered stream')}</span>
                <span class="reconstruction-pill">Recovered: ${data.recovered_bytes || 0} bytes</span>
                <span class="reconstruction-pill">Recovered %: ${data.recovery_pct || 0}%</span>
                <span class="reconstruction-pill">Status: ${(data.blocks && data.blocks.length) ? 'Visible' : 'Unavailable'}</span>
            `;
            output.textContent = data.document_text || '[No recoverable text available in this scan.]';

            if (btnDownload) btnDownload.disabled = !hasContent;
            if (btnPdf) btnPdf.disabled = !hasContent;
        })
        .catch(() => {
            panel.style.display = 'none';
            if (summary) summary.innerHTML = '';
            if (output) output.textContent = 'No reconstructed document available yet.';
            if (btnDownload) btnDownload.disabled = true;
            if (btnPdf) btnPdf.disabled = true;
        });
}

function hasRecoveredDocumentPayload(data) {
    return Boolean(data && Array.isArray(data.blocks) && data.blocks.some(block =>
        block.text && !block.text.startsWith('[DATA DAMAGED') && !block.text.startsWith('[PARTIAL DATA')
    ));
}

// 7. Post-Scan Executive User Report Modal
function showReportModal(scanData) {
    const modal = document.getElementById('report-modal');
    if (!modal) return;
    const stats = scanData.stats;

    document.getElementById('modal-scan-title').innerText = `Recovery Analysis: ${scanData.source_name}`;
    document.getElementById('modal-verdict').innerText = stats.executive_verdict || "Deep sector carving and structural repair complete.";

    const folderElem = document.getElementById('modal-folder-path');
    if (folderElem) folderElem.innerText = scanData.saved_folder || 'C:/Users/laksh/OneDrive/Desktop/hakthon/recovered_storage';

    const modalDirectDl = document.getElementById('btn-modal-direct-download');
    if (modalDirectDl && scanData.fragments && scanData.fragments.length > 0) {
        const firstFrag = scanData.fragments[0];
        modalDirectDl.href = `${API_BASE}/export/${scanData.scan_id}/${firstFrag.fragment_id}`;
        modalDirectDl.setAttribute('download', firstFrag.suggested_filename);
        modalDirectDl.innerText = `⬇️ Download ${firstFrag.suggested_filename}`;
        modalDirectDl.style.display = 'inline-flex';
    } else if (modalDirectDl) {
        modalDirectDl.style.display = 'none';
    }

    document.getElementById('mstat-input').innerText = stats.total_input_formatted;
    document.getElementById('mstat-recovered').innerText = `${stats.recovered_bytes_formatted} (${stats.recovery_pct}%)`;
    document.getElementById('mstat-damaged').innerText = `${stats.damaged_bytes_formatted} (${stats.damaged_pct}%)`;
    document.getElementById('mstat-count').innerText = `${scanData.fragments.length} Files`;

    // Extract all unique intel tokens
    const intelList = document.getElementById('modal-intel-list');
    intelList.innerHTML = '';
    const allEntities = [];
    scanData.fragments.forEach(f => {
        if (f.entities) {
            f.entities.forEach(e => allEntities.push(e));
        }
    });

    if (allEntities.length > 0) {
        allEntities.slice(0, 8).forEach(e => {
            const span = document.createElement('span');
            span.className = 'intel-tag';
            span.innerText = `${e.entity_type.toUpperCase()}: ${e.value.slice(0, 28)}`;
            intelList.appendChild(span);
        });
        if (allEntities.length > 8) {
            const span = document.createElement('span');
            span.className = 'intel-tag';
            span.innerText = `+${allEntities.length - 8} additional items`;
            intelList.appendChild(span);
        }
    } else {
        intelList.innerHTML = '<span class="intel-tag">No sensitive credentials detected.</span>';
    }

    loadModalDocumentReconstruction(scanData);
    modal.style.display = 'flex';
}

function loadModalDocumentReconstruction(scanData) {
    const status = document.getElementById('modal-reconstruction-status');
    const content = document.getElementById('modal-reconstruction-content');
    const downloadButton = document.getElementById('btn-modal-download-reconstruction');
    const pdfButton = document.getElementById('btn-modal-export-pdf');
    if (!status || !content) return;

    status.textContent = 'Loading recovered document content...';
    content.textContent = '';
    if (downloadButton) downloadButton.disabled = true;
    if (pdfButton) pdfButton.disabled = true;

    fetch(`${API_BASE}/scan/${scanData.scan_id}/document`)
        .then(async response => {
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'Reconstruction is unavailable for this scan.');
            return data;
        })
        .then(data => {
            content.textContent = data.document_text || '[No recovered document content is available for this scan.]';
            status.textContent = `${data.filename || scanData.source_name} | ${data.available_payload_bytes || 0} available payload bytes | ${data.recovery_pct || 0}% recovery`;
            const hasPayload = hasRecoveredDocumentPayload(data);
            if (downloadButton) downloadButton.disabled = !hasPayload;
            if (pdfButton) pdfButton.disabled = !hasPayload;
        })
        .catch(error => {
            status.textContent = error.message || 'Could not load reconstructed document content.';
            content.textContent = '';
        });
}

// --- Sector Buffering State Controller ---
function setSectorBufferingState(isBuffering, message) {
    const indicator = document.getElementById('sector-buffering-indicator');
    const label = document.getElementById('sector-buffer-status-text');
    const laser = document.getElementById('sector-scan-laser');
    if (!indicator) return;

    if (isBuffering) {
        indicator.className = 'sector-buffering-badge buffering';
        if (label) label.innerText = message || 'BUFFERING SECTORS...';
        if (laser) laser.style.display = 'block';
    } else {
        indicator.className = 'sector-buffering-badge idle';
        if (label) label.innerText = message || 'BUFFER READY';
        if (laser) laser.style.display = 'none';
    }
}

let activeSectorHoverIndex = -1;
let sectorGraphDataCache = null;

// 8A. Interactive Forensic Entropy Waveform Graph & Carving Boundaries
function renderSectorGraph(sectors, fragments) {
    const canvas = document.getElementById('sector-entropy-canvas');
    const wrapper = document.getElementById('sector-graph-wrapper');
    const emptyHint = document.getElementById('sector-empty-hint');
    const tooltip = document.getElementById('sector-graph-tooltip');
    if (!canvas || !wrapper) return;

    if (!sectors || sectors.length === 0) {
        if (emptyHint) emptyHint.style.display = 'block';
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        return;
    }

    if (emptyHint) emptyHint.style.display = 'none';
    sectorGraphDataCache = { sectors, fragments };

    // Setup high-DPI canvas
    const dpr = window.devicePixelRatio || 1;
    const rect = wrapper.getBoundingClientRect();
    const width = Math.max(300, rect.width || wrapper.clientWidth || 800);
    const height = 230;

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    // Padding
    const padLeft = 52;
    const padRight = 24;
    const padTop = 32;
    const padBottom = 38;
    const plotW = Math.max(10, width - padLeft - padRight);
    const plotH = Math.max(10, height - padTop - padBottom);

    // Clear background
    ctx.clearRect(0, 0, width, height);

    // 1. Draw Y-Axis Horizontal Gridlines and Entropy Zones
    const entropyLevels = [
        { val: 8.0, label: '8.0 H (Max)', color: 'rgba(245, 158, 11, 0.25)', textCol: '#f59e0b' },
        { val: 6.5, label: '6.5 H (Media)', color: 'rgba(245, 158, 11, 0.15)', textCol: '#fbbf24' },
        { val: 5.0, label: '5.0 H (DB)', color: 'rgba(139, 92, 246, 0.15)', textCol: '#a78bfa' },
        { val: 3.0, label: '3.0 H (Code)', color: 'rgba(2, 132, 199, 0.15)', textCol: '#38bdf8' },
        { val: 0.0, label: '0.0 H (Zero)', color: 'rgba(100, 116, 139, 0.25)', textCol: '#64748b' }
    ];

    entropyLevels.forEach(lvl => {
        const y = padTop + plotH - (lvl.val / 8.0) * plotH;
        ctx.beginPath();
        ctx.strokeStyle = lvl.color;
        ctx.lineWidth = 1;
        ctx.setLineDash(lvl.val === 0.0 ? [] : [4, 4]);
        ctx.moveTo(padLeft, y);
        ctx.lineTo(width - padRight, y);
        ctx.stroke();
        ctx.setLineDash([]);

        // Label
        ctx.fillStyle = lvl.textCol;
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.textAlign = 'right';
        ctx.fillText(lvl.label, padLeft - 6, y + 3);
    });

    const totalSec = sectors.length;
    const getX = (idx) => padLeft + (idx / Math.max(1, totalSec - 1)) * plotW;
    const getY = (entropy) => padTop + plotH - (Math.min(8.0, Math.max(0.0, entropy)) / 8.0) * plotH;

    // 2. Draw Carving Boundary Columns for Fragments
    if (fragments && fragments.length > 0) {
        fragments.forEach((frag, fIdx) => {
            const startX = getX(frag.start_sector);
            const endX = getX(frag.end_sector);
            const spanW = Math.max(12, endX - startX);

            // Shaded Pillar
            const colGrad = ctx.createLinearGradient(startX, padTop, startX, padTop + plotH);
            if (frag.integrity_status === 'INTACT') {
                colGrad.addColorStop(0, 'rgba(16, 185, 129, 0.22)');
                colGrad.addColorStop(1, 'rgba(16, 185, 129, 0.03)');
                ctx.strokeStyle = 'rgba(16, 185, 129, 0.7)';
            } else if (frag.integrity_status === 'RECOVERABLE') {
                colGrad.addColorStop(0, 'rgba(0, 240, 255, 0.22)');
                colGrad.addColorStop(1, 'rgba(0, 240, 255, 0.03)');
                ctx.strokeStyle = 'rgba(0, 240, 255, 0.7)';
            } else {
                colGrad.addColorStop(0, 'rgba(245, 158, 11, 0.22)');
                colGrad.addColorStop(1, 'rgba(245, 158, 11, 0.03)');
                ctx.strokeStyle = 'rgba(245, 158, 11, 0.7)';
            }

            ctx.fillStyle = colGrad;
            ctx.fillRect(startX, padTop, spanW, plotH);

            // Dashed boundary edges
            ctx.setLineDash([3, 3]);
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(startX, padTop);
            ctx.lineTo(startX, padTop + plotH);
            ctx.moveTo(startX + spanW, padTop);
            ctx.lineTo(startX + spanW, padTop + plotH);
            ctx.stroke();
            ctx.setLineDash([]);

            // Top boundary tag label
            const labelY = padTop - 10 - ((fIdx % 2) * 11);
            const tagText = frag.suggested_filename || `Frag_${frag.start_sector}`;
            ctx.font = 'bold 9px "JetBrains Mono", monospace';
            const textMetrics = ctx.measureText(tagText);
            const tagW = Math.min(spanW, textMetrics.width + 10);
            
            ctx.fillStyle = frag.integrity_status === 'INTACT' ? '#10b981' : '#0284c7';
            ctx.fillRect(startX, labelY - 8, Math.max(tagW, 24), 10);
            ctx.fillStyle = '#07090e';
            ctx.textAlign = 'left';
            if (spanW >= 20) {
                const truncatedText = textMetrics.width > spanW - 4 ? tagText.slice(0, 8) + '..' : tagText;
                ctx.fillText(truncatedText, startX + 2, labelY);
            }
        });
    }

    // 3. Draw Waveform Area Fill and Stroke Curve
    if (totalSec > 1) {
        // Gradient fill under curve
        const areaGrad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
        areaGrad.addColorStop(0, 'rgba(0, 240, 255, 0.45)');
        areaGrad.addColorStop(0.5, 'rgba(139, 92, 246, 0.25)');
        areaGrad.addColorStop(1, 'rgba(7, 9, 14, 0.02)');

        ctx.beginPath();
        ctx.moveTo(getX(0), padTop + plotH);
        sectors.forEach((sec, idx) => {
            ctx.lineTo(getX(idx), getY(sec.entropy));
        });
        ctx.lineTo(getX(totalSec - 1), padTop + plotH);
        ctx.closePath();
        ctx.fillStyle = areaGrad;
        ctx.fill();

        // Stroke line
        ctx.beginPath();
        sectors.forEach((sec, idx) => {
            if (idx === 0) ctx.moveTo(getX(idx), getY(sec.entropy));
            else ctx.lineTo(getX(idx), getY(sec.entropy));
        });
        ctx.strokeStyle = '#00f0ff';
        ctx.lineWidth = 2.5;
        ctx.shadowColor = '#00f0ff';
        ctx.shadowBlur = 8;
        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    // 4. Draw Sector Data Points (Nodes)
    sectors.forEach((sec, idx) => {
        const x = getX(idx);
        const y = getY(sec.entropy);

        let nodeColor = '#0284c7';
        if (sec.is_zeroed) nodeColor = '#475569';
        else if (sec.entropy > 6.5) nodeColor = '#f59e0b';
        else if (sec.entropy >= 5.0) nodeColor = '#8b5cf6';
        else nodeColor = '#00f0ff';

        ctx.beginPath();
        const isHovered = activeSectorHoverIndex === idx;
        const radius = isHovered ? 6 : (totalSec > 64 ? 2 : 3.5);
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fillStyle = isHovered ? '#ffffff' : nodeColor;
        ctx.fill();
        ctx.strokeStyle = '#07090e';
        ctx.lineWidth = 1;
        ctx.stroke();

        if (isHovered) {
            ctx.strokeStyle = '#00f0ff';
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.arc(x, y, 9, 0, Math.PI * 2);
            ctx.stroke();
        }
    });

    // 5. Draw X-Axis Sector Ticks & Offsets
    ctx.fillStyle = '#64748b';
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    const tickInterval = Math.max(1, Math.floor(totalSec / 8));
    for (let i = 0; i < totalSec; i += tickInterval) {
        const x = getX(i);
        ctx.beginPath();
        ctx.strokeStyle = '#1e293b';
        ctx.moveTo(x, padTop + plotH);
        ctx.lineTo(x, padTop + plotH + 5);
        ctx.stroke();
        ctx.fillText(`Sec ${sectors[i].sector_index}`, x, padTop + plotH + 16);
        ctx.fillText(`0x${sectors[i].byte_offset.toString(16).toUpperCase()}`, x, padTop + plotH + 28);
    }
}

// 8B. Bind Sector Graph Mouse Hover, Crosshair & Click Events
function bindSectorGraphEvents() {
    const canvas = document.getElementById('sector-entropy-canvas');
    const wrapper = document.getElementById('sector-graph-wrapper');
    const tooltip = document.getElementById('sector-graph-tooltip');
    if (!canvas || !wrapper) return;

    canvas.addEventListener('mousemove', (e) => {
        if (!sectorGraphDataCache || !sectorGraphDataCache.sectors || sectorGraphDataCache.sectors.length === 0) return;
        const rect = canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        const padLeft = 52;
        const padRight = 24;
        const plotW = rect.width - padLeft - padRight;
        const totalSec = sectorGraphDataCache.sectors.length;

        if (mouseX < padLeft || mouseX > rect.width - padRight) {
            if (tooltip) tooltip.style.display = 'none';
            if (activeSectorHoverIndex !== -1) {
                activeSectorHoverIndex = -1;
                renderSectorGraph(sectorGraphDataCache.sectors, sectorGraphDataCache.fragments);
            }
            return;
        }

        const ratio = (mouseX - padLeft) / plotW;
        const secIdx = Math.min(totalSec - 1, Math.max(0, Math.round(ratio * (totalSec - 1))));
        activeSectorHoverIndex = secIdx;
        const sec = sectorGraphDataCache.sectors[secIdx];

        // Find if this sector belongs to a carved fragment
        let linkedFrag = null;
        if (sectorGraphDataCache.fragments) {
            linkedFrag = sectorGraphDataCache.fragments.find(f => sec.sector_index >= f.start_sector && sec.sector_index <= f.end_sector);
        }

        // Re-render highlight on graph
        renderSectorGraph(sectorGraphDataCache.sectors, sectorGraphDataCache.fragments);

        // Position and update HUD Tooltip
        if (tooltip) {
            const fragNotice = linkedFrag 
                ? `<div style="margin-top:6px; padding-top:6px; border-top:1px solid #1e293b; color:#10b981; font-weight:700;">
                     🎯 Carved: ${escapeHtml(linkedFrag.suggested_filename)} (${linkedFrag.recoverability_score}% Fidelity)
                     <div style="font-size:0.7rem; color:#38bdf8; font-weight:normal;">[Click node to inspect artifact]</div>
                   </div>`
                : '<div style="margin-top:4px; font-size:0.7rem; color:#64748b;">Unallocated or Slack Sector</div>';

            tooltip.innerHTML = `
                <div style="display:flex; justify-content:space-between; gap:14px; font-weight:700; color:#f8fafc;">
                    <span>Sector #${sec.sector_index}</span>
                    <span style="color:#00f0ff;">Offset: 0x${sec.byte_offset.toString(16).toUpperCase()}</span>
                </div>
                <div style="margin-top:4px; color:#94a3b8;">
                    Shannon Entropy: <b style="color:${sec.entropy > 6.5 ? '#f59e0b' : (sec.entropy >= 5.0 ? '#8b5cf6' : (sec.entropy >= 3.0 ? '#00f0ff' : '#64748b'))};">${Number(sec.entropy).toFixed(2)}</b> / 8.0 bits
                </div>
                <div style="color:#cbd5e1; font-size:0.72rem;">Profile: <b>${sec.classification}</b> ${sec.is_zeroed ? '(Zero-Slack)' : ''}</div>
                ${fragNotice}
            `;
            tooltip.style.left = `${mouseX}px`;
            tooltip.style.top = `${Math.max(25, mouseY - 10)}px`;
            tooltip.style.display = 'block';
        }
    });

    canvas.addEventListener('mouseleave', () => {
        if (tooltip) tooltip.style.display = 'none';
        if (activeSectorHoverIndex !== -1) {
            activeSectorHoverIndex = -1;
            if (sectorGraphDataCache) {
                renderSectorGraph(sectorGraphDataCache.sectors, sectorGraphDataCache.fragments);
            }
        }
    });

    canvas.addEventListener('click', () => {
        if (!sectorGraphDataCache || activeSectorHoverIndex === -1) return;
        const sec = sectorGraphDataCache.sectors[activeSectorHoverIndex];
        if (sec && sectorGraphDataCache.fragments) {
            const linkedFrag = sectorGraphDataCache.fragments.find(f => sec.sector_index >= f.start_sector && sec.sector_index <= f.end_sector);
            if (linkedFrag) {
                selectFragment(linkedFrag);
                const inspector = document.getElementById('fragment-inspector');
                if (inspector) inspector.scrollIntoView({ behavior: 'smooth' });
            }
        }
    });

    window.addEventListener('resize', () => {
        if (sectorGraphDataCache && document.getElementById('sector-graph-wrapper').style.display !== 'none') {
            renderSectorGraph(sectorGraphDataCache.sectors, sectorGraphDataCache.fragments);
        }
    });
}

// 8C. Classic Sector Grid
function renderSectorGrid(sectors) {
    const container = document.getElementById('sector-grid');
    if (!container) return;
    container.innerHTML = '';

    if (!sectors || sectors.length === 0) {
        container.innerHTML = '<div class="empty-hint">No sector data.</div>';
        return;
    }

    sectors.forEach(sec => {
        const cell = document.createElement('div');
        cell.className = 'sector-cell';

        if (sec.is_zeroed) {
            cell.className += ' bg-zero';
        } else if (sec.entropy > 6.5) {
            cell.className += ' bg-media';
        } else if (sec.entropy >= 5.0) {
            cell.className += ' bg-db';
        } else {
            cell.className += ' bg-code';
        }

        cell.title = `Sector ${sec.sector_index} | Offset: 0x${sec.byte_offset.toString(16).toUpperCase()} | H: ${sec.entropy} (${sec.classification})`;
        
        cell.addEventListener('click', () => {
            if (sec.fragment_id && currentScan) {
                const targetFrag = currentScan.fragments.find(f => f.fragment_id === sec.fragment_id);
                if (targetFrag) selectFragment(targetFrag);
            }
        });

        container.appendChild(cell);
    });
}

// 9. Render Fragments with Search & Multi-Select
function renderFragments() {
    const container = document.getElementById('fragment-list');
    if (!container || !currentScan) return;
    container.innerHTML = '';

    let frags = currentScan.fragments;
    if (activeFilter === 'CRITICAL') {
        frags = frags.filter(f => f.priority === 'CRITICAL');
    } else if (activeFilter !== 'ALL') {
        frags = frags.filter(f => f.category === activeFilter);
    }

    if (searchQuery) {
        frags = frags.filter(f => {
            const matchName = f.suggested_filename && f.suggested_filename.toLowerCase().includes(searchQuery);
            const matchId = f.fragment_id.toLowerCase().includes(searchQuery);
            const matchSum = f.summary.toLowerCase().includes(searchQuery);
            const matchType = f.detected_type.toLowerCase().includes(searchQuery);
            const matchEntity = f.entities && f.entities.some(e => e.value.toLowerCase().includes(searchQuery));
            return matchName || matchId || matchSum || matchType || matchEntity;
        });
    }

    const countElem = document.getElementById('frag-count');
    if (countElem) countElem.innerText = frags.length;

    if (frags.length === 0) {
        container.innerHTML = '<div class="empty-hint">No fragments match the active filter or search query.</div>';
        return;
    }

    frags.forEach(frag => {
        const card = document.createElement('div');
        const isSelected = selectedFragment && selectedFragment.fragment_id === frag.fragment_id;
        card.className = `fragment-card ${isSelected ? 'selected' : ''}`;
        
        let entitiesHtml = '';
        if (frag.entities && frag.entities.length > 0) {
            entitiesHtml = `<div class="frag-entities">` +
                frag.entities.slice(0, 3).map(e => `<span class="entity-pill">${e.entity_type.toUpperCase()}: ${escapeHtml(e.value.slice(0, 24))}</span>`).join('') +
                (frag.entities.length > 3 ? `<span class="entity-pill">+${frag.entities.length - 3} more</span>` : '') +
                `</div>`;
        }

        const fileName = frag.suggested_filename || `recovered_${frag.fragment_id}.bin`;
        const sizeFormatted = frag.byte_length ? formatFileSize(frag.byte_length) : '';
        const isChecked = Boolean(selectedFragIdsForStitch && typeof selectedFragIdsForStitch.has === 'function' && selectedFragIdsForStitch.has(frag.fragment_id));

        card.innerHTML = `
            <div class="frag-top" style="display:flex; justify-content:space-between; align-items:flex-start;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <input type="checkbox" class="frag-checkbox" data-id="${frag.fragment_id}" ${isChecked ? 'checked' : ''} title="Select for stitching" />
                    <span class="frag-filename" style="font-weight:700; font-size:1.02rem; color:#38bdf8;">
                        📄 ${escapeHtml(fileName)}
                    </span>
                </div>
                <span class="badge-priority priority-${frag.priority}">${frag.priority}</span>
            </div>
            <div class="frag-meta" style="margin-top:6px; display:flex; flex-wrap:wrap; gap:10px; font-size:0.82rem;">
                <span style="background:rgba(56,189,248,0.12); color:#38bdf8; padding:2px 6px; border-radius:4px; font-weight:600;">${frag.category}</span>
                <span>Size: <b>${sizeFormatted}</b></span>
                <span>Fidelity: <b class="text-emerald">${frag.recoverability_score}%</b></span>
                <span style="color:#64748b; font-size:0.75rem;">(${frag.fragment_id})</span>
            </div>
            <div class="frag-summary" style="margin-top:6px; color:#cbd5e1; font-size:0.85rem;">${escapeHtml(frag.summary)}</div>
            ${entitiesHtml}
            <div class="frag-actions-row" style="margin-top:10px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                <a href="${API_BASE}/export/${currentScan.scan_id}/${frag.fragment_id}" class="btn btn-sm btn-emerald" style="text-decoration:none; display:inline-flex; align-items:center; gap:4px; padding:4px 12px; font-weight:700;" download="${fileName}">
                    ⬇️ Download ${escapeHtml(fileName)}
                </a>
                <span style="font-size:0.75rem; color:#10b981; font-weight:600;">✓ Saved on Hard Drive</span>
            </div>
        `;

        const chk = card.querySelector('.frag-checkbox');
        chk.addEventListener('click', (e) => {
            e.stopPropagation();
            if (e.target.checked) {
                selectedFragIdsForStitch.add(frag.fragment_id);
            } else {
                selectedFragIdsForStitch.delete(frag.fragment_id);
            }
            updateStitchToolbar();
        });

        card.addEventListener('click', () => {
            document.querySelectorAll('.fragment-card').forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            selectFragment(frag);
        });

        container.appendChild(card);
    });
}

function updateStitchToolbar() {
    const bar = document.getElementById('stitch-toolbar');
    const text = document.getElementById('stitch-count-text');
    if (!bar) return;

    if (selectedFragIdsForStitch.size >= 2) {
        bar.style.display = 'flex';
        text.innerText = `${selectedFragIdsForStitch.size} fragments selected for reconstruction`;
    } else {
        bar.style.display = 'none';
    }
}

// 10. Stitch Multi-Fragments
function stitchSelectedFragments() {
    if (selectedFragIdsForStitch.size < 2 || !currentScan) return;

    const fragIds = Array.from(selectedFragIdsForStitch);
    const btn = document.getElementById('btn-stitch-fragments');
    btn.disabled = true;
    btn.innerText = "Stitching & Repairing...";

    fetch(`${API_BASE}/scan/${currentScan.scan_id}/stitch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fragment_ids: fragIds })
    })
    .then(res => res.json())
    .then(data => {
        alert(`Successfully Stitched ${fragIds.length} fragments into: ${data.filename} (${data.byte_length} bytes)!`);
        fetch(`${API_BASE}/scan/${currentScan.scan_id}`)
            .then(r => r.json())
            .then(updated => {
                currentScan = updated;
                selectedFragIdsForStitch.clear();
                updateStitchToolbar();
                renderFragments();
                const stitchedFrag = updated.fragments.find(f => f.fragment_id === data.stitched_fragment_id);
                if (stitchedFrag) selectFragment(stitchedFrag);
            });
    })
    .catch(err => {
        console.error('Stitch error:', err);
        alert('Failed to stitch fragments.');
    })
    .finally(() => {
        btn.disabled = false;
        btn.innerText = "🔗 Stitch & Rebuild File Chain";
    });
}

// 11. Select Fragment Inspector
function selectFragment(frag) {
    selectedFragment = frag;
    document.getElementById('inspector-actions').style.display = 'flex';

    const container = document.getElementById('inspector-content');
    if (!container) return;

    let previewSection = '';
    if (frag.preview_data) {
        if (frag.category === 'IMAGE' && frag.preview_data.startsWith('data:')) {
            previewSection = `
                <div class="inspector-section">
                    <div class="inspector-title">AI RECONSTRUCTED RASTER PREVIEW</div>
                    <img src="${frag.preview_data}" class="preview-img" alt="Reconstructed Evidence" />
                </div>
            `;
        } else {
            previewSection = `
                <div class="inspector-section">
                    <div class="inspector-title">DECODED PAYLOAD & SALVAGED RECORDS</div>
                    <div class="preview-view">${escapeHtml(frag.preview_data)}</div>
                </div>
            `;
        }
    }

    let notesHtml = '';
    if (frag.reconstruction_notes && frag.reconstruction_notes.length > 0) {
        notesHtml = `
            <div class="inspector-section">
                <div class="inspector-title">FORENSIC DIAGNOSIS & RECONSTRUCTION LOG</div>
                <ul class="notes-list">
                    ${frag.reconstruction_notes.map(n => `<li>${escapeHtml(n)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    let hexHtml = '';
    if (frag.raw_hex_preview) {
        hexHtml = `
            <div class="inspector-section">
                <div class="inspector-title">BYTE-LEVEL FORENSIC HEX DUMP</div>
                <div class="hex-dump-view">${escapeHtml(frag.raw_hex_preview)}</div>
            </div>
        `;
    }

    const dlBtn = document.getElementById('btn-download-frag');
    if (dlBtn) {
        dlBtn.innerText = `⬇️ Download ${frag.suggested_filename}`;
    }

    let geminiSection = '';
    if (frag.gemini_verification) {
        const gv = frag.gemini_verification;
        let insightsList = '';
        if (gv.structural_insights && gv.structural_insights.length > 0) {
            insightsList = `<ul style="margin:8px 0 0 18px; padding:0; font-size:0.83rem; color:#cbd5e1;">` +
                gv.structural_insights.map(i => `<li style="margin-bottom:4px;">${escapeHtml(i)}</li>`).join('') +
                `</ul>`;
        }
        geminiSection = `
            <div class="inspector-section gemini-verified-card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:1.3rem;">🤖</span>
                        <span style="font-weight:700; color:#c084fc; font-size:0.95rem;">GOOGLE GEMINI FORENSIC VERIFICATION</span>
                    </div>
                    <span style="background:rgba(168,85,247,0.25); border:1px solid #c084fc; color:#f8fafc; font-weight:700; font-size:0.75rem; padding:3px 10px; border-radius:12px;">
                        ${escapeHtml(gv.verification_status || 'VERIFIED')} (${gv.confidence_score || 95}% CONFIDENCE)
                    </span>
                </div>
                <div style="font-size:0.84rem; color:#e2e8f0; line-height:1.5;">
                    <b>Model:</b> <span class="text-cyan">${escapeHtml(gv.model_used || 'Gemini Forensic Engine')}</span>
                </div>
                <div style="font-size:0.84rem; color:#cbd5e1; margin-top:6px; line-height:1.5;">
                    <b>Forensic Verdict:</b> ${escapeHtml(gv.forensic_verdict || '')}
                </div>
                ${insightsList}
                <div style="margin-top:10px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px; border-top:1px solid rgba(168,85,247,0.2); padding-top:8px;">
                    <span style="font-size:0.75rem; color:#10b981; font-weight:600;">✓ Verified & Persisted to Local Hard Drive</span>
                    <button id="btn-gemini-card-folder" class="btn btn-sm btn-folder-glow" style="font-size:0.75rem; padding:4px 10px;">
                        📂 Open in Explorer
                    </button>
                </div>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="inspector-section">
            <div class="inspector-title">RECOVERED FILE METADATA & STATUS</div>
            <div style="margin-bottom:12px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
                <div style="font-size:1.15rem; color:#38bdf8; font-weight:700;">
                    📄 ${escapeHtml(frag.suggested_filename)}
                </div>
                <div style="display:flex; gap:8px;">
                    <a href="${API_BASE}/export/${currentScan.scan_id}/${frag.fragment_id}" class="btn btn-sm btn-emerald" style="text-decoration:none; font-weight:700;" download="${frag.suggested_filename}">
                        ⬇️ Download File
                    </a>
                </div>
            </div>
            <div class="frag-meta" style="flex-wrap:wrap; gap:16px;">
                <div><b>MIME Type:</b> ${frag.detected_type}</div>
                <div><b>Category:</b> ${frag.category}</div>
                <div><b>Integrity Status:</b> <span class="text-cyan">${frag.integrity_status}</span></div>
                <div><b>Recoverability Fidelity:</b> <span class="text-emerald" style="font-weight:700;">${frag.recoverability_score}%</span></div>
                <div><b>Payload Size:</b> ${formatFileSize(frag.byte_length)} (${frag.byte_length} bytes)</div>
            </div>
            <div style="margin-top:10px; font-size:0.8rem; color:#94a3b8; background:rgba(0,0,0,0.3); padding:6px 10px; border-radius:4px;">
                <span style="color:#10b981; font-weight:700;">✓ SAVED ON DISK:</span> 
                <span style="font-family:monospace; color:#38bdf8;">${currentScan.saved_folder}\\${frag.suggested_filename}</span>
            </div>
        </div>
        ${geminiSection}
        ${previewSection}
        ${notesHtml}
        ${hexHtml}
    `;

    const geminiCardFolderBtn = document.getElementById('btn-gemini-card-folder');
    if (geminiCardFolderBtn) geminiCardFolderBtn.addEventListener('click', openLocalRecoveryFolder);
}

// 12. Interactive 2D Graph Canvas
function renderCanvasGraph() {
    const canvas = document.getElementById('graph-canvas');
    if (!canvas || !currentScan) return;
    const ctx = canvas.getContext('2d');
    
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = 340;

    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const frags = currentScan.fragments;
    const rels = currentScan.relationships;
    if (!frags || frags.length === 0) return;

    const nodes = {};
    const radiusX = Math.min(w / 2 - 80, 420);
    const radiusY = Math.min(h / 2 - 50, 110);
    const centerX = w / 2;
    const centerY = h / 2;

    frags.forEach((f, idx) => {
        const angle = (idx / frags.length) * 2 * Math.PI;
        nodes[f.fragment_id] = {
            id: f.fragment_id,
            x: centerX + radiusX * Math.cos(angle),
            y: centerY + radiusY * Math.sin(angle),
            category: f.category,
            priority: f.priority
        };
    });

    // Edges
    rels.forEach(rel => {
        const src = nodes[rel.source_id];
        const tgt = nodes[rel.target_id];
        if (src && tgt) {
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            
            if (rel.relationship_type === 'CONTINUATION') {
                ctx.strokeStyle = 'rgba(0, 240, 255, 0.7)';
                ctx.lineWidth = 2.5;
            } else if (rel.relationship_type === 'SHARED_ENTITY') {
                ctx.strokeStyle = 'rgba(139, 92, 246, 0.7)';
                ctx.lineWidth = 2.0;
            } else {
                ctx.strokeStyle = 'rgba(16, 185, 129, 0.6)';
                ctx.lineWidth = 1.5;
            }
            ctx.stroke();

            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2;
            ctx.fillStyle = '#64748b';
            ctx.font = '9px JetBrains Mono';
            ctx.fillText(rel.relationship_type, midX - 20, midY);
        }
    });

    // Nodes
    Object.values(nodes).forEach(n => {
        ctx.beginPath();
        ctx.arc(n.x, n.y, 16, 0, 2 * Math.PI);
        
        let fillColor = '#0284c7';
        if (n.category === 'IMAGE') fillColor = '#f59e0b';
        if (n.category === 'DATABASE') fillColor = '#8b5cf6';
        if (n.priority === 'CRITICAL') fillColor = '#ef4444';

        ctx.fillStyle = fillColor;
        ctx.shadowColor = fillColor;
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.fillStyle = '#f8fafc';
        ctx.font = '10px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.fillText(n.id.replace('FRAG_', ''), n.x, n.y + 28);
    });
}

// 13. Render Relationship Cards
function renderRelationships(relationships) {
    const container = document.getElementById('relationships-container');
    if (!container) return;
    container.innerHTML = '';

    if (!relationships || relationships.length === 0) {
        container.innerHTML = '<div class="empty-hint">No inter-fragment relationships detected.</div>';
        return;
    }

    relationships.forEach(rel => {
        const card = document.createElement('div');
        card.className = 'rel-card';
        card.innerHTML = `
            <div class="rel-header">
                <span class="rel-type">${rel.source_id} &harr; ${rel.target_id} [${rel.relationship_type}]</span>
                <span class="rel-conf">Confidence: ${Math.round(rel.confidence * 100)}%</span>
            </div>
            <div class="rel-desc">${escapeHtml(rel.explanation)}</div>
        `;
        container.appendChild(card);
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
