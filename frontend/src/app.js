/**
 * PCAP Network Analyzer - Frontend JavaScript
 * Gerencia upload, análise e visualização de resultados
 * Com suporte a PostgreSQL, dark mode, filtro por período e geolocalização
 */

// Estado global
let currentData = null;
let trafficChart = null;
let protocolChart = null;
let statusEventSource = null;
// task_id of the analysis this browser started, so we stream/poll only our own
// job (multiple users can analyse concurrently).
let currentTaskId = null;
let ipsDataTable = null;
let protocolsDataTable = null;
let ipProtocolsDataTable = null;
let scansDataTable = null;
let currentViewMode = 'single';  // 'single' ou 'aggregate'
let selectedScanIds = [];
let currentPacketPage = 1;
let currentScanId = null;
// Graph view (B.6) — vis-network instance + datasets, recreated per load.
let graphNetwork = null;
let graphNodesDS = null;
let graphEdgesDS = null;
// Carved files (A.1/A.2/A.4)
let carvedDataTable = null;
let _carvedLastPayload = null;
let _carvedFilter = 'all';

// Filtros ativos da aba de Alertas (severidade x categoria de triagem x selo SOC)
let _alertSeverityFilter = 'all';
let _alertStatusFilter = 'all';
let _alertSocFilter = 'all';

// Categorias de triagem de alertas. 'analisar' é o padrão — todo alerta chega
// nessa categoria. 'falso_positivo' é marcado pelo analista e treina o
// classificador. 'sem_risco' é atribuído automaticamente (pelo classificador
// ou por regras de supressão). Apenas 'analisar' conta no badge vermelho.
const TRIAGE_STATUSES = {
    analisar:       { label: 'Analisar',       badge: 'bg-warning text-dark', btn: 'btn-warning' },
    falso_positivo: { label: 'Falso Positivo', badge: 'bg-info text-dark',    btn: 'btn-info'    },
    resolvido:      { label: 'Resolvido',      badge: 'bg-success',           btn: 'btn-success' },
    sem_risco:      { label: 'Sem Risco',      badge: 'bg-secondary',         btn: 'btn-secondary' }
};

function triageStatusOf(alert) {
    return (alert && alert.triage_status) || 'analisar';
}

// Alertas que ainda exigem atenção do analista — base do badge vermelho.
function countAlertsToAnalyze(alerts) {
    return (alerts || []).filter(a => triageStatusOf(a) === 'analisar').length;
}

// ==================== INICIALIZAÇÃO ====================

// CSRF token bound to the current session. Bootstrapped from /api/auth/me
// or /api/auth/csrf-token before any mutating request fires; refreshed on
// every successful /me and /login response.
let _csrfToken = null;

function setCsrfToken(token) {
    _csrfToken = token || null;
}

// Attach X-CSRF-Token to every jQuery POST/PUT/PATCH/DELETE. The server
// rejects mutating requests without a matching token (defense-in-depth on
// top of SESSION_COOKIE_SAMESITE=Lax).
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        const method = (settings.type || settings.method || 'GET').toUpperCase();
        if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return;
        const url = settings.url || '';
        // Login itself creates the session that owns the token, so it cannot
        // present one. The server exempts this path.
        if (url.indexOf('/api/auth/login') === 0) return;
        if (_csrfToken) {
            xhr.setRequestHeader('X-CSRF-Token', _csrfToken);
        }
    }
});

// Intercepta qualquer resposta 401 globalmente e exibe o modal de login.
// Exclui /api/auth/* que têm tratamento próprio.
$(document).ajaxError(function(event, xhr, settings) {
    if (xhr.status === 401 && !(settings.url || '').includes('/api/auth/')) {
        showLoginModal();
    }
});

$(document).ready(function() {
    console.log('PCAP Analyzer initialized');

    // Carregar tema salvo
    loadTheme();

    // Verificar autenticação antes de qualquer coisa
    checkAuth();

    // Event listeners - Upload
    $('#pcap-file').on('change', handleFileSelect);
    $('#upload-btn').on('click', uploadFile);

    // Event listeners - Settings
    $('#save-thresholds-btn').on('click', saveThresholds);
    $('#add-range-btn').on('click', addTrustedRange);
    $('#add-soc-btn').on('click', addSocIp);
    $('#soc-default-mode').on('change', saveSocDefaultMode);
    $('#clear-analysis-btn').on('click', clearAnalysis);
    $('button[data-bs-target="#settings"]').on('shown.bs.tab', loadSocIps);

    // Event listeners - Filtros de alertas (severidade)
    $('[data-filter]').on('click', function() {
        _alertSeverityFilter = $(this).data('filter');
        $('[data-filter]').removeClass('active');
        $(this).addClass('active');
        applyAlertFilters();
    });

    // Event listeners - Filtros de alertas (categoria de triagem)
    $('[data-status-filter]').on('click', function() {
        _alertStatusFilter = $(this).data('status-filter');
        $('[data-status-filter]').removeClass('active');
        $(this).addClass('active');
        applyAlertFilters();
    });

    // Event listeners - Filtros de alertas (selo SOC)
    $('[data-soc-filter]').on('click', function() {
        _alertSocFilter = $(this).data('soc-filter');
        $('[data-soc-filter]').removeClass('active');
        $(this).addClass('active');
        applyAlertFilters();
    });

    $('#alerts-bulk-fp-btn').on('click', bulkMarkFilteredAsFP);

    // Event listeners - View mode
    $('#view-single-btn').on('click', function() {
        setViewMode('single');
    });
    $('#view-aggregate-btn').on('click', function() {
        setViewMode('aggregate');
    });

    // Event listeners - Scan selection (usa delegação para funcionar com header clonado pelo DataTables)
    $(document).on('change', '.select-all-scans-cb', function() {
        const checked = $(this).prop('checked');
        $('.select-all-scans-cb').prop('checked', checked);
        if (scansDataTable) {
            scansDataTable.rows().nodes().to$().find('.scan-checkbox').prop('checked', checked);
        } else {
            $('.scan-checkbox').prop('checked', checked);
        }
        updateSelectedScans();
    });

    $(document).on('change', '.scan-checkbox', function() {
        updateSelectedScans();
    });

    // Event listeners - Aggregate actions
    $('#view-selected-btn').on('click', viewSelectedScans);
    $('#view-all-btn').on('click', viewAllScans);
    $('#close-aggregate-view').on('click', closeAggregateView);

    // Event listeners - IP Names
    $('#save-ip-name-btn').on('click', saveIpName);
    $('#add-ip-name-btn').on('click', addIpNameFromModal);
    $('#export-ip-names-btn').on('click', exportIpNames);
    $('#import-ip-names-btn').on('click', () => $('#import-ip-names-file').trigger('click'));
    $('#import-ip-names-file').on('change', importIpNamesFromFile);
    $('#cancel-edit-ip-name').on('click', function(ev) { ev.preventDefault(); resetIpNameForm(); });
    $('#ipNamesModal').on('hidden.bs.modal', resetIpNameForm);

    // Event listeners - Packets tab
    $('button[data-bs-target="#packets"]').on('shown.bs.tab', function() {
        if (currentScanId && $('#packets-tbody tr').length <= 1) {
            loadPackets(1);
        }
    });

    // Event listeners - Kill-chain tab
    $('button[data-bs-target="#killchain"]').on('shown.bs.tab', function() {
        if (currentScanId) loadKillchain();
    });
    $('#killchain-show-empty').on('change', function() {
        if (currentScanId) loadKillchain();
    });
    $('#killchain-reload').on('click', function() {
        if (currentScanId) loadKillchain();
    });
    $('#killchain-export-navigator').on('click', function() {
        if (!currentScanId) {
            alert('Selecione um scan primeiro.');
            return;
        }
        exportMitreNavigatorLayer(currentScanId);
    });

    // Event listeners - Graph tab (B.6)
    $('button[data-bs-target="#graph"]').on('shown.bs.tab', function() {
        if (currentScanId && !graphNetwork) loadGraph();
    });
    $('#graph-reload').on('click', function() {
        if (currentScanId) loadGraph();
    });
    $('#graph-fit').on('click', function() {
        if (graphNetwork) graphNetwork.fit({animation: {duration: 400}});
    });
    $('#graph-top-n, #graph-layout, #graph-hide-isolated').on('change', function() {
        if (currentScanId) loadGraph();
    });

    // Event listeners - Carved tab (A.1/A.2/A.4)
    $('button[data-bs-target="#carved"]').on('shown.bs.tab', function() {
        if (currentScanId && !carvedDataTable) loadCarvedFiles();
    });
    $('#carved-reload').on('click', function() {
        if (currentScanId) loadCarvedFiles();
    });
    $('input[name="carved-filter"]').on('change', function() {
        _carvedFilter = $(this).val();
        if (_carvedLastPayload) renderCarvedFiles(_carvedLastPayload);
    });
    // Expand/collapse details row on chevron click.
    $('#carved-table tbody').on('click', 'td.carved-detail-toggle', function() {
        if (!carvedDataTable) return;
        const tr = $(this).closest('tr');
        const row = carvedDataTable.row(tr);
        const sha = tr.attr('data-sha256');
        const file = sha && _carvedLastPayload
            ? (_carvedLastPayload.files || []).find(f => f.sha256 === sha)
            : null;
        if (row.child.isShown()) {
            row.child.hide();
            tr.removeClass('carved-row-open');
            $(this).find('i').removeClass('fa-chevron-down').addClass('fa-chevron-right');
        } else {
            row.child(file ? _buildCarvedDetailHtml(file) : '<em class="text-muted">sem detalhes</em>').show();
            tr.addClass('carved-row-open');
            $(this).find('i').removeClass('fa-chevron-right').addClass('fa-chevron-down');
        }
    });

    // Event listeners - Modals
    $('#ipNamesModal').on('show.bs.modal', loadIpNamesModal);

    // Event listeners - Protocolos: alternar entre Por Protocolo / Por IP
    $('#protocols-view-by-proto').on('click', function() {
        $(this).addClass('active');
        $('#protocols-view-by-ip').removeClass('active');
        $('#protocols-by-proto-section').show();
        $('#protocols-by-ip-section').hide();
        if (protocolsDataTable) {
            protocolsDataTable.columns.adjust();
        }
    });
    $('#protocols-view-by-ip').on('click', function() {
        $(this).addClass('active');
        $('#protocols-view-by-proto').removeClass('active');
        $('#protocols-by-ip-section').show();
        $('#protocols-by-proto-section').hide();
        if (ipProtocolsDataTable) {
            ipProtocolsDataTable.columns.adjust();
        }
    });

});

// ==================== DARK MODE ====================

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('pcap-analyzer-theme', newTheme);
    updateThemeIcon(newTheme);
    updateChartColors(newTheme);
}

function loadTheme() {
    const savedTheme = localStorage.getItem('pcap-analyzer-theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

function updateChartColors(theme) {
    const textColor = theme === 'dark' ? '#e0e0e0' : '#666';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';

    if (trafficChart) {
        trafficChart.options.scales.x.ticks.color = textColor;
        trafficChart.options.scales.y.ticks.color = textColor;
        trafficChart.options.scales.x.grid.color = gridColor;
        trafficChart.options.scales.y.grid.color = gridColor;
        trafficChart.update();
    }
    if (protocolChart) {
        protocolChart.options.plugins.legend.labels.color = textColor;
        protocolChart.update();
    }
}

// ==================== DATE FILTER ====================

function applyDateFilter() {
    const dateFrom = $('#filter-date-from').val();
    const dateTo = $('#filter-date-to').val();

    if (!dateFrom && !dateTo) {
        showNotify('Selecione pelo menos uma data para filtrar.', 'warning');
        return;
    }

    loadScanHistory(dateFrom, dateTo);

    // Mostrar indicação do filtro ativo
    let filterText = 'Filtro ativo: ';
    if (dateFrom && dateTo) {
        filterText += `${formatDateBR(dateFrom)} a ${formatDateBR(dateTo)}`;
    } else if (dateFrom) {
        filterText += `a partir de ${formatDateBR(dateFrom)}`;
    } else {
        filterText += `até ${formatDateBR(dateTo)}`;
    }
    $('#filter-status-text').text(filterText).addClass('text-primary');
}

function clearDateFilter() {
    $('#filter-date-from').val('');
    $('#filter-date-to').val('');
    $('#filter-status-text').text('').removeClass('text-primary');
    loadScanHistory();
}

function formatDateBR(dateStr) {
    const parts = dateStr.split('-');
    return `${parts[2]}/${parts[1]}/${parts[0]}`;
}

// ==================== VIEW MODE ====================

function setViewMode(mode) {
    currentViewMode = mode;

    if (mode === 'single') {
        $('#view-single-btn').addClass('active');
        $('#view-aggregate-btn').removeClass('active');
        $('#aggregate-actions').hide();
        $('.scan-checkbox, #select-all-scans').prop('checked', false);
    } else {
        $('#view-single-btn').removeClass('active');
        $('#view-aggregate-btn').addClass('active');
        $('#aggregate-actions').show();
    }
}

function updateSelectedScans() {
    selectedScanIds = [];
    $('.scan-checkbox:checked').each(function() {
        selectedScanIds.push(parseInt($(this).data('scan-id')));
    });

    if (selectedScanIds.length > 0) {
        $('#view-selected-btn').prop('disabled', false);
    } else {
        $('#view-selected-btn').prop('disabled', true);
    }
}

function viewSelectedScans() {
    if (selectedScanIds.length === 0) {
        showNotify('Selecione pelo menos um scan', 'warning');
        return;
    }

    const dateFrom = $('#filter-date-from').val();
    const dateTo = $('#filter-date-to').val();
    loadResults(null, 'aggregate', selectedScanIds, dateFrom, dateTo);
    $('#view-mode-indicator').show();
    $('#view-mode-text').text(`Visualizando: ${selectedScanIds.length} scans selecionados (Agregado)`);
}

function viewAllScans() {
    const dateFrom = $('#filter-date-from').val();
    const dateTo = $('#filter-date-to').val();
    loadResults(null, 'aggregate', null, dateFrom, dateTo);
    $('#view-mode-indicator').show();

    let text = 'Visualizando: Todos os scans (Agregado)';
    if (dateFrom || dateTo) {
        text += ' - com filtro de período';
    }
    $('#view-mode-text').text(text);
}

function closeAggregateView() {
    $('#view-mode-indicator').hide();
    checkForResults();
}

// ==================== SCAN HISTORY ====================

function loadScanHistory(dateFrom, dateTo) {
    let url = '/api/scans';
    const params = [];

    if (dateFrom) params.push('date_from=' + dateFrom);
    if (dateTo) params.push('date_to=' + dateTo);

    if (params.length > 0) {
        url += '?' + params.join('&');
    }

    $.ajax({
        url: url,
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderScanHistory(response.data);
            }
        },
        error: function(xhr) {
            console.error('Error loading scan history:', xhr);
        }
    });
}

function renderScanHistory(scans) {
    // Destruir DataTable existente antes de reconstruir
    if (scansDataTable) {
        scansDataTable.destroy();
        scansDataTable = null;
    }

    const tbody = $('#scans-tbody');
    tbody.empty();

    if (!scans || scans.length === 0) {
        tbody.html(`
            <tr>
                <td colspan="8" class="text-center text-muted">
                    Nenhum scan realizado ainda
                </td>
            </tr>
        `);
        return;
    }

    scans.forEach(scan => {
        // Usa start_time (data do 1º pacote no pcap) como data principal;
        // analyzed_at (data de inserção) aparece no tooltip.
        const sortKey = scan.start_time || scan.analyzed_at;
        const captureDate = sortKey
            ? new Date(sortKey).toLocaleString('pt-BR')
            : '—';
        const uploadDate = new Date(scan.analyzed_at).toLocaleString('pt-BR');

        const alertBadge = scan.alert_count > 0 ?
            `<span class="badge bg-danger">${scan.alert_count}</span>` :
            `<span class="badge bg-success">0</span>`;

        const row = `
            <tr>
                <td><input type="checkbox" class="scan-checkbox" data-scan-id="${scan.id}" value="${scan.id}"></td>
                <td><code>${escHtml(scan.filename)}</code></td>
                <td data-order="${escHtml(sortKey || '')}">
                    <small title="Inserido: ${escHtml(uploadDate)}">${escHtml(captureDate)}</small>
                </td>
                <td>${formatNumber(scan.packet_count)}</td>
                <td>${formatBytes(scan.total_bytes)}</td>
                <td>${scan.ip_count}</td>
                <td data-order="${scan.alert_count}">${alertBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewScan(${scan.id})" title="Ver">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteScan(${scan.id})" title="Excluir">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.append(row);
    });

    scansDataTable = $('#scans-table').DataTable({
        scrollY: '270px',
        scrollCollapse: true,
        paging: false,
        ordering: true,
        order: [[2, 'desc']],
        language: {
            url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json'
        },
        columnDefs: [
            { orderable: false, searchable: false, targets: [0, 7] }
        ],
        initComplete: function() {
            // Adiciona a classe ao checkbox clonado no header visível pelo DataTables
            $(this.api().table().header())
                .find('input[type="checkbox"]')
                .addClass('select-all-scans-cb');
        }
    });
}

function viewScan(scanId) {
    currentScanId = scanId;
    loadResults(scanId, 'single');
    $('#view-mode-indicator').hide();
    resetGraphView();
    resetCarvedView();
}

function deleteScan(scanId) {
    confirmAction({
        title: 'Excluir scan',
        message: 'Tem certeza que deseja excluir este scan? O registro da análise será removido do sistema. O arquivo PCAP original será mantido em disco.',
        confirmText: 'Excluir',
        danger: true
    }).then(ok => {
        if (!ok) return;
        $.ajax({
            url: `/api/scans/${scanId}`,
            type: 'DELETE',
            success: function(response) {
                if (response.success) {
                    loadScanHistory();
                    showNotify('Scan excluído com sucesso', 'success');
                }
            },
            error: function(xhr) {
                showNotify('Erro ao excluir scan', 'error');
            }
        });
    });
}

function deleteSelectedScans() {
    const selectedIds = [];
    $('.scan-checkbox:checked').each(function() {
        selectedIds.push(parseInt($(this).val()));
    });

    if (selectedIds.length === 0) {
        showNotify('Nenhum scan selecionado para exclusão.', 'warning');
        return;
    }

    confirmAction({
        title: 'Excluir scans selecionados',
        message: `Tem certeza que deseja excluir ${selectedIds.length} scan(s)? Os registros das análises serão removidos do sistema. Os arquivos PCAP originais serão mantidos em disco. Esta ação não pode ser desfeita.`,
        confirmText: 'Excluir',
        danger: true
    }).then(ok => {
        if (!ok) return;
        $.ajax({
            url: '/api/scans/batch',
            type: 'DELETE',
            contentType: 'application/json',
            data: JSON.stringify({ ids: selectedIds }),
            success: function(response) {
                if (response.success) {
                    loadScanHistory();
                    showNotify(response.message, 'success');
                }
            },
            error: function(xhr) {
                showNotify('Erro ao excluir scans selecionados', 'error');
            }
        });
    });
}

// ==================== UPLOAD E ANÁLISE ====================

function handleFileSelect() {
    const file = $('#pcap-file')[0].files[0];
    if (file) {
        $('#upload-btn').prop('disabled', false);
    } else {
        $('#upload-btn').prop('disabled', true);
    }
}

function uploadFile() {
    const fileInput = $('#pcap-file')[0];
    const file = fileInput.files[0];

    if (!file) {
        showNotify('Por favor, selecione um arquivo', 'warning');
        return;
    }

    // Verificar extensão
    const validExtensions = ['pcap', 'pcapng'];
    const extension = file.name.split('.').pop().toLowerCase();

    if (!validExtensions.includes(extension)) {
        showNotify('Arquivo inválido. Use .pcap ou .pcapng', 'warning');
        return;
    }

    // Preparar FormData
    const formData = new FormData();
    formData.append('file', file);

    // Mostrar progresso
    $('#upload-progress').show();
    $('#progress-bar').css('width', '0%').text('0%');
    $('#progress-message').text('Uploading file...');
    $('#progress-phase').text('upload');
    $('#progress-packets').text('0');
    $('#progress-bytes').text('0 B');
    $('#progress-elapsed').text('0s');
    $('#upload-btn').prop('disabled', true);
    updateStatus('analyzing', 'Uploading file...');

    // Upload
    $.ajax({
        url: '/api/upload',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            console.log('Upload successful:', response);
            currentTaskId = response.task_id || null;
            startStatusStream(currentTaskId);
        },
        error: function(xhr) {
            console.error('Upload error:', xhr);
            const error = xhr.responseJSON?.error || 'Erro no upload';
            showNotify('Erro: ' + error, 'error');
            $('#upload-progress').hide();
            $('#upload-btn').prop('disabled', false);
            updateStatus('idle', 'Idle');
        }
    });
}

// Open a Server-Sent Events stream to /api/status/stream. The backend
// closes the stream on its own after a terminal state ('completed' or
// 'error') is delivered; we also close defensively on the client side
// so the EventSource does not auto-reconnect once the scan is done.
function startStatusStream(taskId) {
    stopStatusStream();
    if (taskId) {
        currentTaskId = taskId;
    }

    const url = currentTaskId
        ? '/api/status/stream?task_id=' + encodeURIComponent(currentTaskId)
        : '/api/status/stream';

    let source;
    try {
        source = new EventSource(url);
    } catch (err) {
        console.error('EventSource unsupported, falling back to polling:', err);
        return fallbackToPolling();
    }
    statusEventSource = source;

    source.onmessage = function(event) {
        let status;
        try {
            status = JSON.parse(event.data);
        } catch (err) {
            console.error('Bad SSE payload:', err, event.data);
            return;
        }
        applyStatusUpdate(status);
    };

    source.onerror = function(err) {
        // EventSource fires onerror both for transient drops (state ===
        // CONNECTING after) and for terminal closes (state === CLOSED).
        // We only need to fall back when the connection is dead AND the
        // scan is still in progress.
        console.warn('SSE error:', err);
        if (source.readyState === EventSource.CLOSED) {
            stopStatusStream();
            // If the upload card is still showing, server may have died
            // mid-scan — try a one-shot poll to recover state.
            if ($('#upload-progress').is(':visible')) {
                fallbackToPolling();
            }
        }
    };
}

function stopStatusStream() {
    if (statusEventSource) {
        statusEventSource.close();
        statusEventSource = null;
    }
}

// Used when SSE is unavailable (very old browsers) or after a connection
// drop while a scan is still running. Performs a single status fetch and,
// if the scan is still active, reopens the SSE feed.
function fallbackToPolling() {
    $.ajax({
        url: currentTaskId
            ? '/api/status?task_id=' + encodeURIComponent(currentTaskId)
            : '/api/status',
        type: 'GET',
        success: function(status) {
            applyStatusUpdate(status);
            if (status.status === 'analyzing') {
                setTimeout(() => startStatusStream(currentTaskId), 1000);
            }
        },
        error: function(xhr) {
            console.error('Status fallback failed:', xhr);
        }
    });
}

function applyStatusUpdate(status) {
    updateStatus(status.status, status.message);

    const progress = status.progress || 0;
    $('#progress-bar').css('width', progress + '%').text(progress + '%');
    $('#progress-message').text(status.message || 'Processing...');

    // Detalhes granulares (Fase 1): fase, pacotes, bytes, tempo.
    $('#progress-phase').text(status.phase || '—');
    $('#progress-packets').text(
        (status.packet_count || 0).toLocaleString('pt-BR')
    );
    const bytesRead = status.bytes_read || 0;
    const fileSize = status.file_size || 0;
    if (fileSize > 0) {
        $('#progress-bytes').text(
            formatBytes(bytesRead) + ' / ' + formatBytes(fileSize)
        );
    } else {
        $('#progress-bytes').text(formatBytes(bytesRead));
    }
    $('#progress-elapsed').text(formatElapsed(status.elapsed_seconds));

    if (status.status === 'completed') {
        stopStatusStream();
        currentTaskId = null;
        setTimeout(() => {
            loadResults();
            loadScanHistory();
            $('#upload-progress').hide();
            $('#upload-btn').prop('disabled', false);
            $('#pcap-file').val('');
        }, 500);
    }

    if (status.status === 'error') {
        stopStatusStream();
        currentTaskId = null;
        showNotify('Erro na análise: ' + status.message, 'error');
        $('#upload-progress').hide();
        $('#upload-btn').prop('disabled', false);
        updateStatus('idle', 'Idle');
    }
}

function formatBytes(n) {
    if (!n || n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 100 ? 0 : 1) + ' ' + units[i];
}

function formatElapsed(seconds) {
    if (!seconds || seconds < 0) return '0s';
    const s = Math.floor(seconds);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    const r = s % 60;
    if (m < 60) return m + 'm ' + r + 's';
    const h = Math.floor(m / 60);
    return h + 'h ' + (m % 60) + 'm';
}

function updateStatus(status, message) {
    const statusIndicator = $('#status-indicator i');
    const statusText = $('#status-text');

    switch(status) {
        case 'idle':
            statusIndicator.removeClass().addClass('fas fa-circle text-secondary');
            break;
        case 'analyzing':
            statusIndicator.removeClass().addClass('fas fa-spinner fa-spin text-primary');
            break;
        case 'completed':
            statusIndicator.removeClass().addClass('fas fa-check-circle text-success');
            break;
        case 'error':
            statusIndicator.removeClass().addClass('fas fa-times-circle text-danger');
            break;
    }

    statusText.text(message || status);
}

// ==================== CARREGAMENTO DE RESULTADOS ====================

function checkForResults() {
    $.ajax({
        url: '/api/results',
        type: 'GET',
        success: function(response) {
            if (response.success && response.data) {
                loadResults();
            }
        },
        error: function() {
            // Sem resultados, ignorar
        }
    });
}

function loadResults(scanId = null, view = 'single', scanIds = null, dateFrom = null, dateTo = null) {
    let url = '/api/results';
    const params = [];

    if (view === 'aggregate') {
        params.push('view=aggregate');
        if (scanIds && scanIds.length > 0) {
            params.push('scan_ids=' + scanIds.join(','));
        }
        if (dateFrom) params.push('date_from=' + dateFrom);
        if (dateTo) params.push('date_to=' + dateTo);
    } else if (scanId) {
        params.push('scan_id=' + scanId);
    }

    if (params.length > 0) {
        url += '?' + params.join('&');
    }

    $.ajax({
        url: url,
        type: 'GET',
        success: function(response) {
            if (response.success && response.data) {
                currentData = response.data;
                if (response.scan_id) {
                    currentScanId = response.scan_id;
                }
                renderResults(currentData);
                $('#results-section').fadeIn();
                updateStatus('completed', 'Analysis completed');
            }
        },
        error: function(xhr) {
            console.error('Error loading results:', xhr);
            if (xhr.status !== 404) {
                showNotify('Erro ao carregar resultados', 'error');
            }
        }
    });
}

function renderResults(data) {
    // Track current scan ID for packets/reports
    if (data.summary && data.summary.scan_id) {
        currentScanId = data.summary.scan_id;
    }

    renderOverview(data);
    renderIPs(data);
    renderProtocols(data);
    renderAlerts(data);

    // Enable/disable report buttons
    if (currentScanId) {
        $('#download-pdf-btn, #download-html-btn').prop('disabled', false);
    } else {
        $('#download-pdf-btn, #download-html-btn').prop('disabled', true);
    }
}

// ==================== RENDERIZAÇÃO: VISÃO GERAL ====================

function renderOverview(data) {
    const summary = data.summary || {};
    const alerts = data.alerts || [];
    const protocols = data.protocols || [];
    const ips = data.ips || [];

    // Métricas
    $('#metric-packets').text(formatNumber(summary.packet_count || 0));
    $('#metric-bytes').text(formatBytes(summary.total_bytes || 0));
    $('#metric-duration').text(formatDuration(summary.duration || 0));
    $('#metric-ips').text(ips.length);
    $('#metric-protocols').text(protocols.length);
    // Métrica e badge contam apenas alertas em "Analisar" — as demais
    // categorias (Falso Positivo, Resolvido, Sem Risco) não somam.
    refreshAlertBadge(alerts);

    // Gráficos
    renderTrafficChart(data.traffic_timeline || []);
    renderProtocolChart(protocols);

    // Alertas recentes — apenas os que ainda precisam de análise
    renderRecentAlerts(alerts.filter(a => triageStatusOf(a) === 'analisar').slice(0, 5));
}

// Atualiza o badge vermelho e a métrica de alertas. Conta só "Analisar".
function refreshAlertBadge(alerts) {
    if (!alerts) {
        alerts = (currentData && currentData.alerts) || [];
    }
    const n = countAlertsToAnalyze(alerts);
    $('#metric-alerts').text(n);
    $('#alerts-badge').text(n);
}

function renderTrafficChart(timeline) {
    const ctx = document.getElementById('traffic-chart');
    if (!ctx) return;

    if (trafficChart) {
        trafficChart.destroy();
    }

    const theme = document.documentElement.getAttribute('data-theme');
    const textColor = theme === 'dark' ? '#e0e0e0' : '#666';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';

    if (!timeline || timeline.length === 0) {
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Sem dados'],
                datasets: [{
                    label: 'Bytes',
                    data: [0],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: textColor }, grid: { color: gridColor } },
                    y: { ticks: { color: textColor }, grid: { color: gridColor } }
                }
            }
        });
        return;
    }

    const labels = timeline.map(t => {
        const date = new Date(t.timestamp * 1000);
        return date.toLocaleTimeString();
    });

    const data = timeline.map(t => t.bytes);

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Bytes',
                data: data,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: textColor }, grid: { color: gridColor } },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: textColor,
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    },
                    grid: { color: gridColor }
                }
            }
        }
    });
}

function renderProtocolChart(protocols) {
    const ctx = document.getElementById('protocol-chart');
    if (!ctx) return;

    if (protocolChart) {
        protocolChart.destroy();
    }

    const theme = document.documentElement.getAttribute('data-theme');
    const textColor = theme === 'dark' ? '#e0e0e0' : '#666';

    const top5 = protocols.slice(0, 5);
    const labels = top5.map(p => p.name);
    const data = top5.map(p => p.bytes);

    const colors = [
        'rgba(255, 99, 132, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(255, 206, 86, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(153, 102, 255, 0.8)'
    ];

    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: textColor }
                }
            }
        }
    });
}

function renderRecentAlerts(alerts) {
    const container = $('#recent-alerts');
    container.empty();

    if (alerts.length === 0) {
        container.html('<p class="text-muted">Nenhum alerta detectado</p>');
        return;
    }

    alerts.forEach(alert => {
        const severityClass = getSeverityClass(alert.severity);
        const severityIcon = getSeverityIcon(alert.severity);

        const idTag = (alert.id !== undefined && alert.id !== null)
            ? `<span class="badge bg-dark ms-1">#${escHtml(String(alert.id))}</span>` : '';
        const socTag = alert.soc_match
            ? `<span class="badge bg-primary ms-1" title="${escHtml('SOC: ' + (alert.soc_match.cidr || ''))}">SOC</span>` : '';
        const alertHtml = `
            <div class="alert alert-${severityClass} alert-dismissible fade show" role="alert">
                <i class="${severityIcon}"></i>
                <strong>${escHtml(alert.title)}</strong> ${idTag}${socTag}<br>
                ${escHtml(alert.description)}
                ${renderAlertEndpointsCompact(alert)}
                ${alert.filename ? `<br><small class="text-muted">Arquivo: ${escHtml(alert.filename)}</small>` : ''}
            </div>
        `;

        container.append(alertHtml);
    });
}

// ==================== RENDERIZAÇÃO: IPs ====================

function renderIPs(data) {
    const ips = data.ips || [];
    const tbody = $('#ips-tbody');

    if (ipsDataTable) {
        ipsDataTable.clear().destroy();
    }
    tbody.empty();

    ips.forEach(ip => {
        const typeLabel = ip.is_local ?
            '<span class="badge bg-primary">Local</span>' :
            '<span class="badge bg-secondary">Externo</span>';

        const protocolsBadges = ip.protocols.map(p =>
            `<span class="badge bg-info">${p}</span>`
        ).join(' ');

        const alertsBadge = ip.alert_count > 0 ?
            `<span class="badge bg-danger">${ip.alert_count}</span>` :
            '<span class="badge bg-success">0</span>';

        const nameCell = ip.name ?
            `<span class="text-success">${escapeHtml(ip.name)}</span>` :
            '<span class="text-muted">-</span>';

        const deviceType = ip.device_type || 'Computador';
        const deviceBadge = deviceTypeBadge(deviceType);

        const groupCell = ip.group ?
            `<span class="badge bg-info">${escapeHtml(ip.group)}</span>` :
            '<span class="text-muted">-</span>';

        // Geolocalização — values come from ip-api.com, treat as untrusted.
        let geoCell = '<span class="text-muted">-</span>';
        if (ip.geolocation) {
            const geo = ip.geolocation;
            const flag = getCountryFlag(geo.country_code);
            const titleStr = `${geo.city || ''}, ${geo.region || ''}, ${geo.country || ''} | ISP: ${geo.isp || ''}`;
            const label = geo.city || geo.country || '';
            geoCell = `<span title="${escHtml(titleStr)}">${flag} ${escHtml(label)}</span>`;
        } else if (ip.is_local) {
            geoCell = '<span class="text-muted">Local</span>';
        }

        // Reputação
        let reputationCell = '<span class="text-muted">-</span>';
        if (ip.reputation) {
            const rep = ip.reputation;
            const score = rep.reputation_score || 0;
            let badgeClass = 'bg-success';
            let label = 'Clean';
            if (rep.is_malicious || score >= 70) {
                badgeClass = 'bg-danger';
                label = 'Malicious';
            } else if (score >= 30) {
                badgeClass = 'bg-warning text-dark';
                label = 'Suspicious';
            }
            reputationCell = `<span class="badge ${badgeClass}" title="Score: ${score}/100">${label} (${score})</span>`;
        } else if (ip.is_local) {
            reputationCell = '<span class="text-muted">Local</span>';
        }

        // Risk score (0-100, computed server-side from severity × persistence × reputation × baseline-deviation)
        const riskScore = Number.isFinite(ip.risk_score) ? ip.risk_score : 0;
        let riskClass = 'bg-success';
        if (riskScore >= 70) riskClass = 'bg-danger';
        else if (riskScore >= 40) riskClass = 'bg-warning text-dark';
        else if (riskScore >= 15) riskClass = 'bg-info text-dark';
        const breakdown = ip.risk_breakdown || {};
        const riskTitle = `severity: ${breakdown.severity || 0} | persistence: ${breakdown.persistence || 0} | reputation: ${breakdown.reputation || 0} | baseline: ${breakdown.baseline_deviation || 0}`;
        const riskCell = `<span class="badge ${riskClass}" data-order="${riskScore}" title="${escHtml(riskTitle)}">${riskScore}</span>`;

        const ipEsc = escHtml(ip.ip);
        const row = `
            <tr>
                <td><code>${ipEsc}</code></td>
                <td>${nameCell}</td>
                <td>${deviceBadge}</td>
                <td>${groupCell}</td>
                <td>${typeLabel}</td>
                <td>${geoCell}</td>
                <td>${reputationCell}</td>
                <td data-order="${riskScore}">${riskCell}</td>
                <td>${formatNumber(ip.packets_sent)}</td>
                <td>${formatNumber(ip.packets_received)}</td>
                <td>${formatBytes(ip.bytes_sent)}</td>
                <td>${formatBytes(ip.bytes_received)}</td>
                <td>${protocolsBadges || '-'}</td>
                <td>${alertsBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="editIpName('${ipEsc}', ${escHtml(JSON.stringify(ip.name || ''))}, '', ${escHtml(JSON.stringify(deviceType))})" title="Editar Nome">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="showIpEvolution('${ipEsc}')" title="Ver Evolução">
                        <i class="fas fa-chart-line"></i>
                    </button>
                </td>
            </tr>
        `;

        tbody.append(row);
    });

    ipsDataTable = $('#ips-table').DataTable({
        order: [[7, 'desc']],  // Sort by risk score by default
        pageLength: 25,
        language: {
            url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json'
        }
    });
}

function deviceTypeBadge(t) {
    const map = {
        'Computador': 'bg-primary',
        'Roteador': 'bg-warning text-dark',
        'Impressora': 'bg-info text-dark',
        'IoT': 'bg-secondary',
        'Smartphone': 'bg-success',
        'Servidor': 'bg-dark',
        'Switch': 'bg-warning text-dark',
        'NAS': 'bg-dark',
        'Camera': 'bg-secondary',
        'TV/Streaming': 'bg-secondary',
        'Console': 'bg-secondary',
        'Virtual': 'bg-secondary',
        'Desconhecido': 'bg-light text-dark'
    };
    const cls = map[t] || 'bg-primary';
    return `<span class="badge ${cls}">${escapeHtml(t)}</span>`;
}

function getCountryFlag(countryCode) {
    if (!countryCode) return '';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

// ==================== RENDERIZAÇÃO: PROTOCOLOS ====================

function renderProtocols(data) {
    const protocols = data.protocols || [];
    const tbody = $('#protocols-tbody');

    if (protocolsDataTable) {
        protocolsDataTable.clear().destroy();
    }
    tbody.empty();

    protocols.forEach(proto => {
        const riskBadge = getRiskBadge(proto.risk_level);
        const protoEsc = escHtml(proto.name);
        const warnEsc = escHtml(proto.warning || '');

        const warningCell = proto.warning ?
            `<i class="fas fa-exclamation-circle text-warning" title="${warnEsc}"></i> ${warnEsc}` :
            '<span class="text-muted">-</span>';

        // JSON.stringify produces a JS string literal safe to embed inside
        // an onclick="..." attribute once the outer "s have been escaped.
        const onclickArg = escHtml(JSON.stringify(proto.name || ''));
        const row = `
            <tr class="protocol-row" data-protocol="${protoEsc}" style="cursor: pointer;" onclick="showProtocolIPs(${onclickArg})">
                <td><strong>${protoEsc}</strong> <i class="fas fa-search text-muted" title="Clique para ver IPs"></i></td>
                <td>${formatNumber(proto.packets)}</td>
                <td>${formatBytes(proto.bytes)}</td>
                <td>${proto.percentage}%</td>
                <td>${riskBadge}</td>
                <td>${warningCell}</td>
            </tr>
        `;

        tbody.append(row);
    });

    protocolsDataTable = $('#protocols-table').DataTable({
        order: [[2, 'desc']],
        pageLength: 25,
        language: {
            url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json'
        }
    });

    renderIpProtocols(data);
}

function renderIpProtocols(data) {
    const ipProtocols = data.ip_protocols || [];
    const tbody = $('#ip-protocols-tbody');

    if (ipProtocolsDataTable) {
        ipProtocolsDataTable.clear().destroy();
    }
    tbody.empty();

    const ipNames = {};
    (data.ips || []).forEach(ip => { ipNames[ip.ip] = ip.name || ''; });

    ipProtocols.forEach(entry => {
        const typeLabel = entry.is_local
            ? '<span class="badge bg-primary">Local</span>'
            : '<span class="badge bg-secondary">Externo</span>';
        const name = escapeHtml(ipNames[entry.ip] || '-');
        const protoBadges = (entry.protocols || [])
            .slice(0, 6)
            .map(p => `<span class="badge bg-info me-1">${escapeHtml(p.name)}</span>`)
            .join('');
        const extra = (entry.protocols || []).length > 6
            ? `<span class="badge bg-light text-dark">+${entry.protocols.length - 6}</span>`
            : '';

        const ipEsc = encodeURIComponent(entry.ip);
        const row = `
            <tr class="ip-protocols-row" style="cursor: pointer;" onclick="showIpProtocols('${ipEsc}')">
                <td><code>${escapeHtml(entry.ip)}</code> <i class="fas fa-search text-muted" title="Clique para ver protocolos"></i></td>
                <td>${name}</td>
                <td>${typeLabel}</td>
                <td>${protoBadges}${extra}</td>
                <td>${formatNumber(entry.total_packets)}</td>
                <td>${formatBytes(entry.total_bytes)}</td>
            </tr>
        `;
        tbody.append(row);
    });

    ipProtocolsDataTable = $('#ip-protocols-table').DataTable({
        order: [[5, 'desc']],
        pageLength: 25,
        language: {
            url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json'
        }
    });
}

function showIpProtocols(encodedIp) {
    if (!currentData) return;
    const ipAddr = decodeURIComponent(encodedIp);
    const entry = (currentData.ip_protocols || []).find(e => e.ip === ipAddr);

    const ipNames = {};
    (currentData.ips || []).forEach(ip => { ipNames[ip.ip] = ip.name || ''; });

    let content = '';
    if (!entry || !entry.protocols || entry.protocols.length === 0) {
        content = '<p class="text-muted">Nenhum protocolo encontrado para este IP.</p>';
    } else {
        const ipTypeLabel = entry.is_local
            ? '<span class="badge bg-primary">Local</span>'
            : '<span class="badge bg-secondary">Externo</span>';
        const ipName = escapeHtml(ipNames[entry.ip] || '');

        content += `<div class="mb-3">
            <strong>IP:</strong> <code>${escapeHtml(entry.ip)}</code> ${ipTypeLabel}
            ${ipName ? `&nbsp;<span class="text-muted">(${ipName})</span>` : ''}
            <br>
            <small class="text-muted">
                Total: ${formatNumber(entry.total_packets)} pacotes &middot; ${formatBytes(entry.total_bytes)} &middot;
                ${entry.protocols.length} protocolo(s)
            </small>
        </div>`;

        content += '<div class="accordion" id="ipProtocolsAccordion">';
        entry.protocols.forEach((proto, idx) => {
            const accId = `ipproto-${idx}`;
            const peerRows = (proto.peers || []).map(peer => {
                const ptype = peer.is_local
                    ? '<span class="badge bg-primary">Local</span>'
                    : '<span class="badge bg-secondary">Externo</span>';
                const pname = escapeHtml(ipNames[peer.ip] || '-');
                return `<tr>
                    <td><code>${escapeHtml(peer.ip)}</code></td>
                    <td>${pname}</td>
                    <td>${ptype}</td>
                    <td>${formatNumber(peer.packets)}</td>
                    <td>${formatBytes(peer.bytes)}</td>
                </tr>`;
            }).join('');

            const peerTable = peerRows
                ? `<div class="table-responsive"><table class="table table-sm table-striped mb-0">
                        <thead><tr><th>IP</th><th>Nome</th><th>Tipo</th><th>Pacotes</th><th>Bytes</th></tr></thead>
                        <tbody>${peerRows}</tbody>
                   </table></div>`
                : '<p class="text-muted mb-0">Sem peers registrados.</p>';

            content += `
                <div class="accordion-item">
                    <h2 class="accordion-header" id="heading-${accId}">
                        <button class="accordion-button ${idx === 0 ? '' : 'collapsed'}" type="button"
                                data-bs-toggle="collapse" data-bs-target="#collapse-${accId}"
                                aria-expanded="${idx === 0 ? 'true' : 'false'}" aria-controls="collapse-${accId}">
                            <span class="me-2"><strong>${escapeHtml(proto.name)}</strong></span>
                            <span class="badge bg-info me-2">${formatNumber(proto.packets)} pkts</span>
                            <span class="badge bg-success me-2">${formatBytes(proto.bytes)}</span>
                            <span class="badge bg-light text-dark">${(proto.peers || []).length} peer(s)</span>
                        </button>
                    </h2>
                    <div id="collapse-${accId}" class="accordion-collapse collapse ${idx === 0 ? 'show' : ''}"
                         aria-labelledby="heading-${accId}" data-bs-parent="#ipProtocolsAccordion">
                        <div class="accordion-body">${peerTable}</div>
                    </div>
                </div>
            `;
        });
        content += '</div>';
    }

    $('#evolution-ip').text(ipAddr);
    $('#evolution-content').html(content);
    $('#ipEvolutionModal .modal-title').html(`<i class="fas fa-server"></i> Protocolos por IP: ${escapeHtml(ipAddr)}`);
    new bootstrap.Modal('#ipEvolutionModal').show();
}

function showProtocolIPs(protocolName) {
    if (!currentData) return;

    const protocolIps = currentData.protocol_ips ? currentData.protocol_ips[protocolName] : null;

    let content = `<h6>IPs que utilizaram ${escHtml(protocolName)}:</h6>`;

    if (protocolIps && protocolIps.length > 0) {
        content += '<div class="table-responsive"><table class="table table-sm table-striped"><thead><tr><th>IP</th><th>Nome</th><th>Tipo</th><th>Pacotes</th><th>Bytes</th></tr></thead><tbody>';

        const ipNames = {};
        if (currentData.ips) {
            currentData.ips.forEach(ip => {
                ipNames[ip.ip] = ip.name || '';
            });
        }

        protocolIps.forEach(ipData => {
            const typeLabel = ipData.is_local ?
                '<span class="badge bg-primary">Local</span>' :
                '<span class="badge bg-secondary">Externo</span>';
            const name = ipData.name || ipNames[ipData.ip] || '-';

            content += `<tr>
                <td><code>${escHtml(ipData.ip)}</code></td>
                <td>${escapeHtml(name)}</td>
                <td>${typeLabel}</td>
                <td>${formatNumber(ipData.packets)}</td>
                <td>${formatBytes(ipData.bytes)}</td>
            </tr>`;
        });

        content += '</tbody></table></div>';

        const totalPackets = protocolIps.reduce((sum, ip) => sum + ip.packets, 0);
        const totalBytes = protocolIps.reduce((sum, ip) => sum + ip.bytes, 0);
        const localCount = protocolIps.filter(ip => ip.is_local).length;
        const externalCount = protocolIps.length - localCount;

        content += `<hr><div class="row text-center">
            <div class="col-3">
                <strong>${protocolIps.length}</strong><br><small class="text-muted">IPs Total</small>
            </div>
            <div class="col-3">
                <strong>${localCount}</strong><br><small class="text-muted">Locais</small>
            </div>
            <div class="col-3">
                <strong>${externalCount}</strong><br><small class="text-muted">Externos</small>
            </div>
            <div class="col-3">
                <strong>${formatBytes(totalBytes)}</strong><br><small class="text-muted">Total</small>
            </div>
        </div>`;

    } else {
        const ipsWithProtocol = currentData.ips ? currentData.ips.filter(ip =>
            ip.protocols && ip.protocols.includes(protocolName)
        ) : [];

        if (ipsWithProtocol.length === 0) {
            content += '<p class="text-muted">Nenhum IP encontrado</p>';
        } else {
            content += '<div class="table-responsive"><table class="table table-sm"><thead><tr><th>IP</th><th>Nome</th><th>Tipo</th><th>Bytes Env.</th><th>Bytes Rec.</th></tr></thead><tbody>';

            ipsWithProtocol.forEach(ip => {
                const typeLabel = ip.is_local ? 'Local' : 'Externo';
                const name = ip.name || '-';
                content += `<tr><td><code>${escHtml(ip.ip)}</code></td><td>${escHtml(name)}</td><td>${typeLabel}</td><td>${formatBytes(ip.bytes_sent)}</td><td>${formatBytes(ip.bytes_received)}</td></tr>`;
            });

            content += '</tbody></table></div>';
        }
    }

    $('#evolution-ip').text(protocolName);
    $('#evolution-content').html(content);
    $('#ipEvolutionModal .modal-title').html(`<i class="fas fa-layer-group"></i> Protocolo: ${escHtml(protocolName)}`);
    new bootstrap.Modal('#ipEvolutionModal').show();
}

// ==================== NOTIFICAÇÕES ====================

function showNotify(message, type) {
    const cfg = {
        success: { icon: 'fa-check-circle',        color: 'text-success' },
        error:   { icon: 'fa-times-circle',         color: 'text-danger'  },
        warning: { icon: 'fa-exclamation-triangle', color: 'text-warning' },
        info:    { icon: 'fa-info-circle',          color: 'text-info'    }
    };
    const t = cfg[type] || cfg.info;
    $('#notify-modal-icon').attr('class', `fas ${t.icon} fa-2x ${t.color}`);
    $('#notify-modal-body').text(message);
    const el = document.getElementById('notifyModal');
    (bootstrap.Modal.getInstance(el) || new bootstrap.Modal(el)).show();
}

// ==================== CONFIRMAÇÃO ====================

// Modal de confirmação reutilizável — substitui o confirm() do navegador.
// Retorna uma Promise resolvida com o `value` do botão clicado. No caso
// padrão (sem `buttons`) resolve true/false; dispensar o modal resolve false.
function confirmAction(opts) {
    opts = opts || {};
    const danger = !!opts.danger;
    const buttons = opts.buttons || [
        { text: opts.cancelText || 'Cancelar',  value: false, variant: 'secondary' },
        { text: opts.confirmText || 'Confirmar', value: true,
          variant: danger ? 'danger' : 'primary' }
    ];

    $('#confirm-modal-icon').attr('class',
        `fas ${danger ? 'fa-exclamation-triangle' : 'fa-question-circle'} fa-2x ` +
        `${danger ? 'text-danger' : 'text-warning'}`);
    $('#confirm-modal-title').text(opts.title || 'Confirmar ação');
    $('#confirm-modal-body').text(opts.message || '');

    const $footer = $('#confirm-modal-footer').empty();
    const el = document.getElementById('confirmModal');
    const modal = bootstrap.Modal.getInstance(el) || new bootstrap.Modal(el);

    return new Promise(resolve => {
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            resolve(value);
            modal.hide();
        };

        buttons.forEach(btn => {
            $('<button>', {
                type: 'button',
                class: `btn btn-${btn.variant || 'secondary'} px-4`,
                text: btn.text
            }).on('click', () => finish(btn.value)).appendTo($footer);
        });

        // Dispensar (X, ESC, clique fora) equivale a cancelar.
        el.addEventListener('hidden.bs.modal', () => finish(false), { once: true });
        modal.show();
    });
}

// ==================== RENDERIZAÇÃO: ALERTAS ====================

// Resolve o par origem -> destino de um alerta. Detectores de fluxo (port
// scan, host sweep, brute force, etc) gravam src_ip/dst_ip/targets em
// `details`; quando há um destino conhecido mostramos os dois lados de forma
// explícita. Sem destino, cai para a linha "IP:" simples de sempre — o que
// também cobre alertas antigos gravados antes de `details` incluir dst_ip.
function renderAlertEndpoints(alert) {
    const d = alert.details || {};

    // Incidentes (kill-chains) carregam peer_ips/peer_domains + source_role
    // em vez de um único dst_ip. Mostramos os dois lados com papéis
    // explícitos para deixar claro QUEM é o atacante e quem é a vítima.
    if (alert.category === 'incident') {
        const incSrc = d.source_ip || alert.ip || '';
        const role = d.source_role || 'attacker';
        const peers = []
            .concat(Array.isArray(d.peer_ips) ? d.peer_ips : [])
            .concat(Array.isArray(d.peer_domains) ? d.peer_domains : []);
        const peerText = peers.length
            ? peers.slice(0, 6).map(p => `<code>${escHtml(String(p))}</code>`).join(', ') +
              (peers.length > 6 ? ` <small class="text-muted">(+${peers.length - 6})</small>` : '')
            : '<span class="text-muted">não resolvido a partir das detecções</span>';

        let srcLabel, peerLabel, srcBadge;
        if (role === 'compromised_host') {
            srcLabel = 'Host comprometido (vítima)';
            peerLabel = 'Atacante / C2 (contraparte externa)';
            srcBadge = ' <span class="badge bg-warning text-dark">vítima</span>';
        } else {
            srcLabel = 'Atacante (origem)';
            peerLabel = 'Alvo(s)';
            srcBadge = ' <span class="badge bg-danger">atacante</span>';
        }

        let incHtml = '';
        if (incSrc) {
            incHtml += `<p class="mb-1"><strong>${srcLabel}:</strong> <code>${escHtml(incSrc)}</code>${srcBadge}</p>`;
        }
        incHtml += `<p class="mb-1"><strong>${peerLabel}:</strong> ${peerText}</p>`;
        return incHtml;
    }

    const src = d.src_ip || alert.ip || '';
    const dst = d.dst_ip || '';
    const targetsCount = d.targets_count ||
        (Array.isArray(d.targets) ? d.targets.length : 0);

    if (!dst) {
        return alert.ip
            ? `<p class="mb-1"><strong>IP:</strong> <code>${escHtml(alert.ip)}</code></p>`
            : '';
    }

    let dstHtml = `<code>${escHtml(dst)}</code>`;
    if (targetsCount > 1) {
        dstHtml += ` <small class="text-muted">(+${targetsCount - 1} host(s))</small>`;
    }

    let html = '';
    if (src) {
        html += `<p class="mb-1"><strong>IP de origem:</strong> <code>${escHtml(src)}</code></p>`;
    }
    html += `<p class="mb-1"><strong>IP de destino:</strong> ${dstHtml}</p>`;

    // Connection-state badge for detectors that track TCP handshake state.
    // Lets the analyst sort "scan-only" noise from real established
    // connections at a glance. Powered by TcpFlowTracker on the backend.
    if (d.connection_status) {
        const map = {
            established:      { cls: 'bg-danger',           txt: 'Conexão estabelecida' },
            open_no_ack:      { cls: 'bg-warning text-dark', txt: 'Porta aberta — handshake incompleto' },
            icmp_unreachable: { cls: 'bg-info text-dark',    txt: 'ICMP unreachable — pacote bloqueado' },
            scan_rejected:    { cls: 'bg-secondary',        txt: 'Scan rejeitado (RST do servidor)' },
            scan_no_response: { cls: 'bg-secondary',        txt: 'Scan sem resposta' },
        };
        const m = map[d.connection_status];
        if (m) {
            html += `<p class="mb-1"><strong>Estado da conexão:</strong> ` +
                    `<span class="badge ${m.cls}">${m.txt}</span></p>`;
        }
    }
    // Bytes exchanged across the TCP flow(s) backing this alert. Helps the
    // analyst tell "interactive session with data" from "pure handshake".
    if (typeof d.bytes_exchanged === 'number' && d.bytes_exchanged > 0) {
        html += `<p class="mb-1"><strong>Dados trocados:</strong> ` +
                `${formatBytes(d.bytes_exchanged)}</p>`;
    }
    return html;
}

// Variante compacta de renderAlertEndpoints para o widget "Alertas recentes":
// uma única linha <small> inline em vez de parágrafos.
function renderAlertEndpointsCompact(alert) {
    const d = alert.details || {};

    if (alert.category === 'incident') {
        const role = d.source_role || 'attacker';
        const peers = []
            .concat(Array.isArray(d.peer_ips) ? d.peer_ips : [])
            .concat(Array.isArray(d.peer_domains) ? d.peer_domains : []);
        const srcRole = role === 'compromised_host' ? 'Vítima' : 'Atacante';
        const peerRole = role === 'compromised_host' ? 'C2/atacante' : 'Alvo';
        const srcTxt = d.source_ip || alert.ip || '—';
        const peerTxt = peers.length
            ? peers.slice(0, 3).join(', ') +
              (peers.length > 3 ? ` (+${peers.length - 3})` : '')
            : '—';
        return `<br><small>${srcRole}: ${escHtml(srcTxt)} &middot; ` +
               `${peerRole}: ${escHtml(peerTxt)}</small>`;
    }

    const src = d.src_ip || alert.ip || '';
    const dst = d.dst_ip || '';
    const targetsCount = d.targets_count ||
        (Array.isArray(d.targets) ? d.targets.length : 0);

    if (!dst) {
        return alert.ip ? `<br><small>IP: ${escHtml(alert.ip)}</small>` : '';
    }

    let dstText = escHtml(dst);
    if (targetsCount > 1) {
        dstText += ` (+${targetsCount - 1} host(s))`;
    }
    const srcText = src ? `Origem: ${escHtml(src)} &middot; ` : '';
    return `<br><small>${srcText}Destino: ${dstText}</small>`;
}

function renderAlerts(data) {
    const alerts = data.alerts || [];
    const container = $('#alerts-list');
    container.empty();

    if (alerts.length === 0) {
        container.html('<p class="text-muted">Nenhum alerta detectado</p>');
        return;
    }

    alerts.forEach((alert, index) => {
        const severityClass = getSeverityClass(alert.severity);
        const severityIcon = getSeverityIcon(alert.severity);
        const status = triageStatusOf(alert);
        const statusMeta = TRIAGE_STATUSES[status] || TRIAGE_STATUSES.analisar;

        const hasId = alert.id !== undefined && alert.id !== null;
        const dropdownItems = Object.entries(TRIAGE_STATUSES).map(([key, meta]) =>
            `<li><a class="dropdown-item${key === status ? ' active' : ''}" href="#"
                    onclick="changeAlertTriage(${alert.id}, '${key}', this); return false;">
                ${escHtml(meta.label)}
            </a></li>`
        ).join('');
        const triageControl = hasId ? `
            <div class="alert-triage ms-2">
                <div class="dropdown">
                    <button class="btn btn-sm dropdown-toggle triage-btn ${statusMeta.btn}"
                            type="button" data-bs-toggle="dropdown" aria-expanded="false"
                            title="Alterar categoria do alerta">
                        ${escHtml(statusMeta.label)}
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end shadow-sm">${dropdownItems}</ul>
                </div>
            </div>
        ` : `
            <div class="alert-triage ms-2">
                <button class="btn btn-sm triage-btn ${statusMeta.btn}" disabled
                        title="Salve o scan para classificar">
                    ${escHtml(statusMeta.label)}
                </button>
            </div>
        `;

        // MITRE block: only render if the URL looks like a safe http(s) link.
        // Defends against `javascript:` / `data:` payloads that would smuggle
        // XSS through the href attribute even if the rest is escaped.
        let mitreBlock = '';
        if (alert.mitre_attack) {
            const ma = alert.mitre_attack;
            const safeUrl = /^https?:\/\//i.test(ma.url || '') ? ma.url : '';
            const hrefAttr = safeUrl ? ` href="${escHtml(safeUrl)}"` : '';
            mitreBlock = `<p class="mb-1"><strong>MITRE ATT&CK:</strong> ` +
                `<a${hrefAttr} target="_blank" rel="noopener noreferrer"><code>${escHtml(ma.technique_id || '')}</code></a> ` +
                `${escHtml(ma.technique_name || '')} ` +
                `<span class="badge bg-secondary">${escHtml(ma.tactic_name || '')}</span></p>`;
        }

        const sevTag = String(alert.severity || '').toUpperCase();
        // ID rastreável do alerta. Permite localizar e referir-se ao mesmo
        // alerta (ex.: "alerta #1234"). Só existe depois que o scan é salvo.
        const idBadge = hasId
            ? `<span class="badge bg-dark alert-id-badge" title="ID do alerta — use para rastrear e se referir a ele">#${escHtml(String(alert.id))}</span>`
            : '';
        // SOC badge: anotação puramente informativa. Indica que a origem ou
        // destino do alerta cai num range cadastrado em Configurações > IPs do SOC.
        // Não altera severidade nem triagem — o analista decide.
        let socBadge = '';
        const socAttr = alert.soc_match ? 'soc' : 'none';
        if (alert.soc_match) {
            const sm = alert.soc_match;
            const sideTxt = sm.side === 'src' ? 'origem'
                          : sm.side === 'dst' ? 'destino'
                          : 'origem e destino';
            const title = `SOC: IP de ${sideTxt} está em ${sm.cidr}` +
                          (sm.description ? ` (${sm.description})` : '');
            socBadge = `<span class="badge bg-primary ms-1" title="${escHtml(title)}">SOC</span>`;
        }
        const mergedCount = Number(alert.merged_count || 0);
        const mergedBadge = mergedCount > 1
            ? `<span class="badge bg-secondary ms-1" title="${escHtml(`${mergedCount} alertas idênticos consolidados`)}">×${mergedCount}</span>`
            : '';
        const alertHtml = `
            <div class="alert-item alert alert-${severityClass}" data-severity="${escHtml(alert.severity || '')}" data-triage="${escHtml(status)}" data-soc="${socAttr}" data-alert-id="${hasId ? escHtml(String(alert.id)) : ''}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <h6>
                            <i class="${severityIcon}"></i>
                            ${idBadge}
                            ${escHtml(alert.title)}
                            <span class="badge bg-${severityClass}">${escHtml(sevTag)}</span>
                            ${socBadge}
                            ${mergedBadge}
                        </h6>
                        <p class="mb-1">${escHtml(alert.description)}</p>
                        ${renderAlertEndpoints(alert)}
                        <p class="mb-1"><strong>Categoria:</strong> ${escHtml(alert.category || '')}</p>
                        ${mitreBlock}
                        ${alert.filename ? `<p class="mb-1"><small class="text-muted">Arquivo: ${escHtml(alert.filename)}</small></p>` : ''}
                        <p class="mb-2"><em>${escHtml(alert.recommendation || '')}</em></p>
                        ${renderAlertDetails(alert.details)}
                    </div>
                    ${triageControl}
                </div>
            </div>
        `;

        container.append(alertHtml);
    });

    applyAlertFilters();
}

// Persiste a mudança de categoria de um alerta. Marcar como "Falso Positivo"
// treina o classificador no backend (futuros alertas iguais viram "Sem Risco").
function changeAlertTriage(alertId, status, clickedEl) {
    const $item = $(clickedEl).closest('.alert-item');
    const $btn  = $item.find('.triage-btn');
    const previous = $item.attr('data-triage');

    // O onclick inline retorna false (preventDefault), o que em alguns casos
    // impede o auto-close do dropdown do Bootstrap. Fecha manualmente.
    const toggleEl = $btn.get(0);
    if (toggleEl && window.bootstrap && bootstrap.Dropdown) {
        const dd = bootstrap.Dropdown.getInstance(toggleEl) || new bootstrap.Dropdown(toggleEl);
        dd.hide();
    }

    $btn.prop('disabled', true);

    $.ajax({
        url: `/api/alerts/${alertId}/triage`,
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ status: status }),
        success: function(resp) {
            $btn.prop('disabled', false);
            if (!resp || !resp.success) {
                showNotify('Erro ao atualizar categoria: ' + ((resp && resp.error) || 'desconhecido'), 'error');
                return;
            }
            const meta = TRIAGE_STATUSES[status] || TRIAGE_STATUSES.analisar;
            $item.attr('data-triage', status);
            $btn.removeClass('btn-warning btn-info btn-success btn-secondary btn-danger')
                .addClass(meta.btn)
                .text(meta.label);
            $item.find('.dropdown-item').each(function() {
                const key = $(this).attr('onclick')?.match(/'(\w+)'/)?.[1];
                $(this).toggleClass('active', key === status);
            });

            if (currentData && Array.isArray(currentData.alerts)) {
                const a = currentData.alerts.find(x => x.id === alertId);
                if (a) a.triage_status = status;
                refreshAlertBadge(currentData.alerts);
            }
            applyAlertFilters();
        },
        error: function() {
            $btn.prop('disabled', false);
            showNotify('Erro ao atualizar categoria do alerta', 'error');
        }
    });
}

function renderAlertDetails(details) {
    if (!details || Object.keys(details).length === 0) {
        return '';
    }

    function formatValue(value) {
        if (value === null || value === undefined) return '';
        if (Array.isArray(value)) {
            if (value.length === 0) return '';
            // Array de objetos: renderiza como sublista
            if (typeof value[0] === 'object' && value[0] !== null) {
                const items = value.map(obj => {
                    const parts = Object.entries(obj).map(
                        ([k, v]) => `<code>${k}</code>=${escapeHtml(String(v))}`
                    );
                    return '<li>' + parts.join(' &middot; ') + '</li>';
                }).join('');
                return '<ul class="mb-0 ps-3">' + items + '</ul>';
            }
            return value.map(v => escapeHtml(String(v))).join(', ');
        }
        if (typeof value === 'object') {
            return '<code>' + escapeHtml(JSON.stringify(value)) + '</code>';
        }
        return escapeHtml(String(value));
    }

    function escapeHtml(s) {
        return s.replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    let html = '<div class="alert-details"><strong>Detalhes:</strong><ul class="mb-0">';
    for (const [key, value] of Object.entries(details)) {
        html += `<li><strong>${escapeHtml(key)}:</strong> ${formatValue(value)}</li>`;
    }
    html += '</ul></div>';
    return html;
}

// Aplica os três filtros independentes da aba de Alertas: severidade,
// categoria de triagem e selo SOC. Um alerta só aparece se casar com todos.
function applyAlertFilters() {
    $('.alert-item').each(function() {
        const $el = $(this);
        const matchSeverity = _alertSeverityFilter === 'all' ||
            $el.attr('data-severity') === _alertSeverityFilter;
        const matchStatus = _alertStatusFilter === 'all' ||
            $el.attr('data-triage') === _alertStatusFilter;
        const matchSoc = _alertSocFilter === 'all' ||
            $el.attr('data-soc') === _alertSocFilter;
        $el.toggle(matchSeverity && matchStatus && matchSoc);
    });
    // Mostrar o botão "Marcar filtrados como FP" apenas quando o filtro SOC
    // está ativo — fora dele o risco de marcar um alerta legítimo é alto.
    $('#alerts-bulk-fp-btn').toggleClass('d-none', _alertSocFilter !== 'soc');
}

function bulkMarkFilteredAsFP() {
    // Coleta IDs persistidos (sem ID = scan não salvo) dos alertas visíveis.
    const ids = [];
    $('.alert-item:visible').each(function() {
        const id = $(this).attr('data-alert-id');
        if (id) ids.push(parseInt(id, 10));
    });
    if (!ids.length) {
        showNotify('Nenhum alerta visível com ID persistido.', 'warning');
        return;
    }
    confirmAction({
        title: 'Marcar como Falso Positivo',
        message: `Marcar ${ids.length} alerta(s) filtrado(s) como Falso Positivo? ` +
                 'Eles serão usados para treinar o classificador.',
        confirmText: 'Marcar',
        danger: false,
    }).then(ok => {
        if (!ok) return;
        const $btn = $('#alerts-bulk-fp-btn');
        const orig = $btn.html();
        $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Marcando...');
        // Single bulk request instead of one POST per alert.
        $.ajax({
            url: '/api/alerts/triage-bulk',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ alert_ids: ids, status: 'falso_positivo' }),
            success: (resp) => {
                const n = (resp && resp.updated) || 0;
                showNotify(`Concluído: ${n} alerta(s) marcado(s) como Falso Positivo.`, 'success');
                if (currentScanId) loadResults(currentScanId, currentViewMode);
            },
            error: (xhr) => {
                const err = xhr.responseJSON?.error || 'falha ao marcar em lote';
                showNotify('Erro: ' + err, 'error');
            },
            complete: () => { $btn.prop('disabled', false).html(orig); },
        });
    });
}

// ==================== IP NAMES ====================

function editIpName(ip, currentName, currentDesc, currentDeviceType) {
    $('#edit-ip-address').val(ip);
    $('#edit-ip-name').val(currentName);
    $('#edit-ip-description').val(currentDesc);
    $('#edit-ip-device-type').val(currentDeviceType || 'Computador');

    new bootstrap.Modal('#editIpNameModal').show();
}

function saveIpName() {
    const ip = $('#edit-ip-address').val();
    const name = $('#edit-ip-name').val().trim();
    const description = $('#edit-ip-description').val().trim();
    const device_type = $('#edit-ip-device-type').val() || 'Computador';

    if (!name) {
        showNotify('Nome é obrigatório', 'warning');
        return;
    }

    $.ajax({
        url: '/api/ip-names',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip, name, description, device_type }),
        success: function(response) {
            if (response.success) {
                bootstrap.Modal.getInstance('#editIpNameModal').hide();
                loadResults();
                showNotify('Nome salvo com sucesso!', 'success');
            }
        },
        error: function(xhr) {
            showNotify('Erro ao salvar nome', 'error');
        }
    });
}

function loadIpNamesModal() {
    $.ajax({
        url: '/api/ip-names',
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderIpNamesTable(response.data);
            }
        }
    });
}

function renderIpNamesTable(ipNames) {
    const tbody = $('#ip-names-tbody');
    tbody.empty();

    const entries = Object.entries(ipNames);

    if (entries.length === 0) {
        tbody.html('<tr><td colspan="5" class="text-center text-muted">Nenhum nome cadastrado</td></tr>');
        return;
    }

    entries.forEach(([ip, info]) => {
        const dt = info.device_type || 'Computador';
        const safeIp = ip.replace(/'/g, "\\'");
        const row = `
            <tr>
                <td><code>${escapeHtml(ip)}</code></td>
                <td>${escapeHtml(info.name)}</td>
                <td>${deviceTypeBadge(dt)}</td>
                <td>${escapeHtml(info.description || '-')}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary me-1" onclick="editIpNameFromModal('${safeIp}')" title="Editar">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteIpName('${safeIp}')" title="Remover">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.append(row);
    });
}

// Coloca o formulário do modal "Gerenciar Nomes" em modo edição. O IP fica
// somente-leitura e os demais campos são pré-preenchidos. Salvar no mesmo
// formulário usa o endpoint POST (UPSERT), portanto atualiza o registro.
function editIpNameFromModal(ip) {
    const row = $('#ip-names-tbody tr').filter(function() {
        return $(this).find('td:first code').text() === ip;
    });
    if (!row.length) return;

    const name = row.find('td:nth-child(2)').text();
    const description = row.find('td:nth-child(4)').text();
    const descValue = description === '-' ? '' : description;

    // Recupera device_type a partir do dataset carregado (badge não preserva o valor cru).
    $.ajax({
        url: '/api/ip-names',
        type: 'GET',
        success: function(resp) {
            const info = resp && resp.success ? (resp.data[ip] || {}) : {};
            $('#new-ip-address').val(ip).prop('readonly', true);
            $('#new-ip-name').val(info.name || name);
            $('#new-ip-desc').val(info.description || descValue);
            $('#new-ip-device-type').val(info.device_type || 'Computador');
            $('#ip-names-form-title').text('Editar IP');
            $('#add-ip-name-icon').removeClass('fa-plus').addClass('fa-save');
            $('#ip-names-edit-hint').removeClass('d-none');
            $('#new-ip-name').focus();
        }
    });
}

function resetIpNameForm() {
    $('#new-ip-address').val('').prop('readonly', false);
    $('#new-ip-name').val('');
    $('#new-ip-desc').val('');
    $('#new-ip-device-type').val('Computador');
    $('#ip-names-form-title').text('Adicionar Novo');
    $('#add-ip-name-icon').removeClass('fa-save').addClass('fa-plus');
    $('#ip-names-edit-hint').addClass('d-none');
}

function addIpNameFromModal() {
    const ip = $('#new-ip-address').val().trim();
    const name = $('#new-ip-name').val().trim();
    const description = $('#new-ip-desc').val().trim();
    const device_type = $('#new-ip-device-type').val() || 'Computador';

    if (!ip || !name) {
        showNotify('IP e Nome são obrigatórios', 'warning');
        return;
    }

    $.ajax({
        url: '/api/ip-names',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip, name, description, device_type }),
        success: function(response) {
            if (response.success) {
                resetIpNameForm();
                loadIpNamesModal();
                loadResults();
            }
        },
        error: function(xhr) {
            showNotify('Erro ao salvar nome', 'error');
        }
    });
}

function exportIpNames() {
    // Usa fetch para preservar o nome do arquivo definido no Content-Disposition.
    fetch('/api/ip-names/export', { credentials: 'same-origin' })
        .then(resp => {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const cd = resp.headers.get('Content-Disposition') || '';
            const m = cd.match(/filename="?([^"]+)"?/);
            const filename = m ? m[1] : 'ip_names.json';
            return resp.blob().then(blob => ({ blob, filename }));
        })
        .then(({ blob, filename }) => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            showNotify('Lista de IPs exportada', 'success');
        })
        .catch(err => showNotify('Erro ao exportar: ' + err.message, 'error'));
}

function importIpNamesFromFile(ev) {
    const input = ev.target;
    const file = input.files && input.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        let payload;
        try {
            payload = JSON.parse(e.target.result);
        } catch (err) {
            showNotify('Arquivo JSON inválido', 'error');
            input.value = '';
            return;
        }

        confirmAction({
            title: 'Importar IPs do arquivo',
            message: 'Como tratar os IPs que já estão cadastrados? "Sobrescrever" substitui pelos dados do arquivo; "Manter existentes" importa apenas os novos.',
            buttons: [
                { text: 'Cancelar',          value: null,        variant: 'secondary' },
                { text: 'Manter existentes', value: 'skip',      variant: 'primary'   },
                { text: 'Sobrescrever',      value: 'overwrite', variant: 'danger'    }
            ]
        }).then(mode => {
            if (!mode) { input.value = ''; return; }

            $.ajax({
                url: '/api/ip-names/import?mode=' + encodeURIComponent(mode),
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(payload),
                success: function(resp) {
                    input.value = '';
                    if (resp && resp.success) {
                        showNotify(
                            `Importação concluída: ${resp.imported} salvos, ${resp.skipped} ignorados`,
                            'success'
                        );
                        loadIpNamesModal();
                        loadResults();
                    } else {
                        showNotify('Erro: ' + ((resp && resp.error) || 'desconhecido'), 'error');
                    }
                },
                error: function(xhr) {
                    input.value = '';
                    const msg = (xhr.responseJSON && xhr.responseJSON.error) || 'falha de rede';
                    showNotify('Erro ao importar: ' + msg, 'error');
                }
            });
        });
    };
    reader.readAsText(file);
}

function deleteIpName(ip) {
    confirmAction({
        title: 'Remover nome do IP',
        message: `Remover o nome cadastrado para o IP ${ip}?`,
        confirmText: 'Remover',
        danger: true
    }).then(ok => {
        if (!ok) return;
        const encodedIp = ip.replace(/\./g, '-');
        $.ajax({
            url: `/api/ip-names/${encodedIp}`,
            type: 'DELETE',
            success: function(response) {
                if (response.success) {
                    loadIpNamesModal();
                    loadResults();
                }
            },
            error: function(xhr) {
                showNotify('Erro ao remover nome', 'error');
            }
        });
    });
}

// ==================== IP EVOLUTION ====================

function showIpEvolution(ip) {
    const encodedIp = ip.replace(/\./g, '-');

    $('#evolution-ip').text(ip);
    $('#evolution-content').html('<p class="text-muted">Carregando...</p>');
    $('#ipEvolutionModal .modal-title').html(`<i class="fas fa-chart-line"></i> Evolução do IP: <span id="evolution-ip">${ip}</span>`);

    new bootstrap.Modal('#ipEvolutionModal').show();

    $.ajax({
        url: `/api/ip-evolution/${encodedIp}`,
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderIpEvolution(response.data, ip);
            } else {
                $('#evolution-content').html('<p class="text-danger">Erro ao carregar evolução</p>');
            }
        },
        error: function() {
            $('#evolution-content').html('<p class="text-danger">Erro ao carregar evolução</p>');
        }
    });
}

function renderIpEvolution(evolution, ip) {
    const container = $('#evolution-content');

    if (!evolution || evolution.length === 0) {
        container.html('<p class="text-muted">Nenhum histórico encontrado para este IP</p>');
        return;
    }

    let html = `
        <div class="table-responsive">
            <table class="table table-sm table-striped">
                <thead>
                    <tr>
                        <th>Arquivo</th>
                        <th>Data</th>
                        <th>Pacotes Env.</th>
                        <th>Pacotes Rec.</th>
                        <th>Bytes Env.</th>
                        <th>Bytes Rec.</th>
                        <th>Alertas</th>
                    </tr>
                </thead>
                <tbody>
    `;

    evolution.forEach(entry => {
        const date = new Date(entry.analyzed_at).toLocaleString('pt-BR');
        const alertBadge = entry.alert_count > 0 ?
            `<span class="badge bg-danger">${entry.alert_count}</span>` :
            `<span class="badge bg-success">0</span>`;

        html += `
            <tr>
                <td><code>${escHtml(entry.filename)}</code></td>
                <td><small>${escHtml(date)}</small></td>
                <td>${formatNumber(entry.packets_sent)}</td>
                <td>${formatNumber(entry.packets_received)}</td>
                <td>${formatBytes(entry.bytes_sent)}</td>
                <td>${formatBytes(entry.bytes_received)}</td>
                <td>${alertBadge}</td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';

    container.html(html);
}

// ==================== CONFIGURAÇÕES ====================

function loadSettings() {
    $.ajax({
        url: '/api/settings',
        type: 'GET',
        success: function(response) {
            if (response.success && response.data) {
                const settings = response.data;

                const thresholds = settings.thresholds || {};
                $('#threshold-port-scan-min').val(thresholds.port_scan_min_ports || 20);
                $('#threshold-port-scan-time').val(thresholds.port_scan_time_window || 30);
                $('#threshold-arp-gratuitous').val(thresholds.arp_gratuitous_max || 5);
                $('#threshold-dns-subdomain').val(thresholds.dns_subdomain_length || 50);
                $('#threshold-dns-entropy').val(thresholds.dns_entropy_min || 3.5);
                $('#threshold-beaconing-connections').val(thresholds.beaconing_min_connections || 5);
                $('#threshold-beaconing-jitter').val(thresholds.beaconing_max_jitter_percent || 10);
                $('#threshold-brute-force-attempts').val(thresholds.brute_force_attempts || 10);
                $('#threshold-brute-force-time').val(thresholds.brute_force_time_window || 60);

                renderTrustedRanges(settings.trusted_ranges || []);
            }
        },
        error: function(xhr) {
            console.error('Error loading settings:', xhr);
        }
    });
}

function saveThresholds() {
    const thresholds = {
        port_scan_min_ports: parseInt($('#threshold-port-scan-min').val()),
        port_scan_time_window: parseInt($('#threshold-port-scan-time').val()),
        arp_gratuitous_max: parseInt($('#threshold-arp-gratuitous').val()),
        dns_subdomain_length: parseInt($('#threshold-dns-subdomain').val()),
        dns_entropy_min: parseFloat($('#threshold-dns-entropy').val()),
        beaconing_min_connections: parseInt($('#threshold-beaconing-connections').val()),
        beaconing_max_jitter_percent: parseFloat($('#threshold-beaconing-jitter').val()),
        brute_force_attempts: parseInt($('#threshold-brute-force-attempts').val()),
        brute_force_time_window: parseInt($('#threshold-brute-force-time').val())
    };

    $.ajax({
        url: '/api/settings',
        type: 'GET',
        success: function(response) {
            const settings = response.data || {};
            // Merge: preserva thresholds não expostos no formulário (DGA, fast-flux,
            // exfil, ICMP, lateral, ping sweep, etc. — tunáveis via settings.json)
            settings.thresholds = Object.assign({}, settings.thresholds || {}, thresholds);

            $.ajax({
                url: '/api/settings',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(settings),
                success: function() {
                    showNotify('Thresholds salvos com sucesso!', 'success');
                },
                error: function(xhr) {
                    showNotify('Erro ao salvar thresholds', 'error');
                }
            });
        }
    });
}

function renderTrustedRanges(ranges) {
    const container = $('#trusted-ranges-list');
    container.empty();

    if (ranges.length === 0) {
        container.html('<p class="text-muted">Nenhum range configurado</p>');
        return;
    }

    ranges.forEach(range => {
        const cidrEsc = escHtml(range.cidr || '');
        const cidrArg = escHtml(JSON.stringify(range.cidr || ''));
        const rangeHtml = `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded">
                <div>
                    <code>${cidrEsc}</code>
                    <br>
                    <small class="text-muted">${escHtml(range.description || '')}</small>
                </div>
                <button class="btn btn-sm btn-danger" onclick="deleteTrustedRange(${cidrArg})">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        container.append(rangeHtml);
    });
}

function addTrustedRange() {
    const cidr = $('#new-range-cidr').val().trim();
    const description = $('#new-range-desc').val().trim();

    if (!cidr) {
        showNotify('CIDR é obrigatório', 'warning');
        return;
    }

    $.ajax({
        url: '/api/trusted-range',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ cidr, description }),
        success: function() {
            $('#new-range-cidr').val('');
            $('#new-range-desc').val('');
            loadSettings();
            showNotify('Range adicionado com sucesso!', 'success');
        },
        error: function(xhr) {
            const error = xhr.responseJSON?.error || 'Erro ao adicionar range';
            showNotify(error, 'error');
        }
    });
}

function deleteTrustedRange(cidr) {
    confirmAction({
        title: 'Remover range confiável',
        message: `Remover o range ${cidr} da lista de redes confiáveis?`,
        confirmText: 'Remover',
        danger: true
    }).then(ok => {
        if (!ok) return;
        const encodedCidr = cidr.replace('/', '-');
        $.ajax({
            url: `/api/trusted-range/${encodedCidr}`,
            type: 'DELETE',
            success: function() {
                loadSettings();
                showNotify('Range removido com sucesso!', 'success');
            },
            error: function(xhr) {
                showNotify('Erro ao remover range', 'error');
            }
        });
    });
}

// ==================== SOC IPS ====================

const SOC_MODE_LABELS = {
    either:   'Either',
    src_only: 'Apenas origem',
    dst_only: 'Apenas destino',
};

function loadSocIps() {
    $.ajax({
        url: '/api/soc-ips',
        type: 'GET',
        success: function(resp) {
            if (!resp.success) return;
            renderSocIps(resp.soc_ips || []);
            $('#soc-default-mode').val(resp.default_match_mode || 'either');
        },
        error: function() {
            $('#soc-ips-list').html('<p class="text-danger small">Falha ao carregar IPs do SOC.</p>');
        },
    });
}

function renderSocIps(rows) {
    const container = $('#soc-ips-list');
    container.empty();
    if (!rows.length) {
        container.html('<p class="text-muted small mb-0">Nenhum IP do SOC cadastrado.</p>');
        return;
    }
    rows.forEach(r => {
        const cidr = r.cidr || '';
        const cidrEsc = escHtml(cidr);
        const cidrArg = escHtml(JSON.stringify(cidr));
        const mode = SOC_MODE_LABELS[r.match_mode] || r.match_mode || 'either';
        container.append(`
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded">
                <div>
                    <code>${cidrEsc}</code>
                    <span class="badge bg-primary ms-1">${escHtml(mode)}</span>
                    <br>
                    <small class="text-muted">${escHtml(r.description || '')}</small>
                </div>
                <button class="btn btn-sm btn-danger" onclick="deleteSocIp(${cidrArg})">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `);
    });
}

function addSocIp() {
    const cidr = ($('#new-soc-cidr').val() || '').trim();
    const description = ($('#new-soc-desc').val() || '').trim();
    const match_mode = $('#new-soc-mode').val() || 'either';
    if (!cidr) {
        showNotify('CIDR é obrigatório', 'warning');
        return;
    }
    $.ajax({
        url: '/api/soc-ips',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ cidr, description, match_mode }),
        success: function() {
            $('#new-soc-cidr').val('');
            $('#new-soc-desc').val('');
            $('#new-soc-mode').val('either');
            loadSocIps();
            showNotify('IP do SOC adicionado.', 'success');
        },
        error: function(xhr) {
            showNotify(xhr.responseJSON?.error || 'Erro ao adicionar IP do SOC', 'error');
        },
    });
}

function deleteSocIp(cidr) {
    confirmAction({
        title: 'Remover IP do SOC',
        message: `Remover ${cidr} da lista de IPs do SOC?`,
        confirmText: 'Remover',
        danger: true,
    }).then(ok => {
        if (!ok) return;
        const encoded = (cidr || '').replace('/', '-');
        $.ajax({
            url: `/api/soc-ips/${encoded}`,
            type: 'DELETE',
            success: function() {
                loadSocIps();
                showNotify('IP do SOC removido.', 'success');
            },
            error: function(xhr) {
                showNotify(xhr.responseJSON?.error || 'Erro ao remover IP do SOC', 'error');
            },
        });
    });
}

function saveSocDefaultMode() {
    const match_mode = $('#soc-default-mode').val();
    $.ajax({
        url: '/api/soc-default-match-mode',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ match_mode }),
        success: function() {
            showNotify('Modo padrão salvo.', 'success');
        },
        error: function(xhr) {
            showNotify(xhr.responseJSON?.error || 'Erro ao salvar modo padrão', 'error');
        },
    });
}

function clearAnalysis() {
    confirmAction({
        title: 'Limpar análise',
        message: 'Tem certeza que deseja limpar a análise atual?',
        confirmText: 'Limpar',
        danger: true
    }).then(ok => {
        if (!ok) return;
        $.ajax({
            url: '/api/clear',
            type: 'POST',
            success: function() {
                currentData = null;
                $('#results-section').hide();
                updateStatus('idle', 'Idle');
                showNotify('Análise limpa com sucesso!', 'success');
            },
            error: function(xhr) {
                const error = xhr.responseJSON?.error || 'Erro ao limpar análise';
                showNotify(error, 'error');
            }
        });
    });
}

// ==================== AUTENTICAÇÃO ====================

let _loginModal = null;
let _changePasswordModal = null;
let _auditLogModal = null;
let _userMgmtModal = null;
let _adminSettingsModal = null;
let currentUser = null;

function _getLoginModal() {
    if (!_loginModal) {
        _loginModal = new bootstrap.Modal(document.getElementById('loginModal'));
    }
    return _loginModal;
}

function checkAuth() {
    $.ajax({
        url: '/api/auth/me',
        type: 'GET',
        success: function(resp) {
            if (resp.success) {
                setCsrfToken(resp.csrf_token);
                onAuthSuccess(resp.user);
            } else {
                showLoginModal();
            }
        },
        error: function() {
            showLoginModal();
        }
    });
}

function showLoginModal() {
    $('#login-error').addClass('d-none').text('');
    $('#login-form')[0].reset();
    _getLoginModal().show();
}

function onAuthSuccess(user) {
    currentUser = user;
    _getLoginModal().hide();

    // Configure dropdown badge
    $('#nav-username').text(user.username);
    const roleColors = { admin: 'bg-danger', analyst: 'bg-primary', viewer: 'bg-secondary' };
    $('#nav-user-role')
        .text(user.role)
        .removeClass('bg-danger bg-primary bg-secondary')
        .addClass(roleColors[user.role] || 'bg-secondary');

    // Show role-gated menu items
    if (user.role === 'analyst' || user.role === 'admin') {
        $('#nav-audit-log-item').removeClass('d-none');
    }
    if (user.role === 'admin') {
        $('#nav-user-mgmt-item').removeClass('d-none');
        $('#nav-admin-settings-item').removeClass('d-none');
    }

    $('#nav-user-info').removeClass('d-none');
    $('#nav-login-btn').addClass('d-none');

    // Prompt immediate password change if flagged
    if (user.must_change_password) {
        setTimeout(() => showChangePasswordModal(true), 500);
    }

    loadSettings();
    loadScanHistory();
    checkForResults();
}

function submitLogin(event) {
    event.preventDefault();
    const username = $('#login-username').val().trim();
    const password = $('#login-password').val();
    const btn = $('#login-submit-btn');

    btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-1"></i> Entrando...');
    $('#login-error').addClass('d-none');

    $.ajax({
        url: '/api/auth/login',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username, password }),
        success: function(resp) {
            if (resp.success) {
                setCsrfToken(resp.csrf_token);
                onAuthSuccess(resp.user);
            } else {
                $('#login-error').removeClass('d-none').text(resp.error || 'Credenciais inválidas');
            }
        },
        error: function(xhr) {
            const msg = xhr.responseJSON?.error || 'Credenciais inválidas';
            $('#login-error').removeClass('d-none').text(msg);
        },
        complete: function() {
            btn.prop('disabled', false).html('<i class="fas fa-sign-in-alt me-1"></i> Entrar');
        }
    });
}

function logout() {
    $.ajax({
        url: '/api/auth/logout',
        type: 'POST',
        complete: function() {
            currentUser = null;
            // Drop the token — server invalidated the session, and any next
            // login will mint a fresh one.
            setCsrfToken(null);
            $('#nav-user-info').addClass('d-none');
            $('#nav-audit-log-item, #nav-user-mgmt-item, #nav-admin-settings-item').addClass('d-none');
            showLoginModal();
        }
    });
}

// ==================== ALTERAR SENHA ====================

function showChangePasswordModal(forced) {
    if (!_changePasswordModal) {
        _changePasswordModal = new bootstrap.Modal(
            document.getElementById('changePasswordModal'),
            { backdrop: forced ? 'static' : true, keyboard: !forced }
        );
    }
    $('#chpwd-error, #chpwd-success').addClass('d-none');
    $('#change-password-form')[0].reset();

    // Hide "current password" field when user must change (no prior pwd known)
    const mustChange = forced || (currentUser && currentUser.must_change_password);
    $('#chpwd-current-group').toggleClass('d-none', !!mustChange);

    _changePasswordModal.show();
}

function submitChangePassword(event) {
    event.preventDefault();
    const newPwd = $('#chpwd-new').val();
    const confirmPwd = $('#chpwd-confirm').val();

    $('#chpwd-error').addClass('d-none');
    if (newPwd !== confirmPwd) {
        $('#chpwd-error').removeClass('d-none').text('As senhas não coincidem.');
        return;
    }

    const btn = $('#chpwd-btn');
    btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-1"></i> Salvando...');

    $.ajax({
        url: '/api/auth/password',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            current_password: $('#chpwd-current').val(),
            new_password: newPwd
        }),
        success: function(resp) {
            if (resp.success) {
                $('#chpwd-success').removeClass('d-none').text('Senha alterada com sucesso!');
                $('#change-password-form')[0].reset();
                if (currentUser) currentUser.must_change_password = false;
                setTimeout(() => _changePasswordModal.hide(), 1500);
            } else {
                $('#chpwd-error').removeClass('d-none').text(resp.error || 'Erro ao alterar senha.');
            }
        },
        error: function(xhr) {
            $('#chpwd-error').removeClass('d-none')
                .text(xhr.responseJSON?.error || 'Erro ao alterar senha.');
        },
        complete: function() {
            btn.prop('disabled', false).html('<i class="fas fa-save me-1"></i> Salvar');
        }
    });
}

// ==================== LOG DE AUDITORIA ====================

function showAuditLogModal() {
    if (!_auditLogModal) {
        _auditLogModal = new bootstrap.Modal(document.getElementById('auditLogModal'));
    }
    _auditLogModal.show();
    loadAuditLog();
}

function loadAuditLog() {
    const action = $('#audit-filter-action').val();
    const limit  = $('#audit-filter-limit').val() || 200;
    const params = new URLSearchParams({ limit });
    if (action) params.set('action', action);

    const tbody = $('#audit-log-body');
    tbody.html('<tr><td colspan="8" class="text-center text-muted py-4">' +
               '<i class="fas fa-spinner fa-spin me-2"></i>Carregando...</td></tr>');

    $.ajax({
        url: '/api/audit-log?' + params.toString(),
        type: 'GET',
        success: function(resp) {
            tbody.empty();
            if (!resp.success || !resp.entries.length) {
                tbody.html('<tr><td colspan="8" class="text-center text-muted py-4">Nenhum registro encontrado.</td></tr>');
                $('#audit-count-label').text('0 registros');
                return;
            }
            const ACTION_COLORS = {
                login: 'text-success', logout: 'text-secondary',
                upload_pcap: 'text-primary', delete_scan: 'text-danger',
                triage_alert: 'text-warning', create_user: 'text-info',
                delete_user: 'text-danger', retention_purge: 'text-warning',
            };
            resp.entries.forEach(e => {
                const dt = e.occurred_at
                    ? new Date(e.occurred_at).toLocaleString('pt-BR')
                    : '-';
                const statusCls = e.status_code >= 500 ? 'text-danger fw-bold'
                                : e.status_code >= 400 ? 'text-warning'
                                : 'text-success';
                const actionLabel = e.action || `${e.method} ${e.path}`;
                const actionCls   = ACTION_COLORS[e.action] || '';
                const extra = e.extra ? JSON.stringify(e.extra) : '';
                const userLabel = e.user_id ? escHtml(e.user_id) : '&lt;anon&gt;';
                tbody.append(`<tr>
                    <td class="text-nowrap small">${escHtml(dt)}</td>
                    <td><span class="badge bg-secondary">${userLabel}</span></td>
                    <td class="small text-muted">${escHtml(e.actor_ip || '-')}</td>
                    <td><code class="small ${actionCls}">${escHtml(actionLabel)}</code></td>
                    <td class="small">${escHtml(e.target_type || '-')}</td>
                    <td class="small font-monospace">${escHtml(e.target_id || '-')}</td>
                    <td><span class="${statusCls} small">${escHtml(e.status_code || '-')}</span></td>
                    <td class="small text-muted text-truncate" style="max-width:160px"
                        title="${escHtml(extra)}">${escHtml(extra)}</td>
                </tr>`);
            });
            $('#audit-count-label').text(`${resp.count} registro${resp.count !== 1 ? 's' : ''}`);
        },
        error: function() {
            tbody.html('<tr><td colspan="8" class="text-center text-danger py-4">' +
                       '<i class="fas fa-exclamation-triangle me-2"></i>Erro ao carregar log.</td></tr>');
        }
    });
}

// ==================== GERENCIAR USUÁRIOS ====================

function showUserMgmtModal() {
    if (!_userMgmtModal) {
        _userMgmtModal = new bootstrap.Modal(document.getElementById('userMgmtModal'));
    }
    $('#usermgmt-msg').addClass('d-none');
    _userMgmtModal.show();
    loadUserList();
}

function loadUserList() {
    const tbody = $('#users-table-body');
    tbody.html('<tr><td colspan="6" class="text-center text-muted py-3">' +
               '<i class="fas fa-spinner fa-spin me-2"></i>Carregando...</td></tr>');

    $.ajax({
        url: '/api/users',
        type: 'GET',
        success: function(resp) {
            tbody.empty();
            if (!resp.success || !resp.users.length) {
                tbody.html('<tr><td colspan="6" class="text-center text-muted py-3">Nenhum usuário.</td></tr>');
                return;
            }
            const ROLE_COLORS = { admin: 'bg-danger', analyst: 'bg-primary', viewer: 'bg-secondary' };
            resp.users.forEach(u => {
                const isSelf = currentUser && u.id === currentUser.id;
                const createdAt = u.created_at ? new Date(u.created_at).toLocaleDateString('pt-BR') : '-';
                const lastLogin = u.last_login_at
                    ? new Date(u.last_login_at).toLocaleString('pt-BR')
                    : '<span class="text-muted">Nunca</span>';
                const statusBadge = u.enabled
                    ? '<span class="badge bg-success">Ativo</span>'
                    : '<span class="badge bg-secondary">Inativo</span>';
                const roleBadge = `<span class="badge ${ROLE_COLORS[u.role] || 'bg-secondary'}">${escHtml(u.role)}</span>`;
                const selfTag = isSelf ? ' <small class="text-muted fst-italic">(você)</small>' : '';
                const mustChange = u.must_change_password
                    ? ' <i class="fas fa-exclamation-circle text-warning" title="Deve alterar senha"></i>' : '';

                let actions = '';
                if (!isSelf) {
                    const toggleIcon = u.enabled ? 'fa-ban' : 'fa-check-circle';
                    const toggleCls  = u.enabled ? 'btn-outline-warning' : 'btn-outline-success';
                    const toggleTitle = u.enabled ? 'Desativar' : 'Ativar';
                    actions += `<button class="btn btn-sm ${toggleCls} me-1" title="${toggleTitle}"
                                        onclick="toggleUserEnabled(${u.id},${!u.enabled})">
                                    <i class="fas ${toggleIcon}"></i>
                                </button>`;
                    actions += `<button class="btn btn-sm btn-outline-danger" title="Excluir"
                                        onclick="deleteUserConfirm(${u.id},'${escHtml(u.username)}')">
                                    <i class="fas fa-trash"></i>
                                </button>`;
                }

                tbody.append(`<tr>
                    <td>${escHtml(u.username)}${selfTag}${mustChange}</td>
                    <td>${roleBadge}</td>
                    <td>${statusBadge}</td>
                    <td class="small text-muted">${createdAt}</td>
                    <td class="small">${lastLogin}</td>
                    <td class="text-end">${actions}</td>
                </tr>`);
            });
        },
        error: function() {
            tbody.html('<tr><td colspan="6" class="text-center text-danger py-3">Erro ao carregar usuários.</td></tr>');
        }
    });
}

function _showUserMgmtMsg(msg, isError) {
    $('#usermgmt-msg')
        .removeClass('d-none alert-danger alert-success')
        .addClass(isError ? 'alert-danger' : 'alert-success')
        .addClass('alert')
        .text(msg);
}

function createUser(event) {
    event.preventDefault();
    const btn = $('#new-user-btn');
    btn.prop('disabled', true);
    $('#usermgmt-msg').addClass('d-none');

    $.ajax({
        url: '/api/users',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            username: $('#new-user-username').val().trim(),
            password: $('#new-user-password').val(),
            role: $('#new-user-role').val(),
            must_change_password: true
        }),
        success: function(resp) {
            if (resp.success) {
                $('#new-user-form')[0].reset();
                _showUserMgmtMsg('Usuário criado com sucesso!', false);
                loadUserList();
            } else {
                _showUserMgmtMsg(resp.error || 'Erro ao criar usuário.', true);
            }
        },
        error: function(xhr) {
            _showUserMgmtMsg(xhr.responseJSON?.error || 'Erro ao criar usuário.', true);
        },
        complete: function() { btn.prop('disabled', false); }
    });
}

function toggleUserEnabled(userId, enabled) {
    $.ajax({
        url: `/api/users/${userId}/enabled`,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ enabled }),
        success: function(resp) {
            if (resp.success) loadUserList();
            else _showUserMgmtMsg(resp.error || 'Erro.', true);
        },
        error: function(xhr) {
            _showUserMgmtMsg(xhr.responseJSON?.error || 'Erro ao atualizar usuário.', true);
        }
    });
}

function deleteUserConfirm(userId, username) {
    confirmAction({
        title: 'Excluir usuário',
        message: `Excluir o usuário "${username}"? Esta ação não pode ser desfeita.`,
        confirmText: 'Excluir',
        danger: true
    }).then(ok => {
        if (!ok) return;
        $.ajax({
            url: `/api/users/${userId}`,
            type: 'DELETE',
            success: function(resp) {
                if (resp.success) { loadUserList(); _showUserMgmtMsg('Usuário excluído.', false); }
                else _showUserMgmtMsg(resp.error || 'Erro ao excluir.', true);
            },
            error: function(xhr) {
                _showUserMgmtMsg(xhr.responseJSON?.error || 'Erro ao excluir usuário.', true);
            }
        });
    });
}

// Escapa HTML para prevenir XSS em conteúdo dinâmico
function escHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ==================== KILL-CHAIN TIMELINE ====================

function exportMitreNavigatorLayer(scanId) {
    // Fetch the layer JSON, save as a file via Blob, and link it to
    // the MITRE ATT&CK Navigator hosted site for one-click loading.
    $.ajax({
        url: `/api/scans/${scanId}/mitre-layer`,
        method: 'GET',
        dataType: 'json',
        success: function(layer) {
            if (!layer || layer.success === false) {
                alert((layer && layer.error) || 'Falha ao gerar layer.');
                return;
            }
            try {
                const blob = new Blob([JSON.stringify(layer, null, 2)],
                                      {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                const safe = (layer.name || `scan-${scanId}`)
                    .replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
                a.download = `${safe}-attack-navigator.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(url), 1000);
                const count = (layer.techniques || []).length;
                console.log(`[mitre-layer] exported ${count} techniques. ` +
                    `Open https://mitre-attack.github.io/attack-navigator/ → ` +
                    `"Open Existing Layer → Upload from local" and pick the file.`);
            } catch (e) {
                alert('Erro ao salvar o arquivo: ' + e.message);
            }
        },
        error: function(xhr) {
            const msg = (xhr.responseJSON && xhr.responseJSON.error)
                || xhr.statusText || 'erro de rede';
            alert('Falha ao exportar Navigator layer: ' + msg);
        }
    });
}

function loadKillchain() {
    if (!currentScanId) {
        $('#killchain-container').html(
            '<p class="text-muted">Nenhum scan selecionado.</p>'
        );
        return;
    }
    const showEmpty = $('#killchain-show-empty').is(':checked') ? 1 : 0;
    $('#killchain-container').html(
        '<p class="text-muted"><i class="fas fa-spinner fa-spin"></i> Carregando…</p>'
    );
    $.ajax({
        url: `/api/scans/${currentScanId}/killchain?empty=${showEmpty}`,
        method: 'GET',
        success: function(resp) {
            if (!resp || !resp.success) {
                $('#killchain-container').html(
                    `<p class="text-danger">${escHtml((resp && resp.error) || 'Erro ao carregar kill-chain')}</p>`
                );
                return;
            }
            renderKillchain(resp);
        },
        error: function(xhr) {
            const msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.statusText || 'erro de rede';
            $('#killchain-container').html(
                `<p class="text-danger">${escHtml(msg)}</p>`
            );
        }
    });
}

function renderKillchain(payload) {
    const order = payload.tactics_order || [];
    const info  = payload.tactics_info || {};
    const hosts = payload.hosts || [];

    $('#killchain-summary').text(
        `${payload.host_count || 0} host(s) · ${payload.total_alerts || 0} alerta(s)`
    );

    if (!hosts.length || !order.length) {
        $('#killchain-container').html(
            '<p class="text-muted">Nenhum alerta com mapeamento MITRE para este scan.</p>'
        );
        return;
    }

    // Severity legend
    const legend = `
        <div class="kc-legend">
            <span><span class="kc-legend-dot" style="background:#dc3545"></span>Crítico</span>
            <span><span class="kc-legend-dot" style="background:#fd7e14"></span>Alto</span>
            <span><span class="kc-legend-dot" style="background:#ffc107"></span>Médio</span>
            <span><span class="kc-legend-dot" style="background:#0dcaf0"></span>Baixo</span>
            <span class="ms-auto">Colunas: ${order.map(t =>
                escHtml(((info[t] || {}).short) || t)
            ).join(' → ')}</span>
        </div>
    `;

    // Grid template: a label column + one column per tactic.
    // Use fr units so all tactic columns share width equally.
    const gridTemplate = `minmax(140px, 180px) repeat(${order.length}, minmax(60px, 1fr))`;

    const hostBlocks = hosts.map(host => {
        const headerCells = ['<div class="kc-col-header" style="text-align:left">Host</div>']
            .concat(order.map(t => `<div class="kc-col-header" title="${escHtml((info[t] || {}).name || t)}">${escHtml((info[t] || {}).short || t)}</div>`))
            .join('');

        const labelCell = `
            <div class="kc-cell" style="flex-direction:column;align-items:flex-start;justify-content:center;background:var(--bs-tertiary-bg,#f8f9fa);">
                <div class="kc-host-title">
                    <code>${escHtml(host.ip)}</code>
                    ${host.is_local ? '<span class="badge bg-secondary ms-1">local</span>' : ''}
                </div>
                ${host.name ? `<div class="small text-muted">${escHtml(host.name)}</div>` : ''}
                <div class="small">
                    <span style="color:#dc3545">C ${host.severity_counts.critical || 0}</span> ·
                    <span style="color:#fd7e14">H ${host.severity_counts.high || 0}</span> ·
                    <span style="color:#ffc107">M ${host.severity_counts.medium || 0}</span> ·
                    <span style="color:#0dcaf0">L ${host.severity_counts.low || 0}</span>
                </div>
            </div>
        `;

        const tacticCells = order.map(tid => {
            const events = (host.tactics || {})[tid] || [];
            if (!events.length) {
                return '<div class="kc-cell"><span class="kc-empty">·</span></div>';
            }
            const markers = events.map(ev => {
                const sev = (ev.severity || '').toLowerCase();
                const tip = `${ev.title}${ev.technique_id ? ' [' + ev.technique_id + ']' : ''}${ev.timestamp ? ' — ' + ev.timestamp : ''}`;
                return `<span class="kc-marker sev-${escHtml(sev)}"
                              title="${escHtml(tip)}"
                              data-alert-idx="${ev.idx}"
                              data-host-ip="${escHtml(host.ip)}"></span>`;
            }).join('');
            return `<div class="kc-cell">${markers}</div>`;
        }).join('');

        return `
            <div class="kc-host">
                <div class="kc-host-head">
                    <div>
                        <span class="kc-host-title"><code>${escHtml(host.ip)}</code></span>
                        ${host.name ? `<span class="kc-host-meta">· ${escHtml(host.name)}</span>` : ''}
                        ${host.group ? `<span class="kc-host-meta">· grupo ${escHtml(host.group)}</span>` : ''}
                        ${host.is_local ? '<span class="badge bg-secondary ms-1">local</span>' : '<span class="badge bg-info ms-1">externo</span>'}
                    </div>
                    <div class="kc-host-meta">
                        ${host.alert_count} alerta(s) ·
                        max: <strong class="text-${sevBootstrapColor(host.severity_max)}">${escHtml((host.severity_max || '—').toUpperCase())}</strong>
                    </div>
                </div>
                <div class="kc-grid" style="grid-template-columns:${gridTemplate}">
                    ${headerCells}
                    ${labelCell}
                    ${tacticCells}
                </div>
            </div>
        `;
    }).join('');

    $('#killchain-container').html(legend + hostBlocks);

    // Wire marker clicks: jump to the alerts tab and scroll to the alert.
    $('#killchain-container').off('click', '.kc-marker').on('click', '.kc-marker', function() {
        const idx = parseInt($(this).attr('data-alert-idx'), 10);
        focusAlertByIndex(idx);
    });
}

function sevBootstrapColor(sev) {
    switch ((sev || '').toLowerCase()) {
        case 'critical': return 'danger';
        case 'high':     return 'danger';
        case 'medium':   return 'warning';
        case 'low':      return 'info';
        default:         return 'secondary';
    }
}

function focusAlertByIndex(idx) {
    const tabBtn = document.getElementById('alerts-tab');
    if (tabBtn && window.bootstrap && bootstrap.Tab) {
        bootstrap.Tab.getOrCreateInstance(tabBtn).show();
    }
    setTimeout(() => {
        const $items = $('#alerts-list .alert-item');
        if (idx >= 0 && idx < $items.length) {
            const el = $items.get(idx);
            el.scrollIntoView({behavior: 'smooth', block: 'center'});
            $(el).addClass('border border-primary border-3');
            setTimeout(() => $(el).removeClass('border border-primary border-3'), 2000);
        }
    }, 150);
}

// ==================== GRAPH VIEW (B.6) ====================

function resetGraphView() {
    if (graphNetwork) {
        try { graphNetwork.destroy(); } catch (e) { /* ignore */ }
    }
    graphNetwork = null;
    graphNodesDS = null;
    graphEdgesDS = null;
    $('#graph-container').html(
        '<p class="text-muted p-3">Selecione um scan para visualizar o graph.</p>'
    );
    $('#graph-detail').html(
        '<p class="text-muted mb-0">Clique num nó ou aresta para ver detalhes.</p>'
    );
    $('#graph-summary').text('');
}

function loadGraph() {
    if (!currentScanId) {
        $('#graph-container').html('<p class="text-muted p-3">Nenhum scan selecionado.</p>');
        return;
    }
    if (!window.visNetwork) {
        $('#graph-container').html('<p class="text-danger p-3">Biblioteca vis-network não carregada.</p>');
        return;
    }
    const topN = parseInt($('#graph-top-n').val(), 10) || 200;
    $('#graph-container').html(
        '<p class="text-muted p-3"><i class="fas fa-spinner fa-spin"></i> Carregando graph…</p>'
    );
    $.ajax({
        url: `/api/scans/${currentScanId}/graph?top_n=${topN}`,
        method: 'GET',
        success: function(resp) {
            if (!resp || !resp.success) {
                $('#graph-container').html(
                    `<p class="text-danger p-3">${escHtml((resp && resp.error) || 'Erro ao carregar graph')}</p>`
                );
                return;
            }
            renderGraph(resp);
        },
        error: function(xhr) {
            const msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.statusText || 'erro de rede';
            $('#graph-container').html(`<p class="text-danger p-3">${escHtml(msg)}</p>`);
        }
    });
}

function _graphNodeColor(node) {
    // Priority: malicious → severity_max → local/external bucket.
    if (node.is_malicious) {
        return {background: '#6f1d1b', border: '#3d0f0e', highlight: {background: '#8a2522', border: '#3d0f0e'}};
    }
    const sev = (node.severity_max || '').toLowerCase();
    if (sev === 'critical') return {background: '#6f1d1b', border: '#3d0f0e'};
    if (sev === 'high')     return {background: '#dc3545', border: '#7d1d27'};
    if (sev === 'medium')   return {background: '#ffc107', border: '#a37b00'};
    if (sev === 'low')      return {background: '#0dcaf0', border: '#066b81'};
    if (node.is_local)      return {background: '#0d6efd', border: '#06408f'};
    return {background: '#6c757d', border: '#3e454b'};
}

function _formatBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function _logScale(x, min, max) {
    // Map x∈[min,max] → [0,1] on a natural-log scale, clamped.
    if (x <= 0 || max <= 0) return 0;
    const lx = Math.log(x + 1);
    const lmin = Math.log((min || 0) + 1);
    const lmax = Math.log(max + 1);
    if (lmax <= lmin) return 0.5;
    return Math.max(0, Math.min(1, (lx - lmin) / (lmax - lmin)));
}

function renderGraph(payload) {
    const nodes = payload.nodes || [];
    const edges = payload.edges || [];
    const hideIsolated = $('#graph-hide-isolated').is(':checked');
    const layout = $('#graph-layout').val() || 'physics';

    $('#graph-summary').text(
        `${payload.node_count} nó(s) · ${payload.edge_count} aresta(s)`
        + (payload.truncated ? ` · top ${payload.top_n} de ${payload.total_ips}` : '')
    );

    if (!nodes.length) {
        $('#graph-container').html('<p class="text-muted p-3">Sem dados para o graph.</p>');
        $('#graph-detail').html('<p class="text-muted mb-0">Sem dados.</p>');
        return;
    }

    const connected = new Set();
    edges.forEach(e => { connected.add(e.source); connected.add(e.target); });

    const maxBytesNode = nodes.reduce((m, n) => Math.max(m, n.bytes_total || 0), 0);
    const maxBytesEdge = edges.reduce((m, e) => Math.max(m, e.bytes || 0), 0);

    const visNodes = nodes
        .filter(n => !hideIsolated || connected.has(n.id))
        .map(n => {
            const size = 8 + Math.round(_logScale(n.bytes_total || 1, 0, maxBytesNode || 1) * 28);
            const label = n.name || n.ip;
            const tipLines = [
                `<b>${escHtml(n.ip)}</b>`,
                n.name ? `Nome: ${escHtml(n.name)}` : '',
                n.group ? `Grupo: ${escHtml(n.group)}` : '',
                n.country ? `País: ${escHtml(n.country)}` : '',
                n.is_local ? 'Local' : 'Externo',
                `Bytes total: ${_formatBytes(n.bytes_total)}`,
                `Pacotes: ${(n.packets_sent || 0) + (n.packets_received || 0)}`,
                `Alertas: ${n.alert_count || 0}${n.severity_max ? ' (max ' + n.severity_max + ')' : ''}`,
                `Risk: ${n.risk_score || 0}/100`,
                n.is_malicious ? '<b style="color:#ff8a80">MALICIOUS</b>' : '',
            ].filter(Boolean).join('<br>');
            const div = document.createElement('div');
            div.style.maxWidth = '260px';
            div.innerHTML = tipLines;
            return {
                id: n.id,
                label: label,
                size: size,
                shape: n.is_malicious ? 'diamond' : (n.is_local ? 'dot' : 'dot'),
                color: _graphNodeColor(n),
                borderWidth: (n.alert_count || 0) > 0 ? 3 : 1,
                title: div,
                font: {size: 11, color: '#222'},
                _meta: n,
            };
        });

    const visEdges = edges.map(e => {
        const width = 0.5 + _logScale(e.bytes || 1, 0, maxBytesEdge || 1) * 9.5;
        const div = document.createElement('div');
        div.style.maxWidth = '260px';
        div.innerHTML =
            `<b>${escHtml(e.source)} ↔ ${escHtml(e.target)}</b><br>`
            + `Bytes: ${_formatBytes(e.bytes)}<br>`
            + `Pacotes: ${e.packets}<br>`
            + `Protocolos: ${(e.protocols || []).map(escHtml).join(', ') || '-'}`;
        return {
            from: e.source,
            to: e.target,
            width: width,
            color: {color: 'rgba(108,117,125,0.55)', highlight: '#0d6efd', hover: '#0d6efd'},
            smooth: {enabled: true, type: 'continuous'},
            title: div,
            _meta: e,
        };
    });

    if (graphNetwork) {
        try { graphNetwork.destroy(); } catch (e) { /* ignore */ }
    }
    $('#graph-container').empty();

    graphNodesDS = new window.visNetwork.DataSet(visNodes);
    graphEdgesDS = new window.visNetwork.DataSet(visEdges);

    const options = {
        nodes: {shape: 'dot', scaling: {min: 8, max: 40}},
        edges: {selectionWidth: factor => factor * 1.5},
        interaction: {hover: true, tooltipDelay: 120, navigationButtons: true, keyboard: true},
        physics: {
            enabled: layout === 'physics',
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {gravitationalConstant: -45, springLength: 110, damping: 0.55},
            stabilization: {iterations: 180, fit: true},
        },
        layout: layout === 'hierarchical'
            ? {hierarchical: {enabled: true, direction: 'LR', sortMethod: 'hubsize'}}
            : {hierarchical: false},
    };

    const container = document.getElementById('graph-container');
    graphNetwork = new window.visNetwork.Network(
        container,
        {nodes: graphNodesDS, edges: graphEdgesDS},
        options,
    );

    // Selection → detail panel.
    graphNetwork.on('selectNode', function(params) {
        const id = params.nodes[0];
        const n = graphNodesDS.get(id);
        if (n && n._meta) renderGraphNodeDetail(n._meta);
    });
    graphNetwork.on('selectEdge', function(params) {
        if (params.nodes && params.nodes.length) return;  // node-edge ambiguity
        const id = params.edges[0];
        const e = graphEdgesDS.get(id);
        if (e && e._meta) renderGraphEdgeDetail(e._meta);
    });
    graphNetwork.on('deselectNode', function() {
        $('#graph-detail').html('<p class="text-muted mb-0">Clique num nó ou aresta para ver detalhes.</p>');
    });
    // Double-click on a node → jump to IPs tab and filter on its address.
    graphNetwork.on('doubleClick', function(params) {
        if (!params.nodes || !params.nodes.length) return;
        focusIpInIpsTab(params.nodes[0]);
    });
}

function renderGraphNodeDetail(n) {
    const sevBadge = n.severity_max
        ? `<span class="badge bg-${sevBootstrapColor(n.severity_max)}">${escHtml(n.severity_max)}</span>`
        : '';
    const malBadge = n.is_malicious ? '<span class="badge bg-danger ms-1">MALICIOUS</span>' : '';
    const localBadge = n.is_local
        ? '<span class="badge bg-primary ms-1">local</span>'
        : '<span class="badge bg-secondary ms-1">externo</span>';
    const protos = (n.protocols || []).map(p => `<span class="badge bg-info me-1">${escHtml(p)}</span>`).join('');
    const html = `
        <div class="mb-2">
            <code>${escHtml(n.ip)}</code> ${localBadge} ${malBadge}
        </div>
        ${n.name ? `<div class="small mb-1"><strong>Nome:</strong> ${escHtml(n.name)}</div>` : ''}
        ${n.group ? `<div class="small mb-1"><strong>Grupo:</strong> ${escHtml(n.group)}</div>` : ''}
        ${n.country ? `<div class="small mb-1"><strong>País:</strong> ${escHtml(n.country)}</div>` : ''}
        <div class="small mb-1"><strong>Bytes:</strong> ${_formatBytes(n.bytes_total)}
            <span class="text-muted">(↑${_formatBytes(n.bytes_sent)} / ↓${_formatBytes(n.bytes_received)})</span></div>
        <div class="small mb-1"><strong>Pacotes:</strong> ${(n.packets_sent || 0) + (n.packets_received || 0)}</div>
        <div class="small mb-1"><strong>Alertas:</strong> ${n.alert_count || 0} ${sevBadge}</div>
        <div class="small mb-1"><strong>Risk:</strong> ${n.risk_score || 0}/100</div>
        <div class="small mb-2"><strong>Reputação:</strong> ${n.reputation_score || 0}/100</div>
        ${protos ? `<div class="small mb-2"><strong>Protocolos:</strong><br>${protos}</div>` : ''}
        <div class="d-grid gap-1">
            <button class="btn btn-sm btn-outline-primary" onclick="focusIpInIpsTab('${escHtml(n.ip).replace(/'/g, "\\'")}')">
                <i class="fas fa-server"></i> Ver na aba IPs
            </button>
            <button class="btn btn-sm btn-outline-warning" onclick="focusAlertsByIp('${escHtml(n.ip).replace(/'/g, "\\'")}')">
                <i class="fas fa-exclamation-triangle"></i> Filtrar alertas
            </button>
        </div>
    `;
    $('#graph-detail').html(html);
}

function renderGraphEdgeDetail(e) {
    const protos = (e.protocols || []).map(p => `<span class="badge bg-info me-1">${escHtml(p)}</span>`).join('');
    const html = `
        <div class="mb-2"><strong>Fluxo:</strong></div>
        <div class="mb-1"><code>${escHtml(e.source)}</code> ↔ <code>${escHtml(e.target)}</code></div>
        <div class="small mb-1"><strong>Bytes:</strong> ${_formatBytes(e.bytes)}</div>
        <div class="small mb-1"><strong>Pacotes:</strong> ${e.packets}</div>
        ${protos ? `<div class="small mt-2"><strong>Protocolos:</strong><br>${protos}</div>` : ''}
    `;
    $('#graph-detail').html(html);
}

function focusIpInIpsTab(ip) {
    const tabBtn = document.getElementById('ips-tab');
    if (tabBtn && window.bootstrap && bootstrap.Tab) {
        bootstrap.Tab.getOrCreateInstance(tabBtn).show();
    }
    setTimeout(() => {
        if (ipsDataTable) {
            ipsDataTable.search(ip).draw();
            const row = $('#ips-table tbody tr').filter(function() {
                return $(this).find('td').first().text().trim() === ip;
            }).first();
            if (row.length) {
                row.get(0).scrollIntoView({behavior: 'smooth', block: 'center'});
                row.addClass('table-warning');
                setTimeout(() => row.removeClass('table-warning'), 2000);
            }
        }
    }, 200);
}

function focusAlertsByIp(ip) {
    const tabBtn = document.getElementById('alerts-tab');
    if (tabBtn && window.bootstrap && bootstrap.Tab) {
        bootstrap.Tab.getOrCreateInstance(tabBtn).show();
    }
    // The Alerts tab has no per-IP filter; scroll to the first matching item.
    setTimeout(() => {
        const $items = $('#alerts-list .alert-item');
        const $match = $items.filter(function() {
            return $(this).text().indexOf(ip) !== -1;
        }).first();
        if ($match.length) {
            $match.get(0).scrollIntoView({behavior: 'smooth', block: 'center'});
            $match.addClass('border border-primary border-3');
            setTimeout(() => $match.removeClass('border border-primary border-3'), 2000);
        }
    }, 200);
}

// ==================== PACKET VIEWER ====================

function loadPackets(page) {
    if (!currentScanId) {
        showNotify('Nenhum scan selecionado', 'warning');
        return;
    }

    page = page || 1;
    currentPacketPage = page;

    const filterIp = $('#filter-packet-ip').val() || '';
    const filterProtocol = $('#filter-packet-protocol').val() || '';
    const perPage = 100;

    let url = `/api/packets/${currentScanId}?page=${page}&per_page=${perPage}`;
    if (filterIp) url += `&filter_ip=${encodeURIComponent(filterIp)}`;
    if (filterProtocol) url += `&filter_protocol=${encodeURIComponent(filterProtocol)}`;

    $('#packets-tbody').html('<tr><td colspan="8" class="text-center"><i class="fas fa-spinner fa-spin"></i> Carregando pacotes...</td></tr>');

    $.ajax({
        url: url,
        type: 'GET',
        success: function(response) {
            if (response.success) {
                const data = response.data || {};
                renderPackets(data.packets || []);
                renderPacketPagination({
                    page: data.page,
                    total_pages: data.total_pages,
                    total: data.total
                });
            } else {
                $('#packets-tbody').html('<tr><td colspan="8" class="text-center text-danger">' + (response.error || 'Erro ao carregar pacotes') + '</td></tr>');
            }
        },
        error: function(xhr) {
            const error = xhr.responseJSON?.error || 'Erro ao carregar pacotes';
            $('#packets-tbody').html('<tr><td colspan="8" class="text-center text-danger">' + error + '</td></tr>');
        }
    });
}

function renderPackets(packets) {
    const tbody = $('#packets-tbody');
    tbody.empty();

    if (!packets || packets.length === 0) {
        tbody.html('<tr><td colspan="7" class="text-center text-muted">Nenhum pacote encontrado</td></tr>');
        return;
    }

    packets.forEach(pkt => {
        const row = `
            <tr style="cursor: pointer;" onclick="viewPacketDetail(${pkt.number})">
                <td>${pkt.number}</td>
                <td><small>${escHtml(pkt.time)}</small></td>
                <td><code>${escHtml(pkt.src || '-')}</code></td>
                <td><code>${escHtml(pkt.dst || '-')}</code></td>
                <td><span class="badge bg-info">${escHtml(pkt.protocol || '-')}</span></td>
                <td>${pkt.length}</td>
                <td><small>${escapeHtml(pkt.info || '')}</small></td>
                <td><button class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation(); viewPacketDetail(${pkt.number})" title="Detalhes"><i class="fas fa-search"></i></button></td>
            </tr>
        `;
        tbody.append(row);
    });
}

function renderPacketPagination(pagination) {
    if (!pagination) return;

    $('#packet-page-info').text(`Página ${pagination.page} de ${pagination.total_pages} (${pagination.total} pacotes)`);

    $('#packet-prev-page').prop('disabled', pagination.page <= 1);
    $('#packet-next-page').prop('disabled', pagination.page >= pagination.total_pages);
}

function packetPagePrev() {
    if (currentPacketPage > 1) {
        loadPackets(currentPacketPage - 1);
    }
}

function packetPageNext() {
    loadPackets(currentPacketPage + 1);
}

function viewPacketDetail(packetNum) {
    if (!currentScanId) return;

    $.ajax({
        url: `/api/packets/${currentScanId}/${packetNum}`,
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderPacketDetail(response.data);
                new bootstrap.Modal('#packetDetailModal').show();
            }
        },
        error: function(xhr) {
            showNotify('Erro ao carregar detalhes do pacote', 'error');
        }
    });
}

function renderPacketDetail(detail) {
    // Layers tab
    const layersContainer = $('#packet-layers-content');
    layersContainer.empty();

    if (detail.layers && detail.layers.length > 0) {
        detail.layers.forEach((layer, idx) => {
            let fieldsHtml = '';
            if (layer.fields) {
                for (const [key, value] of Object.entries(layer.fields)) {
                    fieldsHtml += `<tr><td><strong>${escapeHtml(key)}</strong></td><td>${escapeHtml(String(value))}</td></tr>`;
                }
            }

            const layerHtml = `
                <div class="card mb-2">
                    <div class="card-header py-1 px-2" data-bs-toggle="collapse" data-bs-target="#layer-${idx}" style="cursor: pointer;">
                        <strong>${escapeHtml(layer.name)}</strong>
                    </div>
                    <div id="layer-${idx}" class="collapse ${idx === 0 ? 'show' : ''}">
                        <div class="card-body p-2">
                            <table class="table table-sm table-striped mb-0">
                                <tbody>${fieldsHtml}</tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
            layersContainer.append(layerHtml);
        });
    } else {
        layersContainer.html('<p class="text-muted">Nenhuma camada disponível</p>');
    }

    // Hex dump tab
    const hexContainer = $('#packet-hex-content');
    if (detail.hex_dump) {
        hexContainer.text(detail.hex_dump);
    } else {
        hexContainer.text('Hex dump não disponível');
    }

    // Modal title
    $('#packet-detail-number').text(detail.number || '');
}

// ==================== REPORTS ====================

function downloadReport(format) {
    if (!currentScanId) {
        showNotify('Nenhum scan selecionado para gerar relatório', 'warning');
        return;
    }

    const btn = format === 'pdf' ? $('#download-pdf-btn') : $('#download-html-btn');
    const originalText = btn.html();
    btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Gerando...');

    window.location.href = `/api/report/${currentScanId}?format=${format}`;

    // Re-enable after a delay (download starts in background)
    setTimeout(function() {
        btn.prop('disabled', false).html(originalText);
    }, 3000);
}

function downloadAlertsReport() {
    if (!currentScanId) {
        showNotify('Nenhum scan selecionado para exportar alertas', 'warning');
        return;
    }

    const btn = $('#export-alerts-pdf-btn');
    const originalText = btn.html();
    btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> Gerando...');

    window.location.href = `/api/scans/${currentScanId}/alerts-report`;

    // Re-enable after a delay (download starts in background)
    setTimeout(function() {
        btn.prop('disabled', false).html(originalText);
    }, 3000);
}

// ==================== UTILITÁRIOS ====================

function formatNumber(num) {
    return num.toLocaleString('pt-BR');
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function getSeverityClass(severity) {
    const classes = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary'
    };
    return classes[severity] || 'secondary';
}

function getSeverityIcon(severity) {
    const icons = {
        'critical': 'fas fa-exclamation-circle',
        'high': 'fas fa-exclamation-triangle',
        'medium': 'fas fa-info-circle',
        'low': 'fas fa-check-circle'
    };
    return icons[severity] || 'fas fa-info-circle';
}

function getRiskBadge(risk) {
    const badges = {
        'low': '<span class="badge bg-success">Baixo</span>',
        'medium': '<span class="badge bg-warning">Médio</span>',
        'high': '<span class="badge bg-danger">Alto</span>'
    };
    return badges[risk] || '<span class="badge bg-secondary">-</span>';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== ADMIN SETTINGS: THREAT INTEL & API KEYS ====================

function showAdminSettingsModal() {
    if (!_adminSettingsModal) {
        _adminSettingsModal = new bootstrap.Modal(document.getElementById('adminSettingsModal'));
    }
    loadApiKeys();
    _adminSettingsModal.show();
}

function loadApiKeys() {
    $('#api-keys-loading').removeClass('d-none');
    $('#api-keys-content').addClass('d-none');

    $.ajax({
        url: '/api/admin/api-keys',
        type: 'GET',
        success: function(resp) {
            if (!resp.success) return;
            const services = resp.services || [];
            const free = services.filter(s => !s.requires_key);
            const paid = services.filter(s => s.requires_key);

            // Free services table
            const freeTbody = $('#free-services-tbody');
            freeTbody.empty();
            free.forEach(svc => {
                const types = (svc.types || []).map(t => `<span class="badge bg-secondary me-1">${t}</span>`).join('');
                freeTbody.append(`
                    <tr>
                        <td><strong>${escapeHtml(svc.name)}</strong></td>
                        <td><small class="text-muted">${escapeHtml(svc.description)}</small></td>
                        <td>${types}</td>
                        <td><span class="badge bg-success"><i class="fas fa-check me-1"></i>Ativo</span></td>
                    </tr>
                `);
            });

            // Paid/key services table
            const paidTbody = $('#paid-services-tbody');
            paidTbody.empty();
            paid.forEach(svc => {
                const types = (svc.types || []).map(t => `<span class="badge bg-secondary me-1">${t}</span>`).join('');
                const statusBadge = svc.configured
                    ? '<span class="badge bg-success"><i class="fas fa-check me-1"></i>Configurado</span>'
                    : '<span class="badge bg-warning text-dark"><i class="fas fa-minus me-1"></i>Sem chave</span>';

                let inputsHtml;
                if (Array.isArray(svc.subfields) && svc.subfields.length) {
                    inputsHtml = '<div class="d-flex flex-column gap-1">';
                    svc.subfields.forEach(f => {
                        const inputType = f.secret ? 'password' : 'text';
                        const ph = f.secret
                            ? (f.configured ? '••••••••••••• (configurado)' : (f.placeholder || 'Cole o valor aqui'))
                            : (f.placeholder || '');
                        const val = (!f.secret && f.current_value) ? escapeHtml(f.current_value) : '';
                        inputsHtml += `
                            <div class="input-group input-group-sm">
                                <span class="input-group-text" style="min-width:7.5rem;font-size:.75rem">${escapeHtml(f.label)}</span>
                                <input type="${inputType}" class="form-control form-control-sm subfield-input"
                                       data-field="${escapeHtml(f.id)}"
                                       placeholder="${escapeHtml(ph)}"
                                       value="${val}"
                                       autocomplete="off">
                            </div>`;
                    });
                    inputsHtml += '</div>';
                } else {
                    inputsHtml = `
                        <input type="password" class="form-control form-control-sm subfield-input"
                               data-field="${escapeHtml(svc.id)}"
                               placeholder="${svc.configured ? '••••••••••••• (configurado)' : 'Cole a chave aqui'}"
                               autocomplete="off">`;
                }

                paidTbody.append(`
                    <tr data-service="${escapeHtml(svc.id)}">
                        <td><strong>${escapeHtml(svc.name)}</strong></td>
                        <td><small class="text-muted">${escapeHtml(svc.description)}</small></td>
                        <td>${types}</td>
                        <td class="status-cell">${statusBadge}</td>
                        <td>${inputsHtml}</td>
                        <td class="d-flex flex-column gap-1">
                            <button class="btn btn-sm btn-outline-primary"
                                    onclick="saveApiKey('${escapeHtml(svc.id)}', this)">
                                <i class="fas fa-save me-1"></i>Salvar
                            </button>
                            ${svc.configured ? `
                            <button class="btn btn-sm btn-outline-danger"
                                    onclick="clearApiKey('${escapeHtml(svc.id)}', this)">
                                <i class="fas fa-eraser me-1"></i>Limpar
                            </button>` : ''}
                        </td>
                    </tr>
                `);
            });

            $('#api-keys-loading').addClass('d-none');
            $('#api-keys-content').removeClass('d-none');
        },
        error: function() {
            $('#api-keys-loading').html('<span class="text-danger">Erro ao carregar serviços.</span>');
        }
    });
}

function saveApiKey(serviceId, btn) {
    const row = $(btn).closest('tr');
    const fields = {};
    row.find('.subfield-input').each(function() {
        const fid = $(this).attr('data-field') || serviceId;
        const input = $(this);
        // Only send a value when the user actually typed something. Empty
        // password fields are skipped so we don't wipe an already-saved secret
        // by accident — explicit clearing requires the legacy /clear flow.
        const v = (input.val() || '').trim();
        const isSecret = input.attr('type') === 'password';
        if (isSecret) {
            if (v) fields[fid] = v;
        } else {
            // Text fields (URLs / collection ids) are visible — always echo
            // current state so the operator can clear them by emptying the box.
            fields[fid] = v;
        }
    });

    if (Object.keys(fields).length === 0) {
        showNotify('Nada para salvar.', 'warning');
        return;
    }

    const $btn = $(btn);
    const orig = $btn.html();
    $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i>');

    $.ajax({
        url: `/api/admin/api-keys/${encodeURIComponent(serviceId)}`,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ fields }),
        success: function(resp) {
            if (resp.success) {
                row.find('.subfield-input').each(function() {
                    if ($(this).attr('type') === 'password') {
                        $(this).val('').attr('placeholder', '••••••••••••• (configurado)');
                    }
                });
                // Reload the whole list so status badges/current_values reflect what was saved.
                loadApiKeys();
                showNotify('Configuração salva.', 'success');
            } else {
                showNotify('Erro ao salvar: ' + (resp.error || 'erro desconhecido'), 'error');
            }
        },
        error: function(xhr) {
            showNotify('Erro ao salvar: ' + (xhr.responseJSON?.error || xhr.statusText), 'error');
        },
        complete: function() {
            $btn.prop('disabled', false).html(orig);
        }
    });
}

function clearApiKey(serviceId, btn) {
    confirmAction({
        title: 'Limpar credenciais',
        message: `Remover todas as credenciais do serviço "${serviceId}"? Essa ação não pode ser desfeita.`,
        confirmText: 'Limpar',
        danger: true,
    }).then(ok => {
        if (!ok) return;
        const row = $(btn).closest('tr');
        const fields = {};
        // Send empty string for every known subfield so the backend wipes them.
        row.find('.subfield-input').each(function() {
            const fid = $(this).attr('data-field') || serviceId;
            fields[fid] = '';
        });
        const $btn = $(btn);
        const orig = $btn.html();
        $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i>');

        $.ajax({
            url: `/api/admin/api-keys/${encodeURIComponent(serviceId)}`,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ fields }),
            success: function(resp) {
                if (resp.success) {
                    showNotify('Credenciais removidas.', 'success');
                    loadApiKeys();
                } else {
                    showNotify('Erro ao limpar: ' + (resp.error || 'erro desconhecido'), 'error');
                }
            },
            error: function(xhr) {
                showNotify('Erro ao limpar: ' + (xhr.responseJSON?.error || xhr.statusText), 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).html(orig);
            }
        });
    });
}

// ==================== MANUAL THREAT INTEL LOOKUP ====================

function runManualLookup(event) {
    event.preventDefault();
    const indicator = $('#lookup-indicator').val().trim();
    const type = $('#lookup-type').val();
    if (!indicator) return;

    const btn = $('#lookup-btn');
    btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-1"></i>Consultando...');
    $('#lookup-result-area').addClass('d-none');
    $('#lookup-result-content').empty();

    $.ajax({
        url: '/api/admin/lookup',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ indicator, type }),
        success: function(resp) {
            if (resp.success) {
                renderLookupResult(resp.result);
            } else {
                $('#lookup-result-content').html(
                    `<div class="alert alert-danger"><i class="fas fa-exclamation-circle me-2"></i>${escapeHtml(resp.error)}</div>`
                );
            }
            $('#lookup-result-area').removeClass('d-none');
        },
        error: function(xhr) {
            const msg = xhr.responseJSON?.error || xhr.statusText || 'Erro desconhecido';
            $('#lookup-result-content').html(
                `<div class="alert alert-danger"><i class="fas fa-exclamation-circle me-2"></i>${escapeHtml(msg)}</div>`
            );
            $('#lookup-result-area').removeClass('d-none');
        },
        complete: function() {
            btn.prop('disabled', false).html('<i class="fas fa-search me-1"></i>Consultar');
        }
    });
}

function renderLookupResult(result) {
    const container = $('#lookup-result-content');
    const summary = result.summary || {};
    const sources = result.sources || {};

    const isMalicious = summary.is_malicious;
    const score = summary.reputation_score || 0;
    const labels = summary.labels || [];

    const verdictClass = isMalicious ? 'danger' : (score > 25 ? 'warning' : 'success');
    const verdictIcon = isMalicious ? 'fa-skull-crossbones' : (score > 25 ? 'fa-exclamation-triangle' : 'fa-check-circle');
    const verdictText = isMalicious ? 'Malicioso' : (score > 25 ? 'Suspeito' : 'Limpo / Não encontrado');

    const labelBadges = labels.map(l => `<span class="badge bg-secondary me-1">${escapeHtml(l)}</span>`).join('');

    let html = `
        <div class="d-flex align-items-center gap-3 mb-3">
            <div class="alert alert-${verdictClass} mb-0 flex-grow-1">
                <i class="fas ${verdictIcon} me-2"></i>
                <strong>${escapeHtml(result.indicator)}</strong> (${escapeHtml(result.type)}) —
                <strong>${verdictText}</strong>
                &nbsp;<span class="badge bg-secondary">Score: ${score}/100</span>
                ${labelBadges ? '<div class="mt-1">' + labelBadges + '</div>' : ''}
            </div>
        </div>
    `;

    const sourceNames = {
        ipsum: 'IPsum',
        tor: 'Tor Exit Nodes',
        feodo: 'Feodo Tracker',
        threatfox: 'ThreatFox',
        urlhaus: 'URLhaus',
        abuseipdb: 'AbuseIPDB',
        virustotal: 'VirusTotal',
        shodan: 'Shodan',
        greynoise: 'GreyNoise',
    };

    if (Object.keys(sources).length === 0) {
        html += `<div class="alert alert-secondary">
            <i class="fas fa-info-circle me-2"></i>Nenhum feed retornou dados para este indicador.
            Serviços com chave de API não configurada são ignorados.
        </div>`;
    } else {
        html += '<div class="row g-3">';
        for (const [svcId, data] of Object.entries(sources)) {
            const svcName = sourceNames[svcId] || svcId;
            let rows = '';
            for (const [k, v] of Object.entries(data)) {
                if (k === 'source') continue;
                let displayVal = typeof v === 'object' ? JSON.stringify(v) : String(v);
                if (displayVal.length > 120) displayVal = displayVal.slice(0, 120) + '…';
                rows += `<tr><td class="text-muted small pe-2">${escapeHtml(k)}</td><td class="small">${escapeHtml(displayVal)}</td></tr>`;
            }
            html += `
                <div class="col-md-6">
                    <div class="card h-100">
                        <div class="card-header py-2 px-3 fw-semibold small">
                            <i class="fas fa-database me-1"></i>${escapeHtml(svcName)}
                        </div>
                        <div class="card-body p-2">
                            ${rows ? '<table class="table table-sm mb-0"><tbody>' + rows + '</tbody></table>'
                                   : '<span class="text-muted small">Sem dados adicionais</span>'}
                        </div>
                    </div>
                </div>`;
        }
        html += '</div>';
    }

    container.html(html);
}

// ==================== CARVED FILES (A.1/A.2/A.4) ====================

function resetCarvedView() {
    if (carvedDataTable) {
        try { carvedDataTable.destroy(); } catch (e) { /* ignore */ }
    }
    carvedDataTable = null;
    _carvedLastPayload = null;
    $('#carved-tbody').empty();
    $('#carved-summary').text('');
    $('#carved-badge').text('0').removeClass('bg-danger bg-warning text-dark').addClass('bg-secondary');
}

function loadCarvedFiles() {
    if (!currentScanId) return;
    $.ajax({
        url: `/api/scans/${currentScanId}/carved-files`,
        method: 'GET',
        success: function(resp) {
            if (!resp || !resp.success) {
                showNotify((resp && resp.error) || 'Erro ao carregar arquivos esculpidos', 'error');
                return;
            }
            _carvedLastPayload = resp;
            renderCarvedFiles(resp);
        },
        error: function(xhr) {
            const msg = (xhr.responseJSON && xhr.responseJSON.error) || xhr.statusText || 'erro de rede';
            showNotify('Falha ao carregar carved files: ' + msg, 'error');
        }
    });
}

function _carvedRepBadge(file) {
    if (file.malicious) {
        const labels = Array.isArray(file.labels) ? file.labels.slice(0, 3).join(', ') : '';
        const title = labels ? `Malicioso — ${labels}` : 'Malicioso';
        return `<span class="badge bg-danger" title="${escHtml(title)}"><i class="fas fa-skull-crossbones"></i> Malicioso</span>`;
    }
    if (file.looked_up_at) {
        return '<span class="badge bg-success" title="VT/MB consultados, sem detecção"><i class="fas fa-check"></i> Limpo</span>';
    }
    return '<span class="badge bg-secondary" title="Sem consulta de reputação (chave VT/MB não configurada)">—</span>';
}

function _carvedYaraBadge(file) {
    const matches = file.yara_matches;
    if (!matches || (Array.isArray(matches) && !matches.length)) {
        if (file.yara_scanned_at) {
            return '<span class="text-muted small">sem match</span>';
        }
        return '<span class="text-muted small">—</span>';
    }
    const sev = (file.yara_severity || 'medium').toLowerCase();
    const sevClass = sev === 'critical' ? 'bg-danger'
                   : sev === 'high'     ? 'bg-danger'
                   : sev === 'medium'   ? 'bg-warning text-dark'
                   : sev === 'low'      ? 'bg-info text-dark'
                   :                      'bg-secondary';
    const list = Array.isArray(matches) ? matches : [matches];
    const names = list.map(m => (typeof m === 'string' ? m : (m && m.rule) || '?')).slice(0, 3);
    const title = list.map(m => (typeof m === 'string' ? m : (m && m.rule) || '?')).join(', ');
    return `<span class="badge ${sevClass}" title="${escHtml(title)}">${escHtml(names.join(', '))}${list.length > 3 ? ` +${list.length - 3}` : ''}</span>`;
}

function _shortHash(h) {
    if (!h) return '';
    return h.length > 16 ? h.slice(0, 8) + '…' + h.slice(-6) : h;
}

function _filterCarvedRows(files) {
    if (_carvedFilter === 'malicious') return files.filter(f => f.malicious);
    if (_carvedFilter === 'yara') {
        return files.filter(f => f.yara_matches && (Array.isArray(f.yara_matches) ? f.yara_matches.length : true));
    }
    return files;
}

function renderCarvedFiles(payload) {
    const files = payload.files || [];
    const totalCount = files.length;
    const maliciousCount = files.filter(f => f.malicious).length;
    const yaraCount = files.filter(f => f.yara_matches && (Array.isArray(f.yara_matches) ? f.yara_matches.length : true)).length;

    $('#carved-summary').text(
        totalCount
            ? `${totalCount} arquivo(s) · ${maliciousCount} malicioso(s) · ${yaraCount} match(es) YARA`
            : 'Nenhum arquivo extraído'
    );

    if (maliciousCount > 0) {
        $('#carved-badge').text(maliciousCount).removeClass('bg-secondary bg-warning text-dark').addClass('bg-danger');
    } else if (yaraCount > 0) {
        $('#carved-badge').text(yaraCount).removeClass('bg-secondary bg-danger').addClass('bg-warning text-dark');
    } else {
        $('#carved-badge').text(totalCount).removeClass('bg-danger bg-warning text-dark').addClass('bg-secondary');
    }

    if (carvedDataTable) {
        try { carvedDataTable.destroy(); } catch (e) { /* ignore */ }
        carvedDataTable = null;
    }
    $('#carved-tbody').empty();

    const isAdmin = currentUser && currentUser.role === 'admin';
    const rows = _filterCarvedRows(files);

    rows.forEach(f => {
        const filename = f.filename || `${(f.sha256 || '').slice(0, 12)}.bin`;
        const ctype = f.content_type || '—';
        const size = formatBytes(f.size_bytes || 0);
        const sha256 = f.sha256 || '';
        const src = f.src_ip ? `${f.src_ip} → ${f.dst_ip || '?'}` : (f.source_url || '—');
        const carvedAt = f.carved_at ? new Date(f.carved_at).toLocaleString() : '—';
        const downloadBtn = isAdmin && sha256
            ? `<a class="btn btn-sm btn-outline-primary" href="/api/carved-files/${escHtml(sha256)}/download" title="Download (admin, auditado)"><i class="fas fa-download"></i></a>`
            : `<button class="btn btn-sm btn-outline-secondary" disabled title="Apenas administradores"><i class="fas fa-lock"></i></button>`;

        const rowClass = f.malicious ? 'table-danger' : (f.yara_matches && (Array.isArray(f.yara_matches) ? f.yara_matches.length : true) ? 'table-warning' : '');
        const tr = $(`
            <tr class="${rowClass}" data-sha256="${escHtml(sha256)}">
                <td class="carved-detail-toggle" style="width:24px;cursor:pointer"><i class="fas fa-chevron-right"></i></td>
                <td><code title="${escHtml(filename)}">${escHtml(filename.length > 40 ? filename.slice(0, 37) + '…' : filename)}</code></td>
                <td><small>${escHtml(ctype)}</small></td>
                <td data-order="${f.size_bytes || 0}">${size}</td>
                <td><code class="small" title="${escHtml(sha256)}">${escHtml(_shortHash(sha256))}</code></td>
                <td><small>${escHtml(src)}</small></td>
                <td>${_carvedRepBadge(f)}</td>
                <td>${_carvedYaraBadge(f)}</td>
                <td><small>${escHtml(carvedAt)}</small></td>
                <td>${downloadBtn}</td>
            </tr>
        `);
        $('#carved-tbody').append(tr);
    });

    carvedDataTable = $('#carved-table').DataTable({
        order: [[3, 'desc']],
        pageLength: 25,
        language: {
            search: 'Buscar:',
            lengthMenu: 'Mostrar _MENU_ por página',
            info: '_START_ a _END_ de _TOTAL_',
            paginate: { previous: '<', next: '>' },
            emptyTable: 'Nenhum arquivo extraído neste scan.',
            zeroRecords: 'Nenhum arquivo corresponde ao filtro.',
        },
        columnDefs: [
            { orderable: false, targets: [0, 9] },
        ],
    });
}

function _buildCarvedDetailHtml(f) {
    const labels = Array.isArray(f.labels) ? f.labels : [];
    const vt = f.vt_data || null;
    const mb = f.mb_data || null;
    const yara = Array.isArray(f.yara_matches) ? f.yara_matches : (f.yara_matches ? [f.yara_matches] : []);

    let parts = ['<div class="carved-detail p-2">'];

    parts.push('<div class="row g-3">');
    parts.push('<div class="col-md-6"><table class="table table-sm mb-0">');
    parts.push(`<tr><td class="text-muted">SHA-256</td><td><code class="small">${escHtml(f.sha256 || '')}</code></td></tr>`);
    if (f.sha1) parts.push(`<tr><td class="text-muted">SHA-1</td><td><code class="small">${escHtml(f.sha1)}</code></td></tr>`);
    if (f.md5)  parts.push(`<tr><td class="text-muted">MD5</td><td><code class="small">${escHtml(f.md5)}</code></td></tr>`);
    if (f.source_url) parts.push(`<tr><td class="text-muted">URL</td><td><code class="small">${escHtml(f.source_url)}</code></td></tr>`);
    if (f.protocol)   parts.push(`<tr><td class="text-muted">Protocolo</td><td>${escHtml(f.protocol)}</td></tr>`);
    if (f.direction)  parts.push(`<tr><td class="text-muted">Direção</td><td>${escHtml(f.direction)}</td></tr>`);
    if (f.family)     parts.push(`<tr><td class="text-muted">Família</td><td>${escHtml(f.family)}</td></tr>`);
    if (labels.length) {
        parts.push(`<tr><td class="text-muted">Labels</td><td>${labels.map(l => `<span class="badge bg-danger me-1">${escHtml(l)}</span>`).join('')}</td></tr>`);
    }
    parts.push('</table></div>');

    parts.push('<div class="col-md-6">');
    // VirusTotal block
    if (vt) {
        parts.push('<div class="carved-section"><h6 class="mb-1"><i class="fas fa-virus"></i> VirusTotal</h6>');
        if (vt.error) {
            parts.push(`<small class="text-muted">${escHtml(String(vt.error))}</small>`);
        } else {
            const stats = vt.last_analysis_stats || vt.stats || {};
            const malicious = stats.malicious || 0;
            const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);
            parts.push(`<div><strong>${malicious}</strong> / ${total} engines maliciosos</div>`);
            if (vt.meaningful_name) parts.push(`<div class="small text-muted">nome: ${escHtml(vt.meaningful_name)}</div>`);
            if (vt.type_description) parts.push(`<div class="small text-muted">tipo: ${escHtml(vt.type_description)}</div>`);
            if (vt.reputation !== undefined) parts.push(`<div class="small text-muted">reputação: ${escHtml(String(vt.reputation))}</div>`);
        }
        parts.push('</div>');
    }
    // MalwareBazaar block
    if (mb) {
        parts.push('<div class="carved-section mt-2"><h6 class="mb-1"><i class="fas fa-bug"></i> MalwareBazaar</h6>');
        if (mb.error) {
            parts.push(`<small class="text-muted">${escHtml(String(mb.error))}</small>`);
        } else {
            if (mb.signature) parts.push(`<div>signature: <strong>${escHtml(mb.signature)}</strong></div>`);
            if (mb.file_type) parts.push(`<div class="small text-muted">tipo: ${escHtml(mb.file_type)}</div>`);
            if (mb.first_seen) parts.push(`<div class="small text-muted">first seen: ${escHtml(mb.first_seen)}</div>`);
            if (Array.isArray(mb.tags) && mb.tags.length) {
                parts.push(`<div>${mb.tags.slice(0, 8).map(t => `<span class="badge bg-warning text-dark me-1">${escHtml(String(t))}</span>`).join('')}</div>`);
            }
        }
        parts.push('</div>');
    }
    if (!vt && !mb && !f.looked_up_at) {
        parts.push('<small class="text-muted">Nenhuma consulta de reputação ainda. Configure <code>VIRUSTOTAL_API_KEY</code> ou <code>MALWAREBAZAAR_AUTH_KEY</code>.</small>');
    }
    parts.push('</div>');
    parts.push('</div>');

    // YARA matches block (full width)
    if (yara.length) {
        parts.push('<div class="mt-3"><h6 class="mb-1"><i class="fas fa-fingerprint"></i> YARA matches</h6>');
        parts.push('<table class="table table-sm mb-0"><thead><tr><th>Regra</th><th>Tags</th><th>Meta</th></tr></thead><tbody>');
        yara.forEach(m => {
            if (typeof m === 'string') {
                parts.push(`<tr><td><code>${escHtml(m)}</code></td><td></td><td></td></tr>`);
                return;
            }
            const rule = (m && m.rule) || '?';
            const tags = Array.isArray(m && m.tags) ? m.tags.join(', ') : '';
            const meta = m && m.meta && typeof m.meta === 'object'
                ? Object.entries(m.meta).map(([k, v]) => `${k}=${v}`).join(', ')
                : '';
            parts.push(`<tr><td><code>${escHtml(rule)}</code></td><td><small>${escHtml(tags)}</small></td><td><small>${escHtml(meta)}</small></td></tr>`);
        });
        parts.push('</tbody></table></div>');
    }

    parts.push('</div>');
    return parts.join('');
}

// Inline event handlers in templates/index.html and HTML strings generated
// here reference these functions by bare name (e.g. onclick="logout()"),
// which requires them on the global scope. Under Vite/ESM the module no
// longer leaks declarations to window, so re-export them explicitly.
Object.assign(window, {
    // Header / global UI
    toggleTheme, logout,
    showLoginModal, showChangePasswordModal,
    showAuditLogModal, loadAuditLog,
    showUserMgmtModal, showAdminSettingsModal,
    // Auth & user mgmt forms
    submitLogin, submitChangePassword, createUser, runManualLookup,
    toggleUserEnabled, deleteUserConfirm, saveApiKey, clearApiKey,
    // Scan list / aggregate view
    applyDateFilter, clearDateFilter,
    viewScan, deleteScan, deleteSelectedScans,
    // Reports / packets
    downloadReport, downloadAlertsReport, loadPackets, viewPacketDetail,
    // Alerts
    changeAlertTriage,
    // IPs
    editIpName, editIpNameFromModal, deleteIpName,
    showIpEvolution, showIpProtocols, showProtocolIPs,
    // Graph view (B.6) — inline onclick targets in the detail panel.
    focusIpInIpsTab, focusAlertsByIp,
    // Settings
    deleteTrustedRange,
    // SOC IPs
    deleteSocIp,
});

