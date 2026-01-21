// --- START: Sample Searches Database ---
const ALL_SAMPLE_SEARCHES = [
    'index=security sourcetype=linux_secure "failed password" | stats count by user', 'index=web status>=500 | top 3 uri, clientip', 'index=network dest_port=22 | timechart span=1h count',
    'index=app service_name=checkout | where status IN (401, 403)', 'index=os | rare limit=5 process_name', 'service.name: "api-gateway" AND http.response.duration: >1000ms',
    'event.outcome: failure AND message: "connection refused"', 'index: server_logs AND NOT log.level: DEBUG', 'http.request.method: POST AND response_time: [500 TO 2000]',
    'host.name: web-prod-*.example.com', 'service:billing env:prod status:error', 'source:nginx @duration:>500ms @http.status_code:[400 TO 499]',
    'host:ip-10-0-1-100.internal source:security_log level:ALERT', 'tags:(team:frontend AND version:1.0) message:"page load slow"', 'sum:system.net.bytes_rcvd{role:loadbalancer} by {interface}',
    '{job="api-service", environment="prod"} |= "payment failed"', '{container="nginx"} | json | status_code >= 500', 'rate({job="auth", level="error"}[5m])',
    '{job="web"} | logfmt | unwrap latency_ms', '{namespace="staging"} |~ "timeout"', 'source=access_logs | where status >= 500 | fields @timestamp, clientip',
    'source=firewall | stats count() by src_ip, action', 'source=app_metrics | stats avg(latency_ms) by span(@timestamp, 1h)', 'source=auth | dedup user_id | fields user_id, user_email',
    'source=endpoint | where event_type="process_creation"', '_sourceCategory=prod/web | count by status_code | sort by status_code', '_index=firewalls and _time > -1h | max(bytes) by src_ip',
    '_sourceHost=db-01 and error | parse "user=*," as user | count by user', '_index=apache and "/admin" | json auto "request_time" as latency', '_source=auth.log and "session expired" | count',
    'Log Message Source="Windows Auth" and Classification="Authentication Failure"', 'LMS="Firewall" and Direction="Outbound" and Port="22" | group by Source IP', 'Engine Name="File Integrity" and Subject="system32\\config\\security"',
    'Log Message Source="Web Server" and MessageType="HTTP Error"', 'Common Event="User Login" and User="admin" | group by Host IP', 'index=windows sourcetype="WinEventLog:Security" EventCode=4625 | stats count by user, src_ip',
    'index=main "error" | top limit=10 host', 'index=network (action=blocked OR action=denied) | stats count by src_ip, dest_port', 'index=sales | timechart span=1d sum(revenue) by product_name',
    'index=inventory | stats latest(location) by asset_id', 'sourcetype=access_combined (status=404 OR status=503) | stats count by status, uri_path', 'index=msexchange | search "virus" | table _time, user, subject',
    'index=firewall dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12" | top src_ip', 'index=vpn sourcetype=cisco_asa "session started" | transaction user maxspan=1h | where duration > 3600',
    '| tstats count where index=network by src_ip | where count > 10000', 'index=main | search "database connection failed" | cluster', 'sourcetype=iis | rex field=cs_uri_stem "^\/api\/(?<api_version>v[0-9]+)\/" | stats count by api_version',
    'index=mail | search subject="*invoice*" (filetype=pdf OR filetype=zip)', 'index:auth user=* NOT (user:admin OR user:guest) | stats dc(user) as distinct_users',
    'event.category: process AND event.action: "Process Create" AND process.name: "powershell.exe"', 'event.module: "microsoft-windows-security-auditing" AND event.code: 4625', 'network.direction: outbound AND destination.port: 22',
    'user.name: ("admin" OR "root") AND event.outcome: success', 'url.path: "/login" AND http.request.method: POST AND http.response.status_code: 200', 'not log.level: "INFO"',
    'process.parent.name: "cmd.exe" AND process.command_line: "*whoami*"', 'dns.question.name: "*evil-domain.com"', 'file.extension: ("exe" OR "dll") AND file.path: "C:\\Users\\*\\Downloads\\*"',
    'registry.path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"', 'network.transport: tcp AND network.bytes > 10000000', 'cloud.provider: aws AND cloud.service.name: S3 AND event.action: "DeleteBucket"',
    'error.message: "NullPointerException"', 'kubernetes.namespace.name: "kube-system" AND log.level: "error"', 'event.dataset: "windows.sysmon" AND event.code: 3', 'event.dataset: "windows.sysmon" AND event.code: 11',
    'SecurityEvent | where EventID == 4625 | summarize count() by Account, IpAddress', 'SigninLogs | where ResultType == 50126 | summarize count() by UserPrincipalName',
    'CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" and Activity == "THREAT" | top 10 SourceIP', 'AzureActivity | where OperationName == "Delete Virtual Machine" and ActivityStatus == "Succeeded"',
    'DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine contains "iex"', 'let suspicious_ips = dynamic(["1.2.3.4", "5.6.7.8"]); NetworkConnectionEvents | where RemoteIP in (suspicious_ips)',
    'OfficeActivity | where Operation == "MailboxLogin" and ResultStatus == "Failed"', 'SecurityAlert | where ProviderName == "Azure Security Center" | summarize count() by AlertName',
    'Syslog | where Facility == "auth" and SyslogMessage contains "failed password"', 'let timeframe = 1h; AWSCloudTrail | where EventTime > ago(timeframe) and EventName == "ConsoleLogin" | where ResponseElements contains "Failure"',
    'SigninLogs | where ConditionalAccessStatus == "failure"', 'DeviceFileEvents | where InitiatingProcessFileName == "outlook.exe" and FileName endswith ".zip"',
    'VMConnection | where Direction == "inbound" | summarize sum(BytesReceived) by SourceIp | order by sum_BytesReceived desc', 'AppServiceHTTPLogs | where ScStatus >= 500 | summarize count() by CsHost, UriStem',
    'AzureDiagnostics | where Category == "FirewallLogs" and msg_s contains "DENY"', '_sourceCategory=aws/cloudtrail "DeleteBucket" | json "eventName", "awsRegion" | count by eventName, awsRegion',
    '_sourceName="access_log" | parse regex "(?<client_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" | count by client_ip | sort by _count', '_sourceCategory=os/windows EventCode=4625 | parse "Account Name:\t\t(?<user>.*)" | count by user',
    'error OR exception', '"payment failed" | json "orderId", "error" | count by error', 'status_code=404 | count_frequent(url)', '_sourceCategory=paloalto | parse "THREAT" | count by src_ip, dest_ip',
    '_view=auth | where outcome="failure" | count by user', '(!_sourceCategory="dev/*") AND "timeout" | count by _sourceHost', 'sum(rate({app="ingress"} | json | status_code=~"5.."[1m])) by (path)',
    '{app="database"} |~ "error|exception" != "test"', 'count_over_time({app="login"} |~ "failed login"[10m])', 'sum(bytes_over_time({job="proxy"}[1h])) by (host)',
    '{job=~"kafka|zookeeper"} | line_format "{{.job}}: {{.message}}"', 'label_replace({app="api"}, "service", "api-gateway", "app", ".*")', '{filename="/var/log/syslog"} |~ "sshd" AND "session opened"',
    '{app="store"} | json | latency > 500 and status_code = 200'
];
const SAMPLES_SECURITY = [
    'index=security sourcetype=linux_secure "failed password" | stats count by user', 'index=network dest_port=22 | timechart span=1h count', 'source=firewall | stats count() by src_ip, action',
    'Log Message Source="Windows Auth" and Classification="Authentication Failure"', 'index=windows sourcetype="WinEventLog:Security" EventCode=4625 | stats count by user, src_ip', 'index=network (action=blocked OR action=denied) | stats count by src_ip, dest_port',
    'index=mail | search subject="*invoice*" (filetype=pdf OR filetype=zip)', 'index:winlogbeat-* AND event.category: process AND event.action: "Process Create" AND process.name: "powershell.exe"', 'index:packetbeat-* AND network.direction: outbound AND destination.port: 22',
    'index:winlogbeat-* AND process.parent.name: "cmd.exe" AND process.command_line: "*whoami*"', 'index:auditbeat-* AND dns.question.name: "*evil-domain.com"', 'index:winlogbeat-* AND file.extension: ("exe" OR "dll") AND file.path: "C:\\Users\\*\\Downloads\\*"',
    'index:auditbeat-* AND registry.path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"', 'index:winlogbeat-* AND event.dataset: "windows.sysmon" AND event.code: 3', 'SecurityEvent | where EventID == 4625 | summarize count() by Account, IpAddress',
    'CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" and Activity == "THREAT" | top 10 SourceIP', 'DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine contains "iex"', 'OfficeActivity | where Operation == "MailboxLogin" and ResultStatus == "Failed"',
    'SecurityAlert | where ProviderName == "Azure Security Center" | summarize count() by AlertName', 'Syslog | where Facility == "auth" and SyslogMessage contains "failed password"', 'SigninLogs | where ConditionalAccessStatus == "failure"',
    'DeviceFileEvents | where InitiatingProcessFileName == "outlook.exe" and FileName endswith ".zip"', 'AzureDiagnostics | where Category == "FirewallLogs" and msg_s contains "DENY"', '_sourceCategory=os/windows EventCode=4625 | parse "Account Name:\t\t(?<user>.*)" | count by user',
    '_sourceCategory=paloalto | parse "THREAT" | count by src_ip, dest_ip', '_view=auth | where outcome="failure" | count by user', 'rate({job="auth", level="error"}[5m])',
    'count_over_time({app="login"} |~ "failed login"[10m])', '{filename="/var/log/syslog"} |~ "sshd" AND "session opened"', 'LMS="Firewall" and Direction="Outbound" and Port="22" | group by Source IP',
    'Engine Name="File Integrity" and Subject="system32\\config\\security"', 'Common Event="User Login" and User="admin" | group by Host IP'
];
const SAMPLES_IT_OPS = [
    'index=web status>=500 | top 3 uri, clientip', 'index=os | rare limit=5 process_name', 'source=access_logs | where status >= 500 | fields @timestamp, clientip', 'index=main "error" | top limit=10 host',
    'sourcetype=access_combined (status=404 OR status=503) | stats count by status, uri_path', 'index=main | search "database connection failed" | cluster', 'sourcetype=iis | rex field=cs_uri_stem "^\/api\/(?<api_version>v[0-9]+)\/" | stats count by api_version',
    'index:filebeat-* AND event.outcome: failure AND message: "connection refused"', 'index: server_logs AND NOT log.level: DEBUG', 'index:nginx-* AND http.request.method: POST AND response_time: [500 TO 2000]',
    'index:filebeat-* AND host.name: "web-prod-*.example.com"', 'index:filebeat-* AND service:billing AND env:prod AND status:error', 'index:nginx-* AND @duration:>500ms AND @http.status_code:[400 TO 499]',
    'index:filebeat-* AND tags:(team:frontend AND version:1.0) AND message:"page load slow"', 'index:filebeat-* AND url.path: "/login" AND http.request.method: POST AND http.response.status_code: 200', 'index:filebeat-* AND not log.level: "INFO"',
    'index:filebeat-* AND cloud.provider: aws AND cloud.service.name: S3 AND event.action: "DeleteBucket"', 'index:filebeat-* AND error.message: "NullPointerException"', 'index:kube-logs-* AND kubernetes.namespace.name: "kube-system" AND log.level: "error"',
    'AzureActivity | where OperationName == "Delete Virtual Machine" and ActivityStatus == "Succeeded"', 'AppServiceHTTPLogs | where ScStatus >= 500 | summarize count() by CsHost, UriStem', '_sourceCategory=prod/web | count by status_code | sort by status_code',
    '_sourceHost=db-01 and error | parse "user=*," as user | count by user', '_index=apache and "/admin" | json auto "request_time" as latency', '_source=auth.log and "session expired" | count',
    '"payment failed" | json "orderId", "error" | count by error', 'status_code=404 | count_frequent(url)', '(!_sourceCategory="dev/*") AND "timeout" | count by _sourceHost', '{job="api-service", environment="prod"} |= "payment failed"',
    '{container="nginx"} | json | status_code >= 500', '{namespace="staging"} |~ "timeout"', '{app="database"} |~ "error|exception" != "test"', '{job=~"kafka|zookeeper"} | line_format "{{.job}}: {{.message}}"',
    'Log Message Source="Web Server" and MessageType="HTTP Error"', '{app="store"} | json | latency > 500 and status_code = 200'
];
const SAMPLES_METRICS = [
    'index=sales | timechart span=1d sum(revenue) by product_name', 'source=app_metrics | stats avg(latency_ms) by span(@timestamp, 1h)', '| tstats count where index=network by src_ip | where count > 10000',
    'index:apm-service-* AND service.name: "api-gateway" AND http.response.duration: >1000ms', 'index:packetbeat-* AND network.transport: tcp AND network.bytes > 10000000', 'VMConnection | where Direction == "inbound" | summarize sum(BytesReceived) by SourceIp | order by sum_BytesReceived desc',
    'Perf | where ObjectName == "Processor" and CounterName == "% Processor Time" | summarize avg(CounterValue) by Computer, InstanceName', 'InsightsMetrics | where Namespace == "Azure.VM.Network.Inbound" | summarize avg(Val) by bin(TimeGenerated, 1h), Computer',
    '_index=firewalls and _time > -1h | max(bytes) by src_ip', 'outlier(avg_latency, 3) from ( _sourceCategory=prod/api | parse "latency=*ms" as latency_ms | avg(latency_ms) by _sourceHost )', 'sum(rate({app="ingress"} | json | status_code=~"5.."[1m])) by (path)',
    'sum(bytes_over_time({job="proxy"}[1h])) by (host)', 'avg_over_time({app="api"} | json | unwrap duration_ms [5m]) > 500', 'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, path))',
    'sum:system.net.bytes_rcvd{role:loadbalancer} by {interface}', '{job="web"} | logfmt | unwrap latency_ms'
];
const SAMPLE_MAP = { 'security': SAMPLES_SECURITY, 'it_ops': SAMPLES_IT_OPS, 'metrics': SAMPLES_METRICS };
// --- END: Sample Searches Database ---

// Global state
let state = { inputFile: null, outputFile: 'cribl_searches.csv', apiEndpoint: 'https://ai.cribl.cloud/api/kql', isProcessing: false, stopRequested: false, apiAbortController: null, fileContent: null, csvContent: null };

// --- Logging Functions ---
const log = (message, type = 'INFO') => {
    const logElement = document.getElementById('log-output'); if (!logElement) { console.error("Log output element missing"); return; }
    const colorMap = { INFO: 'text-blue-600', SUCCESS: 'text-green-600 font-bold', ERROR: 'text-red-600 font-bold', WARN: 'text-yellow-600' };
    const p = document.createElement('p'); p.className = colorMap[type] || 'text-gray-900'; 
    p.innerHTML = `[${type}] ${message}`; logElement.appendChild(p);
    logElement.scrollTop = logElement.scrollHeight;
};

// Helper function to escape HTML
const escapeHtml = (unsafe) => {
    if (typeof unsafe !== 'string') return '';
    return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
 };

// Enhanced aiLog for detailed corrections + copy button
const aiLog = (logData) => {
    const logElement = document.getElementById('ai-debug-log'); if (!logElement) { console.error("AI Debug log element missing"); return; }
    const defaultMsg = logElement.querySelector('p.default-ai-log'); if (defaultMsg) logElement.innerHTML = ''; 
    const entryDiv = document.createElement('div'); entryDiv.className = 'ai-log-entry text-sm'; 
    let messageHtml = ''; let type = 'WARN'; 
    if (typeof logData === 'string') {
         messageHtml = `[INFO] ${escapeHtml(logData)}`; type = 'INFO'; entryDiv.className += ` text-blue-600`; 
    } else if (logData.type === 'correction') {
         type = logData.level || 'WARN'; const title = logData.reason || 'AI Mistake Corrected';
         const colorClass = type === 'ERROR' ? 'text-red-600 font-bold' : 'text-yellow-600';
         messageHtml = `<strong class="${colorClass}">[${type}] ${escapeHtml(title)}:</strong><br><span class="text-gray-600">- <strong>Source Query:</strong> ${escapeHtml(logData.sourceQuery)}</span><br><span class="text-gray-600">- <strong>Original AI Output:</strong> ${escapeHtml(logData.originalAiQuery)}</span><br><div><span class="text-gray-600">- <strong>Corrected Output:</strong> ${escapeHtml(logData.correctedQuery)}</span><button title="Copy Corrected KQL" class="ai-log-copy-button" data-kql="${escapeHtml(logData.correctedQuery)}" onclick="copyKQL(this.dataset.kql)"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg></button></div><hr class="ai-log-separator">`;
    } else { messageHtml = `[WARN] Unknown log format: ${escapeHtml(JSON.stringify(logData))}`; entryDiv.className += ` text-yellow-600`; }
    entryDiv.innerHTML = messageHtml; logElement.appendChild(entryDiv);
    logElement.scrollTop = logElement.scrollHeight;
};

// --- UI State & Utilities ---
const toggleDownloadButton = (show) => { // (from a.py)
    const downloadButton = document.getElementById('download-button'); const clearButton = document.getElementById('clear-button');
    if (downloadButton && clearButton) {
        if (show) { downloadButton.classList.remove('hidden'); clearButton.classList.remove('hidden'); } 
        else { downloadButton.classList.add('hidden'); if (!state.isProcessing) clearButton.classList.remove('hidden'); }
    }
};
const setUIProcessing = (status) => { // (from a.py)
    state.isProcessing = status; const startButton = document.getElementById('start-button');
    const stopButton = document.getElementById('stop-button'); const buttonText = document.getElementById('button-text');
    const downloadButton = document.getElementById('download-button'); const clearButton = document.getElementById('clear-button');
    if (!startButton || !stopButton || !buttonText || !clearButton || !downloadButton) { return; }
    startButton.disabled = status;
    if (status) {
        buttonText.innerHTML = '<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white inline" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Converting...';
        downloadButton.classList.add('hidden'); clearButton.classList.add('hidden'); 
        stopButton.classList.remove('hidden'); stopButton.disabled = false;
    } else {
        buttonText.textContent = '🚀 Start'; stopButton.classList.add('hidden'); clearButton.classList.remove('hidden'); 
        if(state.csvContent) downloadButton.classList.remove('hidden'); 
    }
};
const stopConversion = () => { // (from a.py)
    if (state.isProcessing) {
        log('Stop request received.', 'WARN'); state.stopRequested = true;
        if (state.apiAbortController) { state.apiAbortController.abort(); }
        const stopButton = document.getElementById('stop-button'); if (stopButton) stopButton.disabled = true; 
    }
};
const clearResults = () => { // (from a.py + AI log reset)
    state.csvContent = null;
    const resultsBody = document.getElementById('results-table-body'); if (resultsBody) resultsBody.innerHTML = '';
    const noResultsMsg = document.getElementById('no-results-message'); if (noResultsMsg) { noResultsMsg.classList.remove('hidden'); noResultsMsg.textContent = 'No queries converted yet.'; } 
    const logOutput = document.getElementById('log-output'); if (logOutput) logOutput.innerHTML = '';
    // Reset AI log
    const aiLogElement = document.getElementById('ai-debug-log');
    if (aiLogElement) { aiLogElement.innerHTML = '<p class="default-ai-log text-gray-500">[INFO] AI corrections log.</p>'; }
    toggleDownloadButton(false);
};
// *** MODIFIED: clearAll includes URL input ***
const clearAll = () => { // (from a.py)
    clearResults(); 
    state.fileContent = null; state.inputFile = null;
    const displaySpan = document.getElementById('input-file-display'); if (displaySpan) displaySpan.textContent = 'No file selected';
    const fileInput = document.getElementById('input-file'); if (fileInput) fileInput.value = null; 
    const urlInput = document.getElementById('url-input'); if (urlInput) urlInput.value = ''; // <<< ADDED
    const loadedPanel = document.getElementById('loaded-searches-panel'); if (loadedPanel) loadedPanel.classList.add('hidden');
    const loadedTextarea = document.getElementById('loaded-searches-textarea'); if (loadedTextarea) loadedTextarea.value = '';
    log('Application cleared.', 'INFO');
};

// Copy KQL function (handles HTML entities)
const copyKQL = (text) => { // (Modified to handle decoding)
     const decodeHtml = (html) => { const txt = document.createElement("textarea"); txt.innerHTML = html; return txt.value; }
     const decodedText = decodeHtml(text);
    const textarea = document.createElement('textarea'); textarea.value = decodedText; 
    textarea.style.position = 'fixed'; textarea.style.opacity = '0'; 
    document.body.appendChild(textarea); textarea.select();
    try { if (document.execCommand('copy')) log('KQL copied!', 'INFO'); else log('Copy failed (exec).', 'WARN'); } 
    catch (err) { log('Copy failed: ' + err.message, 'ERROR'); }
    document.body.removeChild(textarea);
};
const addResultToTable = (source, kql, vendor, status) => { // (from a.py)
    const noResultsMsg = document.getElementById('no-results-message'); if (noResultsMsg) noResultsMsg.classList.add('hidden');
    const tbody = document.getElementById('results-table-body'); if (!tbody) { return; }
    const row = tbody.insertRow(); let kqlDisplay = kql; let statusColor = 'text-gray-900'; 
    if (status === 'ERROR') { kqlDisplay = '[Conversion Failed]'; statusColor = 'text-red-600 font-medium'; } 
    else if (status === 'CANCELLED') { kqlDisplay = '[Cancelled by User]'; statusColor = 'text-yellow-600 font-medium'; }
    row.className = status === 'ERROR' ? 'bg-red-50' : 'hover:bg-gray-100 transition duration-100';
    let cellVendor = row.insertCell(); cellVendor.className = 'whitespace-nowrap text-sm text-gray-900'; cellVendor.textContent = vendor;
    let cellSource = row.insertCell(); cellSource.className = 'text-sm max-w-sm lg:max-w-md text-gray-900'; cellSource.textContent = source;
    let cellKql = row.insertCell(); cellKql.className = `${statusColor} text-sm max-w-sm lg:max-w-md`; cellKql.textContent = kqlDisplay;
    let cellCopy = row.insertCell(); cellCopy.className = 'whitespace-nowrap text-center text-sm';
    if (status === 'SUCCESS') {
        const button = document.createElement('button'); button.title = "Copy KQL";
        button.className = "text-blue-500 hover:text-blue-700 transition duration-150 p-1 rounded-full hover:bg-blue-100 focus:outline-none focus:ring-2 focus:ring-blue-500";
        button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`;
        button.dataset.kql = kql; button.addEventListener('click', (e) => copyKQL(e.currentTarget.dataset.kql)); 
        cellCopy.appendChild(button);
    } else { cellCopy.textContent = '---'; }
    const resultsContainer = document.getElementById('results-table-wrapper');
     if (resultsContainer && resultsContainer.scrollHeight > resultsContainer.clientHeight) { resultsContainer.scrollTop = resultsContainer.scrollHeight; }
};
const updateSearchContent = (content, sourceName) => { // (from a.py - Verified panel show logic)
    clearResults(); 
    state.fileContent = content; log(`Loaded: ${sourceName}`, 'SUCCESS');
    const displaySpan = document.getElementById('input-file-display'); if (displaySpan) displaySpan.textContent = sourceName;
    const loadedPanel = document.getElementById('loaded-searches-panel'); const loadedTextarea = document.getElementById('loaded-searches-textarea');
    if (loadedPanel && loadedTextarea) {
        loadedTextarea.value = state.fileContent; const lineCount = state.fileContent.split('\n').length;
        loadedTextarea.rows = Math.max(5, Math.min(lineCount, 20)); 
        loadedPanel.classList.remove('hidden'); // <<< THIS LINE IS CRITICAL
        loadedTextarea.scrollTop = 0; 
    }
    log('--- Loaded Content Start ---', 'INFO');
    state.fileContent.split('\n').forEach(line => { if (line.trim()) log(`[LOADED] ${line.substring(0, 150)}${line.length > 150 ? '...' : ''}`, 'INFO'); });
    log('--- Loaded Content End ---', 'INFO');
};
const processFile = (file) => { // (from a.py)
    if (!file) return;
    if (!file.type.match('text.*') && !['.spl', '.log', '.csv', '.txt'].some(ext => file.name.endsWith(ext))) { log(`Invalid file: ${file.name}`, 'ERROR'); return; }
    clearResults(); state.inputFile = file; const reader = new FileReader();
    reader.onload = (e) => updateSearchContent(e.target.result, file.name);
    reader.onerror = () => { log('Error reading file.', 'ERROR'); state.fileContent = null; }; reader.readAsText(file);
};
const handleFileSelect = (event) => { // (from a.py)
     const file = event.target.files[0]; processFile(file); event.target.value = null; 
     const urlInput = document.getElementById('url-input'); if (urlInput) urlInput.value = ''; // Clear URL input
};
const handlePaste = (e) => { // (from a.py)
     e.preventDefault(); e.stopPropagation(); clearResults(); 
     const text = (e.clipboardData || window.clipboardData).getData('text');
     if (text && text.trim()) {
        state.inputFile = null; const fileInput = document.getElementById('input-file'); if (fileInput) fileInput.value = null;
        const urlInput = document.getElementById('url-input'); if (urlInput) urlInput.value = ''; // Clear URL input
        updateSearchContent(text, "Pasted text");
     } else { log('No text found on clipboard.', 'WARN'); }
};
const getRandomSamples = (sampleArray, count) => { // (from a.py)
    const shuffled = [...sampleArray]; let m = shuffled.length, t, i;
    while (m) { i = Math.floor(Math.random() * m--); t = shuffled[m]; shuffled[m] = shuffled[i]; shuffled[i] = t; }
    return shuffled.slice(0, count);
};
const loadSampleCategory = (category) => { // (from a.py)
     clearResults(); 
     const sampleArray = SAMPLE_MAP[category] || []; if (!sampleArray.length) { log(`No samples for: ${category}`, 'WARN'); return; }
     const count = 10; const samples = getRandomSamples(sampleArray, count); const sampleContent = samples.join('\n');
     state.inputFile = null; const fileInput = document.getElementById('input-file'); if (fileInput) fileInput.value = null;
     const urlInput = document.getElementById('url-input'); if (urlInput) urlInput.value = ''; // Clear URL input
     updateSearchContent(sampleContent, `${count} Random ${category.replace('_', ' ')} Samples`);
};
const downloadCSV = (content, filename) => { // (from a.py)
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' }); const link = document.createElement("a");
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob); link.setAttribute("href", url); link.setAttribute("download", filename);
        link.style.visibility = 'hidden'; document.body.appendChild(link); link.click(); document.body.removeChild(link);
        URL.revokeObjectURL(url); log(`Downloaded '${filename}'.`, 'SUCCESS');
    } else { log('Download not supported.', 'ERROR'); }
};
const downloadResults = () => { // (from a.py)
    if (state.csvContent && state.outputFile) { downloadCSV(state.csvContent, state.outputFile); } 
    else { log('No results to download.', 'WARN'); }
};

// *** NEW: Load from URL Function ***
const loadFromUrl = async () => {
    const urlInput = document.getElementById('url-input');
    if (!urlInput) {
        log('URL input field not found.', 'ERROR');
        return;
    }
    const url = urlInput.value.trim();
    if (!url) {
        log('Please enter a URL to load.', 'WARN');
        return;
    }

    // Clear other inputs and results
    clearResults();
    state.inputFile = null;
    const fileInput = document.getElementById('input-file');
    if (fileInput) fileInput.value = null;
    const displaySpan = document.getElementById('input-file-display');
    if (displaySpan) displaySpan.textContent = 'No file selected';

    log(`Fetching content from: ${url}`, 'INFO');

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Server responded with status ${response.status} (${response.statusText})`);
        }
        const text = await response.text();
        if (!text || !text.trim()) {
            log('URL fetched, but it contained no text content.', 'WARN');
            return;
        }
        
        // Use a simple name for the "source"
        let sourceName = 'Loaded from URL';
        try {
            const urlObj = new URL(url);
            sourceName = `Loaded from ${urlObj.hostname}${urlObj.pathname.substring(0, 30)}...`;
        } catch (_) { /* Use default if URL parsing fails */ }

        updateSearchContent(text, sourceName);

    } catch (error) {
        log(`Failed to fetch from URL: ${error.message}`, 'ERROR');
        log('Note: This may be due to a network error or CORS policy on the remote server.', 'WARN');
    }
};

// *** MODIFIED: Download Panel Content Function ***
const downloadPanel = (elementId, filename) => {
    const element = document.getElementById(elementId);
    if (!element) {
        log(`Error: Could not find element '${elementId}' to download.`, 'ERROR');
        return;
    }
    
    let content = '';
    
    // Handle different element types
    if (element.tagName === 'TEXTAREA') {
        content = element.value;
    } else if (element.id === 'results-table-body') {
        // Special handling for results table
        content = "Vendor\tSource\tCribl Search\n"; // TSV header
        element.querySelectorAll('tr').forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 3) {
                // Get text, replace newlines/tabs within cell text to keep rows clean
                const vendor = (cells[0].textContent || '').replace(/\s+/g, ' ');
                const source = (cells[1].textContent || '').replace(/\s+/g, ' ');
                const kql = (cells[2].textContent || '').replace(/\s+/g, ' ');
                content += `${vendor}\t${source}\t${kql}\n`;
            }
        });
    } else if (element.id === 'ai-debug-log') {
        // Special handling for AI log (which uses divs, not p tags)
        const entries = element.querySelectorAll('.ai-log-entry');
        if (entries.length > 0) {
             content = Array.from(entries)
                              .map(div => div.innerText || '') // Use innerText to preserve formatting
                              .join('\n---------------------------------\n'); // Separator
        } else {
            // Handle default message
            const defaultMsg = element.querySelector('p.default-ai-log');
            if (defaultMsg) content = defaultMsg.textContent || '';
        }
    } else {
        // Default for log panels (divs with <p> tags, e.g., console)
        content = Array.from(element.querySelectorAll('p'))
                         .map(p => p.textContent || '')
                         .join('\n');
    }

    if (!content.trim()) {
        log(`No content found in '${elementId}' to download.`, 'WARN');
        return;
    }
    
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
    const link = document.createElement("a");
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute("href", url);
        link.setAttribute("download", filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        log(`Downloaded panel content to '${filename}'.`, 'SUCCESS');
    } else {
        log('Download not supported by this browser.', 'ERROR');
    }
};

// --- Core Conversion Logic ---
const extractIndexName = (query) => { // (from a.py)
    const match = query.match(/(index|sourcetype|source|_index)\s*[=:]\s*([^ ]+|"[^"]+")/i);
    if (match) { let index = match[2].replace(/"/g, '').trim(); return index; } return null;
};
const extractSplunkByClause = (query) => { // (from a.py)
    const match = query.match(/(?:stats|timechart|chart)\s+.*?\s+by\s+([^|]+)/i);
    if (match && match[1]) { return match[1].trim(); } return null;
};

// *** MODIFIED: extractSplunkAggs captures aliases and simple count ***
const extractSplunkAggs = (query) => {
    const aggs = [];
    // Regex: func(field) or func(field) as alias
    const aggRegex = /\b(avg|sum|min|max|stdev|var|dc|distinct_count|latest|earliest|values|list)\s*\(([\w_.-]+)\)(?:\s+as\s+([\w_.-]+))?/gi;
    const match = query.match(/(?:stats|timechart|chart)\s+(.*?)(?:by\b|$)/i); if (!match || !match[1]) return aggs; 
    const aggString = match[1];
    for (const aggMatch of aggString.matchAll(aggRegex)) {
        const func = aggMatch[1].toLowerCase();
        const field = aggMatch[2];
        const alias = aggMatch[3] || `${func}(${field})`; // Use func(field) as default alias if not provided
        aggs.push({ func, field, alias });
    }
    // Handle simple 'count' or 'count as X'
    const countMatch = aggString.match(/\bcount(?:\s+as\s+([\w_.-]+))?/i);
    if (countMatch && !aggString.match(/\bcount\s*\(/i)) { // Ensure it's not count(field)
        aggs.push({ func: 'count', field: '', alias: countMatch[1] || 'count' });
    }
    return aggs;
};

// *** MODIFIED: extractKqlAggs captures aliases and handles count() ***
const extractKqlAggs = (kqlQuery) => {
    const aggs = [];
    // Regex: alias=func(field) or func(field) (which KQL makes alias)
    const aggRegex = /(?:([\w_.-]+)\s*=\s*)?\b(avg|sum|min|max|stdev|variance|dcount|any|count)\s*\(([\w_.-]*)\)/gi;
    // Find summarize/timestats *wherever* it occurs
    const match = kqlQuery.match(/\b(summarize|timestats)\s+(.*?)(?:by\b|$)/i); if (!match || !match[2]) return aggs; 
    const aggString = match[2];
    for (const aggMatch of aggString.matchAll(aggRegex)) {
        const func = aggMatch[2].toLowerCase();
        const field = aggMatch[3] || ''; // Field can be empty (e.g., count())
        const alias = aggMatch[1] || (func === 'count' ? 'count_' : `${func}_${field}`.replace(/_$/,'')); // KQL auto-alias for count() is 'count_'
        aggs.push({ func, field, alias });
    }
    return aggs;
};

// *** MODIFIED: This function replaces the field *inside* the agg func ***
const replaceKqlAggFields = (kqlQuery, splunkQuery) => {
    const splunkAggs = extractSplunkAggs(splunkQuery);
    const kqlAggs = extractKqlAggs(kqlQuery); // Get KQL aggs
    
    const iterationLength = Math.min(splunkAggs.length, kqlAggs.length);
    if (iterationLength === 0) return kqlQuery;
    
    let modifiedKql = kqlQuery;
    const splunkFuncMap = {'dc': 'dcount', 'distinct_count': 'dcount', 'var': 'variance', 'latest': 'any', 'earliest': 'any'};

    for (let i = 0; i < iterationLength; i++) {
        const splunkAgg = splunkAggs[i]; 
        const kqlAgg = kqlAggs[i];
        const expectedKqlFunc = splunkFuncMap[splunkAgg.func] || splunkAgg.func;

        if (expectedKqlFunc === kqlAgg.func && splunkAgg.field && splunkAgg.field !== kqlAgg.field) {
            const kqlFunc = kqlAgg.func; const kqlField = kqlAgg.field; const splunkField = splunkAgg.field;
            const escapedKqlField = kqlField.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            // Regex: (alias=)func(field)
            const kqlRegex = new RegExp(`(\\b[\\w_.-]+\\s*=\\s*)?${kqlFunc}\\s*\\(${escapedKqlField}\\)`, 'i');
            const replacement = `$1${kqlFunc}(${splunkField})`; 
            
            if (kqlRegex.test(modifiedKql)) {
                modifiedKql = modifiedKql.replace(kqlRegex, replacement);
            } 
        } 
    }
    return modifiedKql; // Return modified KQL
};

// *** NEW: This function replaces the alias *outside* the agg func ***
const replaceKqlAggAliases = (kqlQuery, splunkQuery) => {
    const splunkAggs = extractSplunkAggs(splunkQuery);
    const kqlAggs = extractKqlAggs(kqlQuery); // Get KQL aggs *after* field correction
    
    const iterationLength = Math.min(splunkAggs.length, kqlAggs.length);
    if (iterationLength === 0) return kqlQuery;

    let modifiedKql = kqlQuery;
    const splunkFuncMap = {'dc': 'dcount', 'distinct_count': 'dcount', 'var': 'variance', 'latest': 'any', 'earliest': 'any'};

    for (let i = 0; i < iterationLength; i++) {
        const splunkAgg = splunkAggs[i]; 
        const kqlAgg = kqlAggs[i];
        const expectedKqlFunc = splunkFuncMap[splunkAgg.func] || splunkAgg.func;
        
        if (expectedKqlFunc === kqlAgg.func && splunkAgg.field === kqlAgg.field) {
            if (splunkAgg.alias !== kqlAgg.alias) {
                const kqlFunc = kqlAgg.func;
                const kqlField = kqlAgg.field; 
                const kqlAlias = kqlAgg.alias;
                const splunkAlias = splunkAgg.alias;

                const escapedKqlAlias = kqlAlias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const kqlRegex = new RegExp(`\\b${escapedKqlAlias}\\s*=\\s*${kqlFunc}\\s*\\(${kqlField ? kqlField : ''}\\)`, 'i');
                const replacement = `${splunkAlias}=${kqlFunc}(${kqlField ? kqlField : ''})`;
                
                if (kqlRegex.test(modifiedKql)) {
                    modifiedKql = modifiedKql.replace(kqlRegex, replacement);
                }
            }
        }
    }
    return modifiedKql;
};

// *** NEW: Renames summarize count() to summarize count=count() ***
const addKqlCountAlias = (kqlQuery, splunkQuery) => {
    if (!/\bstats\s+count\b/i.test(splunkQuery) || /\bstats\s+count\s+as\b/i.test(splunkQuery)) {
        return kqlQuery;
    }
    const kqlRegex = /\b(summarize)\s+(count\(\))\s*(by\b.*)?/i;
    const match = kqlQuery.match(kqlRegex);
    if (match) {
        const byClause = match[3] || ''; 
        return kqlQuery.replace(kqlRegex, `$1 count=count() ${byClause}`);
    }
    return kqlQuery;
};

// *** NEW: Optimizes summarize count=count() (no by) to | count ***
const optimizeKqlCount = (kqlQuery, splunkQuery) => {
     if (/\bstats\s+count\b/i.test(splunkQuery) && !/\bstats\s+.*?\s+by\b/i.test(splunkQuery)) {
         const kqlRegex = /\b(summarize)\s+(count=)?count\(\)(?!\s+by\b)/i;
         if (kqlRegex.test(kqlQuery)) {
            const prefixRegex = /(.*?\s*\|\s*)?(summarize)\s+(count=)?count\(\)\s*$/i;
            const match = kqlQuery.match(prefixRegex);
            if (match) {
                const prefix = match[1] || ''; 
                return `${prefix}count`; 
            }
         }
    }
    return kqlQuery; 
};

// *** MODIFIED: replaceKqlByClause fixes regex ***
const replaceKqlByClause = (kqlQuery, splunkFields, originalSplunkQuery) => {
     if (!splunkFields) return kqlQuery;
    const kqlByRegex = /(.*?(?:summarize|timestats)\s+.*?\s+by\s+)([\w\s,()._'-]+?)(?=\s*\||$)/i;
    const match = kqlQuery.match(kqlByRegex); if (!match) return kqlQuery; 
    
    const queryPrefixAndCommand = match[1]; 
    const kqlFieldsPart = match[2].trim(); 
    const restOfQuery = kqlQuery.substring(match.index + match[0].length); 
    
    const cleanAiFields = kqlFieldsPart.toLowerCase().replace(/\s/g, ''); 
    const cleanSplunkFields = splunkFields.toLowerCase().replace(/\s/g, '');
    const isJustTimeBin = /^\s*bin\(TimeGenerated,\s*\w+\)\s*$/.test(kqlFieldsPart);

    if (cleanAiFields !== cleanSplunkFields && !isJustTimeBin) {
         const correctedKql = `${queryPrefixAndCommand}${splunkFields}${restOfQuery}`;
         return correctedKql; 
    }
    return kqlQuery; 
};
const updateDatasetInKQL = (kqlOutput, indexName) => { // (from a.py)
    if (!indexName) return kqlOutput; 
    const finalDatasetName = (indexName.startsWith('"') || indexName.startsWith("'")) ? indexName : `"${indexName}"`;
    let updatedKQL = kqlOutput; let replaced = false;
    updatedKQL = updatedKQL.replace(/dataset=[a-zA-Z_][a-zA-Z0-9_]*/g, () => { replaced = true; return `dataset=${finalDatasetName}`; });
    if(!replaced) updatedKQL = updatedKQL.replace(/dataset\([\"'][^\"']*[\"']\)/g, () => { replaced = true; return `dataset(${finalDatasetName})`; });
    if(!replaced) updatedKQL = updatedKQL.replace(/from [a-zA-Z_][a-zA-Z0-9_]*/g, () => { replaced = true; return `from ${finalDatasetName}`; });
    if (!replaced && /^[a-zA-Z_][a-zA-Z0-9_]*\s*\|/.test(updatedKQL.trim())) {
         updatedKQL = updatedKQL.replace(/^[a-zA-Z_][a-zA-Z0-9_]*( \|)/, (match, group1) => { replaced = true; return `${finalDatasetName}${group1}`; });
    }
    return updatedKQL;
};
const parseQueryLine = (line) => { // (from a.py)
    const trimmedLine = line.trim(); return { source: trimmedLine, search: trimmedLine }; 
};
const identifyVendor = (query) => { // (from a.py)
    const lowerQuery = query.toLowerCase();
    if (/\b(index|sourcetype|source)\s*[=:]\s*([^ ]+|"[^"]+")/i.test(query)) return 'Splunk';
    if (/\b(stats|eval|table|rename|chart|timechart|eventstats|tstats|metadata)\b/i.test(query)) return 'Splunk';
    if (/\bsearch\b/i.test(query) && !/\b(summarize|project|extend)\b/i.test(query)) return 'Splunk';
    if (/\b(summarize|project|extend|take|render|datatable|find|mv-expand|make-series)\b/i.test(query)) return 'KQL';
    if (lowerQuery.includes('|') && /\b(where|count)\b/i.test(query)) return 'KQL';
    if (/\w+:(?!(=|(\/\/)))/i.test(query) && !lowerQuery.includes('|')) { if (/\b(AND|OR|NOT)\b/.test(query)) return 'Elastic (Lucene)'; return 'Elastic (KQL)'; }
    if (/_sourceCategory\s*=/i.test(query)) return 'Sumo Logic';
    if (/{[^}]+}/.test(query) && (lowerQuery.includes('|~') || lowerQuery.includes('|='))) return 'Loki (LogQL)';
    return 'Unknown';
};
const sleep = (ms, signal) => { // (from a.py)
    return new Promise((resolve, reject) => {
        if (signal?.aborted) { return reject(new DOMException('Aborted', 'AbortError')); }
        const timeout = setTimeout(resolve, ms);
        signal?.addEventListener('abort', () => { clearTimeout(timeout); reject(new DOMException('Aborted', 'AbortError')); });
    });
};
const callAPI = async (content, signal, retries = 3) => { // (from a.py)
    const url = state.apiEndpoint; const payload = { messages: [{ content: content, role: 'user' }], datasets: [], fieldDescriptions: {} };
    log(`[API CALL] Sending (retries left: ${retries}): ${content.substring(0,100)}...`, 'INFO');
    for (let i = 0; i < retries; i++) {
        try {
            if (signal?.aborted) { throw new DOMException('Aborted', 'AbortError'); }
            const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: signal });
            if (!response.ok) { const errorText = await response.text(); log(`[API CALL] Error ${response.status}: ${errorText}`, 'ERROR'); throw new Error(`API returned ${response.status}`); }
            const jsonResponse = await response.json(); log(`[API CALL] Response OK (attempt ${i + 1})`, 'INFO');
            const kqlResult = jsonResponse.kql ? jsonResponse.kql.replace(/^cribl\s*(\|\s*)?/, '').trim() : '[KQL Field Missing]';
            return kqlResult;
        } catch (error) {
            if (error.name === 'AbortError') { log(`[API CALL] Aborted attempt ${i + 1}.`, 'WARN'); throw error; }
            log(`[API CALL] Attempt ${i + 1} failed: ${error.message}`, 'ERROR');
            if (i === retries - 1) { log('[API CALL] Max retries reached.', 'ERROR'); throw error; }
            const delay = Math.pow(2, i) * 1000; log(`[API CALL] Waiting ${delay}ms...`, 'INFO');
            try { await sleep(delay, signal); } catch (sleepAbortError) { if (sleepAbortError.name === 'AbortError') { log('[API CALL] Retry sleep aborted.', 'WARN'); throw sleepAbortError; } else { throw sleepAbortError;} }
        }
    }
};

// *** MODIFIED: startConversion applies corrections sequentially and logs difference at the end ***
const startConversion = async () => {
     if (state.isProcessing) { log('Conversion in progress.', 'WARN'); return; }
     const loadedTextarea = document.getElementById('loaded-searches-textarea');
     if (loadedTextarea && loadedTextarea.value.trim() && loadedTextarea.value !== state.fileContent) {
         log('Using edited content.', 'INFO'); state.fileContent = loadedTextarea.value;
     }
     if (!state.fileContent) { log('No content loaded.', 'ERROR'); return; }

    state.stopRequested = false; state.apiAbortController = null; 
    setUIProcessing(true); state.csvContent = null;
    document.getElementById('results-table-body').innerHTML = '';
    const noResultsMsg = document.getElementById('no-results-message'); if (noResultsMsg) { noResultsMsg.classList.add('hidden'); } 
    document.getElementById('log-output').innerHTML = '';
    const aiLogElement = document.getElementById('ai-debug-log');
    if (aiLogElement) { aiLogElement.innerHTML = '<p class="default-ai-log text-gray-500">[INFO] AI corrections log.</p>'; }
    toggleDownloadButton(false); 

    log('Starting conversion...', 'INFO');
    const rawLines = state.fileContent.split('\n').map(line => line.trim()).filter(line => line);
    log(`[PROCESS] Found ${rawLines.length} lines.`, 'INFO');
    const header = '"Vendor","Source","Cribl Search"\n';
    let csvContent = header; let successCount = 0; let failureCount = 0; let cancelCount = 0;
    let resultsAdded = false; 

    try { 
        for (let i = 0; i < rawLines.length; i++) {
            try { 
                log(`[PROCESS] Iteration ${i + 1}/${rawLines.length}`, 'INFO');
                if (state.stopRequested) { break; }

                const line = rawLines[i]; 
                const parsed = parseQueryLine(line); 
                
                if (!parsed || typeof parsed.search !== 'string' || typeof parsed.source !== 'string') {
                    log(`[PROCESS] Skipping invalid line data at index ${i}.`, 'ERROR'); failureCount++;
                    addResultToTable(line || `Line ${i+1} Error`, '[Parsing Error]', 'N/A', 'ERROR'); resultsAdded = true;
                    csvContent += `"N/A","${(line || `Line ${i+1} Error`).replace(/"/g, '""')}","[Parsing Error]"\n`; continue;
                }

                const sourceQuery = parsed.search; 
                const vendor = identifyVendor(sourceQuery); 
                let originalSource = parsed.source; 
                let csvOriginalSource = originalSource.replace(/"/g, '""'); 

                let finalKQL = '[Conversion Failed]'; let status = 'ERROR';
                let indexName = extractIndexName(sourceQuery); let placeholderUsed = false;
                if (!indexName) { indexName = 'your_dataset_here'; placeholderUsed = true; } 

                log(`[Query ${i + 1}] Processing (Vendor: ${vendor})...`, 'INFO');
                state.apiAbortController = new AbortController();
                let initialKqlResponse = ''; // Store the raw response
                
                try {
                    initialKqlResponse = await callAPI(sourceQuery, state.apiAbortController.signal);
                    let updatedKQL = initialKqlResponse; 

                    if (typeof updatedKQL !== 'string') { throw new Error("API response invalid."); }

                    // --- Post-Processing Steps ---
                    // 1. Fix dataset name (always run)
                    updatedKQL = updateDatasetInKQL(updatedKQL, indexName); 
                    
                    // 2. Fix Splunk-specific syntax (only if vendor is Splunk)
                    if (vendor === 'Splunk') { 
                        updatedKQL = replaceKqlByClause(updatedKQL, extractSplunkByClause(sourceQuery), sourceQuery); 
                        updatedKQL = replaceKqlAggFields(updatedKQL, sourceQuery);
                        updatedKQL = replaceKqlAggAliases(updatedKQL, sourceQuery); // Fix aliases
                        updatedKQL = addKqlCountAlias(updatedKQL, sourceQuery);    // Add count=
                        updatedKQL = optimizeKqlCount(updatedKQL, sourceQuery);   // Use | count
                    }
                    
                    // 3. Safety check for prepending dataset (always run last)
                    const startsWithPattern = /^(dataset\(|from |"[^"]+"|'[^']+'|[a-zA-Z_][a-zA-Z0-9_]*)/i.test(updatedKQL.trim());
                    if (!startsWithPattern && updatedKQL.trim()) {
                        let kqlToPrepend = updatedKQL.trim().startsWith('|') ? updatedKQL.trim().substring(1).trim() : updatedKQL.trim();
                        const finalDatasetName = (indexName.startsWith('"') || indexName.startsWith("'")) ? indexName : `"${indexName}"`;
                        updatedKQL = `${finalDatasetName} | ${kqlToPrepend}`;
                    }
                    // --- End Post-Processing ---

                    finalKQL = updatedKQL; // Assign the final, potentially corrected KQL
                    status = 'SUCCESS'; successCount++;
                    log(`[Query ${i + 1}] Conversion successful.`, 'SUCCESS');

                    // *** Log correction only if final result differs from initial AI response ***
                    if (finalKQL.trim() !== initialKqlResponse.trim()) {
                        aiLog({
                             type: 'correction', level: 'WARN', reason: 'AI Output Corrected',
                             sourceQuery: sourceQuery, originalAiQuery: initialKqlResponse, correctedQuery: finalKQL
                        });
                    }

                } catch (e) {
                     if (e.name === 'AbortError') { finalKQL = '[Cancelled by User]'; status = 'CANCELLED'; cancelCount++; log(`[Query ${i + 1}] Cancelled.`, 'WARN'); } 
                     else { finalKQL = '[Conversion Failed]'; status = 'ERROR'; failureCount++; log(`[Query ${i + 1}] Failed: ${e.message}`, 'ERROR');}
                } finally { state.apiAbortController = null; }

                const csvFinalKQL = (typeof finalKQL === 'string') ? finalKQL.replace(/"/g, '""') : '[Result Error]'; 
                csvContent += `"${vendor}","${csvOriginalSource}","${csvFinalKQL}"\n`;
                addResultToTable(sourceQuery, (typeof finalKQL === 'string' ? finalKQL : '[Result Error]'), vendor, status); 
                resultsAdded = true; 

                if (status === 'CANCELLED') { break; } 

            } catch (loopError) { 
                 log(`[PROCESS] Loop error ${i + 1}: ${loopError.message}`, 'ERROR');
                 addResultToTable(line || `Line ${i+1} Error`, '[Unexpected Error]', 'N/A', 'ERROR'); resultsAdded = true; failureCount++;
                 const errorSource = (line || `Line ${i+1} Error`).replace(/"/g, '""');
                 csvContent += `"N/A","${errorSource}","[Unexpected Error]"\n`;
            }
        } // --- End for loop ---
        log('[PROCESS] Loop finished.', 'INFO');
        if (!resultsAdded && noResultsMsg) { 
            noResultsMsg.textContent = 'No results generated. Check input or console log.'; noResultsMsg.classList.remove('hidden'); 
        }
    
    } finally {
         let totalProcessed = successCount + failureCount + cancelCount;
         if (state.stopRequested) log('--- Process Stopped ---', 'WARN'); else log('--- Process Complete ---', 'INFO');
         log(`Summary: ${totalProcessed}/${rawLines.length} processed. S:${successCount}, F:${failureCount}, C:${cancelCount}`, 'INFO');
         if (resultsAdded) { state.csvContent = csvContent; log('Results ready. Click "Download".', 'INFO'); }
         setUIProcessing(false); 
         log('[PROCESS] Cleanup finished.', 'INFO');
    }
};


// --- Dark Mode Logic ---
const DARK_MODE_KEY = 'kql_converter_dark_mode';
const initDarkMode = () => { // (from a.py)
    const savedMode = localStorage.getItem(DARK_MODE_KEY);
    let isDark = (savedMode === null) || (savedMode === 'true'); 
    const label = document.getElementById('theme-toggle-label');
    const htmlElement = document.documentElement;
    if (isDark) { htmlElement.classList.add('dark'); if(label) label.textContent = "Light Mode"; } 
    else { htmlElement.classList.remove('dark'); if(label) label.textContent = "Dark Mode"; }
};
const toggleDarkMode = () => { // (from a.py)
    const htmlElement = document.documentElement; const isCurrentlyDark = htmlElement.classList.contains('dark');
    const label = document.getElementById('theme-toggle-label');
    if (isCurrentlyDark) {
        htmlElement.classList.remove('dark'); localStorage.setItem(DARK_MODE_KEY, 'false');
        log('Switched to Light Mode.', 'INFO'); if(label) label.textContent = "Dark Mode";
    } else {
        htmlElement.classList.add('dark'); localStorage.setItem(DARK_MODE_KEY, 'true');
        log('Switched to Dark Mode.', 'INFO'); if(label) label.textContent = "Light Mode";
    }
};

// --- Drag/Drop/Paste Logic ---
const initFileHandlers = () => { // (from a.py)
    const dropZone = document.getElementById('drop-zone'); if (!dropZone) { return; }
    ['dragenter', 'dragover', 'dragleave', 'drop', 'paste'].forEach(evName => dropZone.addEventListener(evName, e => {e.preventDefault(); e.stopPropagation();}, false));
    ['dragenter', 'dragover'].forEach(evName => dropZone.addEventListener(evName, () => dropZone.classList.add('drop-zone-highlight'), false));
    ['dragleave', 'drop'].forEach(evName => dropZone.addEventListener(evName, () => dropZone.classList.remove('drop-zone-highlight'), false));
    dropZone.addEventListener('drop', (e) => { 
        if (e.dataTransfer.files.length) { 
            processFile(e.dataTransfer.files[0]); 
            const urlInput = document.getElementById('url-input'); if (urlInput) urlInput.value = ''; // Clear URL input
        } 
    }, false);
    dropZone.addEventListener('paste', handlePaste, false);
};

// --- App Initialization ---
document.addEventListener('DOMContentLoaded', () => { // (from a.py)
    initDarkMode(); 
    initFileHandlers(); 
    const outputInput = document.getElementById('output-filename');
    if (outputInput) { outputInput.value = state.outputFile; outputInput.addEventListener('input', (e) => { state.outputFile = e.target.value; }); }
    toggleDownloadButton(false); 
    const noResults = document.getElementById('no-results-message'); if (noResults) noResults.textContent = 'No queries converted yet...';
    const logP = document.querySelector('#log-output p'); if (logP) logP.className = "text-blue-600"; 
    const aiLogP = document.querySelector('#ai-debug-log p'); if(aiLogP) aiLogP.className = "default-ai-log text-gray-500"; 
});
