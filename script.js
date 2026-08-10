/* ============================================================
   NetSentry Dashboard — Interactive Scan Simulation (front-end only)
   ============================================================ */
(function () {
    'use strict';

    var DEFAULT_IP = '192.168.56.104';
    var SCAN_DURATION = 2800; // ms

    /* ---------------- Mock scan database ---------------- */
    var SCAN_DB = {
        '192.168.56.104': {
            services: [
                { port: 21,   service: 'ftp',          version: 'vsftpd 2.3.4',    status: 'critical' },
                { port: 80,   service: 'http',         version: 'Apache 2.4.49',   status: 'high' },
                { port: 139,  service: 'netbios-ssn',  version: 'Samba 3.X',       status: 'high' },
                { port: 445,  service: 'microsoft-ds', version: 'Windows 7 SMB',   status: 'critical' },
                { port: 22,   service: 'ssh',          version: 'OpenSSH 8.2',     status: 'low' },
                { port: 3306, service: 'mysql',        version: 'MySQL 5.5.8',     status: 'medium' }
            ],
            vulns: [
                { port: 445, cve: 'CVE-2017-0144',  desc: 'EternalBlue SMB RCE',   severity: 'critical' },
                { port: 21,  cve: 'CVE-2011-2523',  desc: 'vsftpd backdoor',       severity: 'critical' },
                { port: 80,  cve: 'CVE-2021-41773', desc: 'Apache path traversal', severity: 'high' },
                { port: 139, cve: 'CVE-2017-7494',  desc: 'Samba remote code exec', severity: 'high' }
            ]
        },
        '127.0.0.1': {
            services: [
                { port: 22,  service: 'ssh', version: 'OpenSSH 9.6', status: 'low' },
                { port: 631, service: 'ipp', version: 'CUPS 2.4.7',  status: 'medium' }
            ],
            vulns: [
                { port: 631, cve: 'CVE-2024-47176', desc: 'CUPS filter RCE', severity: 'medium' }
            ]
        },
        '192.168.56.101': {
            services: [
                { port: 22,   service: 'ssh',        version: 'OpenSSH 7.2',   status: 'medium' },
                { port: 80,   service: 'http',       version: 'Apache 2.4.18', status: 'high' },
                { port: 3306, service: 'mysql',      version: 'MySQL 5.7.12',  status: 'medium' },
                { port: 8080, service: 'http-proxy', version: 'Apache Tomcat', status: 'low' }
            ],
            vulns: [
                { port: 80,   cve: 'CVE-2017-15715', desc: 'Apache mod_negotiation RCE', severity: 'high' },
                { port: 3306, cve: 'CVE-2016-6662',  desc: 'MySQL root RCE',             severity: 'high' }
            ]
        },
        '10.0.2.15': {
            services: [
                { port: 22,   service: 'ssh',          version: 'OpenSSH 6.7',    status: 'medium' },
                { port: 53,   service: 'domain',       version: 'dnsmasq 2.76',   status: 'low' },
                { port: 111,  service: 'rpcbind',      version: 'rpcbind 2-4',    status: 'medium' },
                { port: 445,  service: 'microsoft-ds', version: 'Samba smbd 4.1', status: 'high' }
            ],
            vulns: [
                { port: 445, cve: 'CVE-2017-7494',  desc: 'Samba remote code exec', severity: 'high' },
                { port: 22,  cve: 'CVE-2016-6210',  desc: 'SSH user enumeration',   severity: 'medium' },
                { port: 53,  cve: 'CVE-2017-14491', desc: 'dnsmasq heap overflow',  severity: 'high' }
            ]
        }
    };

    /* ---------------- Pools for unknown-host generation ---------------- */
    var SERVICE_POOL = [
        { port: 21,   service: 'ftp',          version: 'ProFTPD 1.3.5e', status: 'high' },
        { port: 22,   service: 'ssh',          version: 'OpenSSH 7.9',    status: 'low' },
        { port: 23,   service: 'telnet',       version: 'Linux telnetd',  status: 'critical' },
        { port: 25,   service: 'smtp',         version: 'Postfix 3.4.13', status: 'low' },
        { port: 53,   service: 'domain',       version: 'dnsmasq 2.80',   status: 'medium' },
        { port: 80,   service: 'http',         version: 'nginx 1.18.0',   status: 'medium' },
        { port: 443,  service: 'https',        version: 'nginx 1.18.0',   status: 'low' },
        { port: 445,  service: 'microsoft-ds', version: 'Samba smbd 4.9', status: 'high' },
        { port: 3306, service: 'mysql',        version: 'MySQL 5.7.30',   status: 'medium' },
        { port: 5432, service: 'postgresql',   version: 'PostgreSQL 12.3', status: 'low' }
    ];

    var VULN_POOL = [
        { cve: 'CVE-2017-0144',  desc: 'EternalBlue SMB RCE',        severity: 'critical' },
        { cve: 'CVE-2014-6271',  desc: 'Shellshock RCE',             severity: 'critical' },
        { cve: 'CVE-2020-0796',  desc: 'SMBGhost RCE',               severity: 'critical' },
        { cve: 'CVE-2021-41773', desc: 'Apache path traversal',      severity: 'high' },
        { cve: 'CVE-2017-7494',  desc: 'Samba remote code exec',     severity: 'high' },
        { cve: 'CVE-2012-1823',  desc: 'PHP CGI argument injection', severity: 'high' },
        { cve: 'CVE-2019-0708',  desc: 'BlueKeep RDP RCE',           severity: 'critical' }
    ];

    var SEVERITIES = ['critical', 'high', 'medium', 'low'];

    /* ---------------- Element references ---------------- */
    var els = {
        input: document.getElementById('target-ip'),
        btn: document.getElementById('scan-btn'),
        statusPill: document.getElementById('header-status'),
        statusText: document.getElementById('status-text'),
        servicesTitle: document.getElementById('services-title'),
        servicesBody: document.getElementById('services-body'),
        vulnsBody: document.getElementById('vulns-body'),
        historyList: document.getElementById('history-list'),
        bars: {
            critical: document.getElementById('bar-critical'),
            high: document.getElementById('bar-high'),
            medium: document.getElementById('bar-medium'),
            low: document.getElementById('bar-low')
        },
        vals: {
            critical: document.getElementById('val-critical'),
            high: document.getElementById('val-high'),
            medium: document.getElementById('val-medium'),
            low: document.getElementById('val-low')
        }
    };

    /* ---------------- Helpers ---------------- */
    function getHost(ip) {
        var key = (ip || '').trim();
        return SCAN_DB[key] || randomHost(key);
    }

    function randomHost(ip) {
        var count = 3 + Math.floor(Math.random() * 4);
        var pool = SERVICE_POOL.slice().sort(function () { return Math.random() - 0.5; }).slice(0, count);
        var services = pool.map(function (s) {
            return { port: s.port, service: s.service, version: s.version, status: s.status };
        });

        var vulns = [];
        services.forEach(function (s) {
            if ((s.status === 'high' || s.status === 'critical') && Math.random() > 0.25) {
                var v = VULN_POOL[Math.floor(Math.random() * VULN_POOL.length)];
                vulns.push({ port: s.port, cve: v.cve, desc: v.desc, severity: v.severity });
            }
        });

        return {
            services: services.sort(function (a, b) { return a.port - b.port; }),
            vulns: vulns
        };
    }

    function flashRow(tr) {
        tr.classList.add('flash');
        window.setTimeout(function () { tr.classList.remove('flash'); }, 1150);
    }

    /* ---------------- Renderers ---------------- */
    function renderServices(host, ip) {
        els.servicesTitle.textContent = 'OPEN PORTS & SERVICES \u2014 ' + (ip || DEFAULT_IP);
        els.servicesBody.innerHTML = '';
        host.services.forEach(function (svc) {
            var tr = document.createElement('tr');
            tr.innerHTML =
                '<td class="text-accent">' + svc.port + '</td>' +
                '<td>' + svc.service + '</td>' +
                '<td class="text-bright">' + svc.version + '</td>' +
                '<td><span class="badge badge--' + svc.status + '">' + svc.status.toUpperCase() + '</span></td>';
            els.servicesBody.appendChild(tr);
            flashRow(tr);
        });
    }

    function renderVulns(host) {
        els.vulnsBody.innerHTML = '';
        if (!host.vulns || host.vulns.length === 0) {
            var empty = document.createElement('tr');
            empty.innerHTML = '<td colspan="4" class="text-muted">No known vulnerabilities detected for this host.</td>';
            els.vulnsBody.appendChild(empty);
            return;
        }
        host.vulns.forEach(function (v) {
            var tr = document.createElement('tr');
            tr.innerHTML =
                '<td class="text-accent">' + v.port + '</td>' +
                '<td class="text-bright">' + v.cve + '</td>' +
                '<td class="text-bright">' + v.desc + '</td>' +
                '<td><span class="badge badge--' + v.severity + '">' + v.severity.toUpperCase() + '</span></td>';
            els.vulnsBody.appendChild(tr);
            flashRow(tr);
        });
    }

    /* ---------------- Severity chart ---------------- */
    function countSeverities(host) {
        var counts = { critical: 0, high: 0, medium: 0, low: 0 };
        (host.vulns || []).forEach(function (v) {
            if (counts.hasOwnProperty(v.severity)) {
                counts[v.severity] += 1;
            }
        });
        return counts;
    }

    function updateSeverityChart(host) {
        var counts = countSeverities(host);
        var max = 1;
        SEVERITIES.forEach(function (s) {
            if (counts[s] > max) max = counts[s];
        });
        SEVERITIES.forEach(function (sev) {
            var pct = Math.round((counts[sev] / max) * 100);
            els.vals[sev].textContent = counts[sev];
            els.bars[sev].dataset.target = pct + '%';
        });
        animateBars();
    }

    function animateBars() {
        SEVERITIES.forEach(function (sev) {
            var bar = els.bars[sev];
            bar.style.transition = 'none';
            bar.style.width = '0%';
        });
        void els.bars.critical.offsetWidth; // force reflow so the transition restarts
        SEVERITIES.forEach(function (sev) {
            var bar = els.bars[sev];
            bar.style.transition = '';
            bar.style.width = bar.dataset.target || '0%';
        });
    }

    /* ---------------- Scan history ---------------- */
    function formatHistoryTime(date) {
        var now = new Date();
        var sameDay = date.getFullYear() === now.getFullYear() &&
            date.getMonth() === now.getMonth() &&
            date.getDate() === now.getDate();
        var hh = String(date.getHours()).padStart(2, '0');
        var mm = String(date.getMinutes()).padStart(2, '0');
        var prefix = sameDay
            ? 'Today'
            : date.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
        return prefix + ', ' + hh + ':' + mm;
    }

    function addHistoryEntry(ip) {
        var li = document.createElement('li');
        li.className = 'history-list__item';
        li.innerHTML =
            '<span class="history-list__ip text-bright">' + ip + '</span>' +
            '<span class="history-list__time">' + formatHistoryTime(new Date()) + '</span>';
        els.historyList.prepend(li);
        while (els.historyList.children.length > 8) {
            els.historyList.removeChild(els.historyList.lastChild);
        }
    }

    function seedHistory() {
        els.historyList.innerHTML = ''; // clear any static placeholder items
        var now = Date.now();
        var seeds = [
            { ip: '192.168.56.104', minsAgo: 2 },
            { ip: '127.0.0.1', minsAgo: 150 },
            { ip: '192.168.56.101', minsAgo: 1560 },
            { ip: '10.0.2.15', minsAgo: 1620 }
        ];
        seeds.forEach(function (seed) {
            var li = document.createElement('li');
            li.className = 'history-list__item';
            li.innerHTML =
                '<span class="history-list__ip text-bright">' + seed.ip + '</span>' +
                '<span class="history-list__time">' + formatHistoryTime(new Date(now - seed.minsAgo * 60000)) + '</span>';
            els.historyList.appendChild(li);
        });
    }

    /* ---------------- Scan state & workflow ---------------- */
    function setScanning(on) {
        els.btn.disabled = on;
        els.btn.textContent = on ? 'SCANNING\u2026' : 'RUN SCAN';
        els.statusText.textContent = on ? 'SCANNING\u2026' : 'ENGINE READY';
        els.statusPill.classList.toggle('header__status--scanning', on);
    }

    function runScan() {
        if (els.btn.disabled) return;

        var ip = (els.input.value || '').trim() || DEFAULT_IP;
        var host = getHost(ip);

        els.input.value = ip;
        setScanning(true);

        els.servicesBody.innerHTML = '';
        els.vulnsBody.innerHTML = '';

        window.setTimeout(function () {
            renderServices(host, ip);
            renderVulns(host);
            updateSeverityChart(host);
            addHistoryEntry(ip);
            setScanning(false);
        }, SCAN_DURATION);
    }

    /* ---------------- Init ---------------- */
    function init() {
        var ip = (els.input.value || '').trim() || DEFAULT_IP;
        var host = SCAN_DB[ip] || SCAN_DB[DEFAULT_IP];

        renderServices(host, ip);
        renderVulns(host);
        updateSeverityChart(host);
        seedHistory();

        els.btn.addEventListener('click', runScan);
        els.input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') runScan();
        });
    }

    document.addEventListener('DOMContentLoaded', init);
})();

