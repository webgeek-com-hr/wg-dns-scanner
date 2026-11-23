(function () {
    'use strict';

    const form = document.getElementById('wg-dns-form');
    const input = document.getElementById('wg-dns-domain');
    const submitBtn = document.getElementById('wg-dns-submit');
    const errorBox = document.getElementById('wg-dns-error');
    const resultsBox = document.getElementById('wg-dns-results');

    if (!form || typeof wgDnsConfig === 'undefined') {
        return;
    }

    function esc(str) {
        return String(str ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function statusLabel(status) {
        const map = {
            ok: 'U redu',
            warning: 'Upozorenje',
            missing: 'Nedostaje',
            error: 'Greška',
            info: 'Info',
        };
        return map[status] || status;
    }

    function setLoading(loading) {
        submitBtn.disabled = loading;
        submitBtn.classList.toggle('is-loading', loading);
        submitBtn.querySelector('.wg-dns-btn-text').textContent = loading
            ? 'Skeniranje...'
            : 'Skeniraj domenu';
    }

    function showError(msg) {
        errorBox.textContent = msg;
        errorBox.hidden = false;
    }

    function clearError() {
        errorBox.textContent = '';
        errorBox.hidden = true;
    }

    function renderResults(data) {
        const recsHtml = (data.summary || [])
            .map((r) => `<li>${esc(r)}</li>`)
            .join('');

        const aList = (data.dns.a || []).length
            ? data.dns.a.map((ip) => `<code class="wg-dns-code">${esc(ip)}</code>`).join('')
            : '<p class="wg-dns-note">Nije pronađen A zapis.</p>';

        const aaaaList = (data.dns.aaaa || []).length
            ? data.dns.aaaa.map((ip) => `<code class="wg-dns-code">${esc(ip)}</code>`).join('')
            : '<p class="wg-dns-note">IPv6 (AAAA) nije postavljen.</p>';

        const mxList = (data.dns.mx || []).length
            ? data.dns.mx.map((m) => `<code class="wg-dns-code">[${esc(m.priority)}] ${esc(m.target)}</code>`).join('')
            : '<p class="wg-dns-note">Nije pronađen MX zapis.</p>';

        const nsList = (data.dns.ns || []).length
            ? data.dns.ns.map((n) => `<code class="wg-dns-code">${esc(n)}</code>`).join('')
            : '<p class="wg-dns-note">Nije pronađen NS zapis.</p>';

        const headersHtml = (data.headers.items || [])
            .map((h) => `
                <div class="wg-dns-item">
                    <div class="wg-dns-item-head">
                        <span class="wg-dns-item-title">${esc(h.name)}</span>
                        <span class="wg-dns-pill ${h.present ? 'wg-pill-ok' : 'wg-pill-missing'}">${h.present ? 'Aktivno' : 'Nedostaje'}</span>
                    </div>
                    <p class="wg-dns-note">${esc(h.value)}</p>
                </div>
            `)
            .join('');

        resultsBox.innerHTML = `
            <div class="wg-dns-card">
                <div class="wg-dns-score-header">
                    <div class="wg-dns-score-meta">
                        <h3>Rezultat za: ${esc(data.domain)}</h3>
                        <p>Skenirano: ${esc(data.scanned_at)}</p>
                    </div>
                    <div class="wg-dns-score-badge">
                        <div class="wg-dns-grade wg-grade-${esc(data.grade)}">${esc(data.grade)}</div>
                        <div>
                            <div class="wg-dns-score-num">${esc(data.score)} / 100</div>
                            <div class="wg-dns-note" style="margin:0;">Sigurnosna ocjena</div>
                        </div>
                    </div>
                </div>
                <div style="margin-top:16px;">
                    <strong>Preporuke:</strong>
                    <ul class="wg-dns-list" style="margin-top:8px;">${recsHtml}</ul>
                </div>
            </div>

            <div class="wg-dns-card">
                <h4 class="wg-dns-section-title">Email sigurnost (SPF, DMARC, DKIM)</h4>
                <div class="wg-dns-grid">
                    <div class="wg-dns-item">
                        <div class="wg-dns-item-head">
                            <span class="wg-dns-item-title">SPF zapis</span>
                            <span class="wg-dns-pill wg-pill-${esc(data.email.spf.status)}">${esc(statusLabel(data.email.spf.status))}</span>
                        </div>
                        ${data.email.spf.value ? `<code class="wg-dns-code">${esc(data.email.spf.value)}</code>` : ''}
                        <p class="wg-dns-note">${esc(data.email.spf.note)}</p>
                    </div>
                    <div class="wg-dns-item">
                        <div class="wg-dns-item-head">
                            <span class="wg-dns-item-title">DMARC zapis</span>
                            <span class="wg-dns-pill wg-pill-${esc(data.email.dmarc.status)}">${esc(statusLabel(data.email.dmarc.status))}</span>
                        </div>
                        ${data.email.dmarc.value ? `<code class="wg-dns-code">${esc(data.email.dmarc.value)}</code>` : ''}
                        <p class="wg-dns-note">${esc(data.email.dmarc.note)}</p>
                    </div>
                    <div class="wg-dns-item">
                        <div class="wg-dns-item-head">
                            <span class="wg-dns-item-title">DKIM zapis</span>
                            <span class="wg-dns-pill wg-pill-${esc(data.email.dkim.status)}">${esc(statusLabel(data.email.dkim.status))}</span>
                        </div>
                        <p class="wg-dns-note">${esc(data.email.dkim.note)}</p>
                    </div>
                </div>
            </div>

            <div class="wg-dns-card">
                <h4 class="wg-dns-section-title">SSL/TLS certifikat</h4>
                <div class="wg-dns-item">
                    <div class="wg-dns-item-head">
                        <span class="wg-dns-item-title">HTTPS Status</span>
                        <span class="wg-dns-pill wg-pill-${esc(data.ssl.status)}">${esc(statusLabel(data.ssl.status))}</span>
                    </div>
                    <p class="wg-dns-note">${esc(data.ssl.note)}</p>
                    ${data.ssl.issuer ? `
                        <p class="wg-dns-note">
                            <strong>Izdavatelj:</strong> ${esc(data.ssl.issuer)} |
                            <strong>Vrijedi od:</strong> ${esc(data.ssl.valid_from)} |
                            <strong>Istječe:</strong> ${esc(data.ssl.valid_to)}
                        </p>
                    ` : ''}
                </div>
            </div>

            <div class="wg-dns-card">
                <h4 class="wg-dns-section-title">DNS zapisi (A, AAAA, MX, NS)</h4>
                <div class="wg-dns-grid">
                    <div class="wg-dns-item"><div class="wg-dns-item-title">A (IPv4)</div>${aList}</div>
                    <div class="wg-dns-item"><div class="wg-dns-item-title">AAAA (IPv6)</div>${aaaaList}</div>
                    <div class="wg-dns-item"><div class="wg-dns-item-title">MX (Mail serveri)</div>${mxList}</div>
                    <div class="wg-dns-item"><div class="wg-dns-item-title">NS (Name serveri)</div>${nsList}</div>
                </div>
            </div>

            <div class="wg-dns-card">
                <h4 class="wg-dns-section-title">HTTP sigurnosna zaglavlja</h4>
                <div class="wg-dns-grid">${headersHtml || '<p class="wg-dns-note">Nije moguće dohvatiti HTTP zaglavlja.</p>'}</div>
            </div>
        `;

        resultsBox.hidden = false;
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        clearError();

        const domain = input.value.trim();
        if (!domain) {
            showError('Molimo unesite naziv domene (npr. webgeek.com.hr).');
            return;
        }

        setLoading(true);
        resultsBox.hidden = true;

        try {
            const response = await fetch(wgDnsConfig.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': wgDnsConfig.nonce,
                },
                body: JSON.stringify({ domain: domain }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Došlo je do greške prilikom skeniranja domene.');
            }

            renderResults(data);
        } catch (err) {
            showError(err.message || 'Neuspješna komunikacija sa serverom.');
        } finally {
            setLoading(false);
        }
    });
})();
