<?php
/**
 * Plugin Name: Webgeek DNS, SSL & Email Security Scanner
 * Plugin URI:  https://webgeek.com.hr
 * Description: Lagani, zero-dependency WordPress alat za provjeru DNS zapisa, SSL certifikata, HTTP sigurnosnih zaglavlja te SPF, DKIM i DMARC zaštite putem shortcodea [wg_dns_scanner].
 * Version:     1.0.0
 * Author:      Webgeek
 * Author URI:  https://webgeek.com.hr
 * License:     MIT
 * Text Domain: wg-dns-scanner
 */

if (!defined('ABSPATH')) {
    exit;
}

class WG_DNS_Scanner {

    const VERSION = '1.0.0';
    const RATE_LIMIT_MAX = 15;       // Maksimalno skeniranja po IP adresi
    const RATE_LIMIT_WINDOW = 600;   // Unutar 10 minuta (600 sekundi)

    public function __construct() {
        add_shortcode('wg_dns_scanner', [$this, 'render_shortcode']);
        add_action('wp_enqueue_scripts', [$this, 'register_assets']);
        add_action('rest_api_init', [$this, 'register_rest_routes']);
    }

    /**
     * Registrira CSS i JS (učitavaju se isključivo kad je shortcode prisutan na stranici).
     */
    public function register_assets() {
        wp_register_style(
            'wg-dns-scanner-css',
            plugin_dir_url(__FILE__) . 'assets/wg-dns-scanner.css',
            [],
            self::VERSION
        );

        wp_register_script(
            'wg-dns-scanner-js',
            plugin_dir_url(__FILE__) . 'assets/wg-dns-scanner.js',
            [],
            self::VERSION,
            true
        );
    }

    /**
     * Prikazuje HTML sučelje alata putem [wg_dns_scanner].
     */
    public function render_shortcode($atts = []) {
        wp_enqueue_style('wg-dns-scanner-css');
        wp_enqueue_script('wg-dns-scanner-js');

        wp_localize_script('wg-dns-scanner-js', 'wgDnsConfig', [
            'endpoint' => esc_url_raw(rest_url('wg-dns/v1/scan')),
            'nonce'    => wp_create_nonce('wp_rest'),
        ]);

        ob_start();
        ?>
        <div class="wg-dns-wrap" id="wg-dns-app">
            <div class="wg-dns-card wg-dns-form-card">
                <form id="wg-dns-form" class="wg-dns-form" novalidate>
                    <label for="wg-dns-domain" class="wg-dns-label">Unesite naziv domene za provjeru:</label>
                    <div class="wg-dns-input-group">
                        <input
                            type="text"
                            id="wg-dns-domain"
                            name="domain"
                            class="wg-dns-input"
                            placeholder="npr. webgeek.com.hr"
                            autocomplete="off"
                            spellcheck="false"
                            required
                        />
                        <button type="submit" id="wg-dns-submit" class="wg-dns-btn">
                            <span class="wg-dns-btn-text">Skeniraj domenu</span>
                            <span class="wg-dns-spinner" aria-hidden="true"></span>
                        </button>
                    </div>
                    <p class="wg-dns-hint">Provjerava A, AAAA, MX, NS, SPF, DKIM, DMARC, SSL certifikat i HTTP sigurnosna zaglavlja u stvarnom vremenu.</p>
                </form>
                <div id="wg-dns-error" class="wg-dns-alert wg-dns-alert-error" hidden></div>
            </div>

            <div id="wg-dns-results" class="wg-dns-results" hidden></div>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Registrira REST API rutu: POST /wp-json/wg-dns/v1/scan
     */
    public function register_rest_routes() {
        register_rest_route('wg-dns/v1', '/scan', [
            'methods'             => 'POST',
            'callback'            => [$this, 'handle_scan_request'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * Dohvaća IP adresu klijenta (uz podršku za Cloudflare).
     */
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        } else {
            $ip = '0.0.0.0';
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    /**
     * Rate limiting putem WordPress Transienta.
     */
    private function check_rate_limit() {
        $ip = $this->get_client_ip();
        $key = 'wg_dns_rl_' . md5($ip);
        $count = (int) get_transient($key);

        if ($count >= self::RATE_LIMIT_MAX) {
            return false;
        }

        set_transient($key, $count + 1, self::RATE_LIMIT_WINDOW);
        return true;
    }

    /**
     * Čisti i validira unesenu domenu (sprječava SSRF i lokalne IP adrese).
     */
    private function sanitize_domain($raw) {
        $domain = strtolower(trim((string) $raw));
        $domain = preg_replace('#^https?://#', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        $domain = preg_replace('#:\d+$#', '', $domain);
        $domain = preg_replace('/^www\./', '', $domain);
        $domain = rtrim($domain, '.');

        if (function_exists('idn_to_ascii') && preg_match('/[^\x20-\x7e]/', $domain)) {
            $ascii = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii) {
                $domain = $ascii;
            }
        }

        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain)) {
            return new WP_Error('invalid_domain', 'Unesite ispravan naziv domene (npr. webgeek.com.hr).', ['status' => 400]);
        }

        $blocked = ['localhost', 'localdomain', 'internal', 'home.arpa'];
        foreach ($blocked as $b) {
            if ($domain === $b || str_ends_with($domain, '.' . $b)) {
                return new WP_Error('blocked_domain', 'Lokalne i interne domene nisu dopuštene.', ['status' => 400]);
            }
        }

        return $domain;
    }

    /**
     * Provjerava je li IP adresa javna (SSRF zaštita).
     */
    private function is_public_ip($ip) {
        return (bool) filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Glavni obrađivač REST API zahtjeva.
     */
    public function handle_scan_request(WP_REST_Request $request) {
        if (!$this->check_rate_limit()) {
            return new WP_Error(
                'rate_limited',
                'Dosegli ste ograničenje broja provjera. Pokušajte ponovno za nekoliko minuta.',
                ['status' => 429]
            );
        }

        $raw_domain = $request->get_param('domain');
        $domain = $this->sanitize_domain($raw_domain);
        if (is_wp_error($domain)) {
            return $domain;
        }

        // Kratki cache rezultata (60 sekundi) za zaštitu servera kod ponovljenih upita
        $cache_key = 'wg_dns_res_' . md5($domain);
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return rest_ensure_response($cached);
        }

        $dns     = $this->scan_dns($domain);
        $email   = $this->scan_email_security($domain, $dns['txt']);
        $ssl     = $this->scan_ssl($domain, $dns['a']);
        $headers = $this->scan_http_headers($domain, $dns['a']);
        $score   = $this->calculate_score($dns, $email, $ssl, $headers);

        $result = [
            'domain'      => $domain,
            'scanned_at'  => current_time('d.m.Y. H:i:s'),
            'score'       => $score['total'],
            'grade'       => $score['grade'],
            'summary'     => $score['recommendations'],
            'dns'         => $dns,
            'email'       => $email,
            'ssl'         => $ssl,
            'headers'     => $headers,
        ];

        set_transient($cache_key, $result, 60);

        return rest_ensure_response($result);
    }

    /**
     * 1. DNS zapisi (A, AAAA, MX, NS, TXT)
     */
    private function scan_dns($domain) {
        $a_raw    = @dns_get_record($domain, DNS_A) ?: [];
        $aaaa_raw = @dns_get_record($domain, DNS_AAAA) ?: [];
        $mx_raw   = @dns_get_record($domain, DNS_MX) ?: [];
        $ns_raw   = @dns_get_record($domain, DNS_NS) ?: [];
        $txt_raw  = @dns_get_record($domain, DNS_TXT) ?: [];

        $a = array_values(array_unique(array_filter(array_column($a_raw, 'ip'))));
        $aaaa = array_values(array_unique(array_filter(array_column($aaaa_raw, 'ipv6'))));

        usort($mx_raw, fn($x, $y) => ($x['pri'] ?? 0) <=> ($y['pri'] ?? 0));
        $mx = array_map(fn($r) => [
            'priority' => (int) ($r['pri'] ?? 0),
            'target'   => (string) ($r['target'] ?? ''),
        ], $mx_raw);

        $ns = array_values(array_unique(array_filter(array_column($ns_raw, 'target'))));
        sort($ns);

        $txt = array_values(array_filter(array_column($txt_raw, 'txt')));

        return [
            'a'    => $a,
            'aaaa' => $aaaa,
            'mx'   => $mx,
            'ns'   => $ns,
            'txt'  => $txt,
        ];
    }

    /**
     * 2. Email sigurnost (SPF, DMARC, DKIM)
     */
    private function scan_email_security($domain, $txt_records) {
        // SPF
        $spf_records = array_values(array_filter($txt_records, fn($t) => stripos($t, 'v=spf1') === 0));
        $spf_status = 'missing';
        $spf_note = 'SPF zapis nije pronađen. Vaši e-mailovi mogu završiti u Spam mapi.';
        $spf_value = '';

        if (count($spf_records) > 1) {
            $spf_status = 'warning';
            $spf_value = implode(' | ', $spf_records);
            $spf_note = 'Pronađeno je više SPF zapisa. Domena smije imati samo jedan v=spf1 zapis.';
        } elseif (count($spf_records) === 1) {
            $spf_value = $spf_records[0];
            if (str_contains($spf_value, '-all')) {
                $spf_status = 'ok';
                $spf_note = 'SPF zapis je pravilno postavljen sa strogim pravilom (-all).';
            } elseif (str_contains($spf_value, '~all')) {
                $spf_status = 'ok';
                $spf_note = 'SPF zapis je aktivan (SoftFail ~all).';
            } else {
                $spf_status = 'warning';
                $spf_note = 'SPF zapis postoji, ali nema jasno završno pravilo (-all ili ~all).';
            }
        }

        // DMARC
        $dmarc_raw = @dns_get_record('_dmarc.' . $domain, DNS_TXT) ?: [];
        $dmarc_txts = array_values(array_filter(
            array_column($dmarc_raw, 'txt'),
            fn($t) => stripos($t, 'v=DMARC1') === 0
        ));
        $dmarc_status = 'missing';
        $dmarc_value = '';
        $dmarc_policy = 'none';
        $dmarc_note = 'DMARC zapis nije pronađen. Dodajte _dmarc TXT zapis za zaštitu od lažiranja e-mailova.';

        if (!empty($dmarc_txts)) {
            $dmarc_value = $dmarc_txts[0];
            if (preg_match('/\bp=(reject|quarantine|none)\b/i', $dmarc_value, $m)) {
                $dmarc_policy = strtolower($m[1]);
            }
            if ($dmarc_policy === 'reject' || $dmarc_policy === 'quarantine') {
                $dmarc_status = 'ok';
                $dmarc_note = "DMARC je aktivan s politikom p={$dmarc_policy} (visoka zaštita).";
            } else {
                $dmarc_status = 'warning';
                $dmarc_note = 'DMARC zapis postoji, ali je u načinu praćenja (p=none). Razmislite o p=quarantine ili p=reject.';
            }
        }

        // DKIM (provjera najčešćih selektora)
        $selectors = ['default', 'google', 'selector1', 'selector2', 'mail', 'dkim', 'k1', 's1'];
        $dkim_found = [];
        foreach ($selectors as $sel) {
            $rec = @dns_get_record("{$sel}._domainkey.{$domain}", DNS_TXT) ?: [];
            foreach ($rec as $r) {
                if (!empty($r['txt']) && stripos($r['txt'], 'v=DKIM1') !== false) {
                    $dkim_found[] = $sel;
                    break;
                }
            }
        }

        $dkim_status = !empty($dkim_found) ? 'ok' : 'info';
        $dkim_note = !empty($dkim_found)
            ? 'Pronađen DKIM zapis za selektor(e): ' . implode(', ', $dkim_found) . '.'
            : 'Nije pronađen DKIM na standardnim selektorima (moguće je da koristite prilagođeni naziv selektora).';

        return [
            'spf'   => ['status' => $spf_status, 'value' => $spf_value, 'note' => $spf_note],
            'dmarc' => ['status' => $dmarc_status, 'value' => $dmarc_value, 'policy' => $dmarc_policy, 'note' => $dmarc_note],
            'dkim'  => ['status' => $dkim_status, 'selectors' => $dkim_found, 'note' => $dkim_note],
        ];
    }

    /**
     * 3. SSL/TLS certifikat
     */
    private function scan_ssl($domain, $a_records) {
        if (empty($a_records) || !$this->is_public_ip($a_records[0])) {
            return [
                'status' => 'error',
                'note'   => 'Nije moguće provjeriti SSL jer domena nema javnu IPv4 adresu.',
            ];
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'SNI_enabled'       => true,
                'peer_name'         => $domain,
            ],
        ]);

        $client = @stream_socket_client(
            "ssl://{$domain}:443",
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$client) {
            return [
                'status' => 'error',
                'note'   => 'HTTPS (port 443) nije dostupan ili SSL certifikat nije instaliran.',
            ];
        }

        $params = stream_context_get_params($client);
        fclose($client);

        if (empty($params['options']['ssl']['peer_certificate'])) {
            return [
                'status' => 'error',
                'note'   => 'Poslužitelj nije vratio valjani SSL certifikat.',
            ];
        }

        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        $valid_to = (int) ($cert['validTo_time_t'] ?? 0);
        $valid_from = (int) ($cert['validFrom_time_t'] ?? 0);
        $days_left = (int) floor(($valid_to - time()) / 86400);
        $issuer = $cert['issuer']['O'] ?? ($cert['issuer']['CN'] ?? 'Nepoznato');

        if ($days_left < 0) {
            $status = 'error';
            $note = 'SSL certifikat je istekao!';
        } elseif ($days_left <= 14) {
            $status = 'warning';
            $note = "SSL certifikat uskoro istječe (za {$days_left} dana).";
        } else {
            $status = 'ok';
            $note = "SSL certifikat je valjan (vrijedi još {$days_left} dana).";
        }

        return [
            'status'     => $status,
            'issuer'     => $issuer,
            'valid_from' => $valid_from ? gmdate('d.m.Y.', $valid_from) : '-',
            'valid_to'   => $valid_to ? gmdate('d.m.Y.', $valid_to) : '-',
            'days_left'  => $days_left,
            'note'       => $note,
        ];
    }

    /**
     * 4. HTTP sigurnosna zaglavlja
     */
    private function scan_http_headers($domain, $a_records) {
        if (empty($a_records) || !$this->is_public_ip($a_records[0])) {
            return ['status' => 'error', 'items' => []];
        }

        $response = wp_remote_head("https://{$domain}/", [
            'timeout'     => 5,
            'redirection' => 3,
            'sslverify'   => false,
            'user-agent'  => 'Webgeek-DNS-Scanner/1.0 (+https://webgeek.com.hr)',
        ]);

        if (is_wp_error($response)) {
            return ['status' => 'error', 'items' => []];
        }

        $raw_headers = wp_remote_retrieve_headers($response);
        $headers_map = is_object($raw_headers) ? $raw_headers->getAll() : (array) $raw_headers;

        $check_list = [
            'strict-transport-security' => 'HSTS (Strict-Transport-Security)',
            'x-frame-options'           => 'X-Frame-Options',
            'x-content-type-options'    => 'X-Content-Type-Options',
            'content-security-policy'   => 'Content-Security-Policy (CSP)',
            'referrer-policy'           => 'Referrer-Policy',
        ];

        $items = [];
        $present_count = 0;

        foreach ($check_list as $key => $label) {
            $val = $headers_map[$key] ?? '';
            if (is_array($val)) {
                $val = implode(', ', $val);
            }
            $present = !empty($val);
            if ($present) {
                $present_count++;
            }
            $items[] = [
                'name'    => $label,
                'present' => $present,
                'value'   => $present ? mb_substr((string) $val, 0, 120) : 'Nedostaje',
            ];
        }

        return [
            'status'        => $present_count >= 3 ? 'ok' : ($present_count >= 1 ? 'warning' : 'missing'),
            'present_count' => $present_count,
            'total_count'   => count($check_list),
            'items'         => $items,
        ];
    }

    /**
     * 5. Ukupna sigurnosna ocjena (0-100) i preporuke
     */
    private function calculate_score($dns, $email, $ssl, $headers) {
        $score = 0;
        $recs = [];

        // DNS osnova (20 bodova)
        if (!empty($dns['a'])) {
            $score += 10;
        } else {
            $recs[] = 'Domena nema postavljen A zapis (IPv4).';
        }
        if (count($dns['ns']) >= 2) {
            $score += 10;
        } else {
            $recs[] = 'Preporučuju se barem dva autoritativna NS poslužitelja radi pouzdanosti.';
        }

        // SSL (25 bodova)
        if (($ssl['status'] ?? '') === 'ok') {
            $score += 25;
        } elseif (($ssl['status'] ?? '') === 'warning') {
            $score += 15;
            $recs[] = 'Obnovite SSL certifikat uskoro kako stranica ne bi prikazivala sigurnosno upozorenje.';
        } else {
            $recs[] = 'Instalirajte valjani SSL/TLS certifikat (npr. Let’s Encrypt) za HTTPS enkripciju.';
        }

        // Email sigurnost (35 bodova)
        if ($email['spf']['status'] === 'ok') {
            $score += 15;
        } elseif ($email['spf']['status'] === 'warning') {
            $score += 8;
            $recs[] = $email['spf']['note'];
        } else {
            $recs[] = 'Dodajte SPF TXT zapis u DNS zonu kako biste spriječili odlazak e-mailova u Spam.';
        }

        if ($email['dmarc']['status'] === 'ok') {
            $score += 15;
        } elseif ($email['dmarc']['status'] === 'warning') {
            $score += 8;
            $recs[] = 'Pojačajte DMARC politiku s p=none na p=quarantine ili p=reject.';
        } else {
            $recs[] = 'Postavite _dmarc TXT zapis za zaštitu ugleda domene od lažiranja pošte.';
        }

        if ($email['dkim']['status'] === 'ok') {
            $score += 5;
        }

        // HTTP Security Headers (20 bodova)
        $h_count = (int) ($headers['present_count'] ?? 0);
        $score += min(20, $h_count * 4);
        if ($h_count < 3) {
            $recs[] = 'Dodajte osnovna HTTP sigurnosna zaglavlja (HSTS, X-Frame-Options, X-Content-Type-Options).';
        }

        if ($score >= 85) {
            $grade = 'A';
        } elseif ($score >= 70) {
            $grade = 'B';
        } elseif ($score >= 50) {
            $grade = 'C';
        } else {
            $grade = 'D';
        }

        if (empty($recs)) {
            $recs[] = 'Odlično! Vaša domena ima vrlo dobro postavljene temeljne DNS, SSL i sigurnosne parametre.';
        }

        return [
            'total'           => min(100, $score),
            'grade'           => $grade,
            'recommendations' => $recs,
        ];
    }
}

new WG_DNS_Scanner();
