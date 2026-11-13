<?php
declare(strict_types=1);

namespace WpPluginAudit;

final class Finding
{
    public function __construct(public string $file, public int $line, public string $rule, public string $severity, public string $message, public string $fix, public string $snippet) {}
}

/** Static audit of WordPress plugin PHP files for common vulnerability patterns. Standard library only. */
final class Audit
{
    private const RULES = [
        'WP001' => ['high', 'SQL built from request data without $wpdb->prepare()', 'Use $wpdb->prepare() with placeholders for every dynamic value.'],
        'WP002' => ['high', 'Request data echoed without escaping (XSS)', 'Escape on output: esc_html(), esc_attr(), esc_url() or wp_kses_post() depending on context.'],
        'WP003' => ['critical', 'Code execution function used', 'Remove eval/assert and shell functions, or hard-code and validate every argument.'],
        'WP004' => ['high', 'unserialize() on request data (object injection)', 'Use json_decode() for data from users, or unserialize() with allowed_classes => false.'],
        'WP005' => ['high', 'AJAX or REST handler without a capability or nonce check', 'Call current_user_can() and check_ajax_referer() / wp_verify_nonce(), and set a permission_callback on REST routes.'],
        'WP006' => ['high', 'Unauthenticated AJAX handler (wp_ajax_nopriv) that changes data', 'Require authentication, or validate a nonce and strictly limit what the endpoint does.'],
        'WP007' => ['medium', 'File include or file operation from request data (path traversal)', 'Map user input to a fixed allow-list of files; never concatenate it into a path.'],
        'WP008' => ['medium', 'REST route with __return_true permission callback', 'Return a real capability check, or document why the route is public and read-only.'],
        'WP009' => ['medium', 'File upload handled without type validation', 'Use wp_handle_upload() with a mime allow-list and never trust the client file name.'],
        'WP010' => ['low', 'Direct access not blocked', 'Start every PHP file with: if ( ! defined( \'ABSPATH\' ) ) { exit; }'],
    ];
    private const SEV = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
    private const REQ = '\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b';

    /** @return Finding[] */
    public static function scanSource(string $file, string $src): array
    {
        $out = [];
        $lines = preg_split('/\R/', $src) ?: [];
        $add = function (string $rule, int $i) use (&$out, $file, $lines): void {
            [$sev, $msg, $fix] = self::RULES[$rule];
            $out[] = new Finding($file, $i + 1, $rule, $sev, $msg, $fix, trim(substr($lines[$i], 0, 140)));
        };
        // light taint tracking: variables assigned straight from request data without a sanitiser
        $tainted = [];
        foreach ($lines as $l) {
            if (preg_match('/\$(\w+)\s*=\s*[^;]*' . self::REQ . '/', $l, $m) && !preg_match('/absint|intval|sanitize_|esc_|wp_unslash\s*\(\s*sanitize|\(int\)|\(bool\)/', $l)) {
                $tainted[$m[1]] = true;
            }
        }
        $req = $tainted ? '(?:' . self::REQ . '|\$(?:' . implode('|', array_map('preg_quote', array_keys($tainted))) . ')\b)' : self::REQ;
        // handlers: collect function names registered for AJAX and check their bodies for guards
        $handlers = [];
        foreach ($lines as $i => $l) {
            if (preg_match('/add_action\(\s*[\'"]wp_ajax_(nopriv_)?[\w-]+[\'"]\s*,\s*[\'"](\w+)[\'"]/', $l, $m)) {
                $handlers[$m[2]] = [$i, $m[1] === 'nopriv_'];
            }
        }
        $isAjaxBody = [];
        foreach ($handlers as $fn => [$ri, $nopriv]) {
            [$start, $end] = self::bodyRange($lines, $fn);
            if ($start === null) {
                continue;
            }
            $body = implode("\n", array_slice($lines, $start, $end - $start + 1));
            for ($k = $start; $k <= $end; $k++) {
                $isAjaxBody[$k] = true;
            }
            $guarded = (bool) preg_match('/current_user_can\(|check_ajax_referer\(|wp_verify_nonce\(|check_admin_referer\(/', $body);
            if (!$guarded) {
                $add('WP005', $start);
            }
            if ($nopriv && preg_match('/update_option|wp_insert_|wp_update_|wp_delete_|->(insert|update|delete)\(|file_put_contents|unlink\(/', $body)) {
                $add('WP006', $ri);
            }
        }
        foreach ($lines as $i => $l) {
            $code = preg_replace('~^\s*(//|\*|/\*|#).*$~', '', $l) ?? $l;
            if (trim($code) === '') {
                continue;
            }
            if (preg_match('/\$wpdb->(query|get_results|get_row|get_var|get_col)\(/', $code) && preg_match("/(\.\s*|\"[^\"]*)$req/", $code) && !str_contains($code, 'prepare(')) {
                $add('WP001', $i);
            }
            if (preg_match("/\b(echo|print)\b[^;]*$req/", $code) && !preg_match('/esc_(html|attr|url|js|textarea)|wp_kses|intval|absint|sanitize_/', $code)) {
                $add('WP002', $i);
            }
            if (preg_match('/<\?=\s*[^?]*' . $req . '/', $code) && !preg_match('/esc_|wp_kses|intval|absint/', $code)) {
                $add('WP002', $i);
            }
            if (preg_match('/\b(eval|assert|shell_exec|passthru|system|popen|proc_open)\s*\(/', $code) || preg_match('/\bexec\s*\(/', $code)) {
                $add('WP003', $i);
            }
            if (preg_match("/\bunserialize\s*\([^)]*$req/", $code) && !str_contains($code, 'allowed_classes')) {
                $add('WP004', $i);
            }
            if (preg_match("/\b(include|require)(_once)?\b[^;]*$req/", $code) || preg_match("/\b(file_get_contents|fopen|readfile|unlink|file_put_contents)\s*\([^)]*$req/", $code)) {
                $add('WP007', $i);
            }
            if (preg_match("/['\"]permission_callback['\"]\s*=>\s*['\"]__return_true['\"]/", $code)) {
                $add('WP008', $i);
            }
            if (preg_match('/move_uploaded_file\s*\(/', $code) && !preg_match('/wp_check_filetype|mime/', $src)) {
                $add('WP009', $i);
            }
        }
        if (preg_match('/^\s*(add_action|add_filter|function|class)\b/m', $src) && !preg_match('/defined\(\s*[\'"]ABSPATH[\'"]\s*\)|namespace\s/', $src)) {
            $out[] = new Finding($file, 1, 'WP010', 'low', self::RULES['WP010'][1], self::RULES['WP010'][2], trim($lines[0] ?? ''));
        }
        return $out;
    }

    /** @return array{0:?int,1:?int} line range of function $name's body */
    private static function bodyRange(array $lines, string $name): array
    {
        foreach ($lines as $i => $l) {
            if (preg_match('/function\s+' . preg_quote($name, '/') . '\s*\(/', $l)) {
                $depth = 0;
                $seen = false;
                for ($k = $i; $k < count($lines); $k++) {
                    $depth += substr_count($lines[$k], '{') - substr_count($lines[$k], '}');
                    $seen = $seen || str_contains($lines[$k], '{');
                    if ($seen && $depth <= 0) {
                        return [$i, $k];
                    }
                }
                return [$i, count($lines) - 1];
            }
        }
        return [null, null];
    }

    /** @return Finding[] */
    public static function scanDir(string $dir): array
    {
        if (!is_dir($dir)) {
            throw new \InvalidArgumentException("$dir is not a directory");
        }
        $files = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile() && preg_match('/\.php$/i', $f->getFilename()) && !str_contains($f->getPathname(), '/vendor/') && $f->getSize() < 2_000_000) {
                $files[] = $f->getPathname();
            }
        }
        sort($files);
        $out = [];
        foreach ($files as $p) {
            array_push($out, ...self::scanSource(ltrim(substr($p, strlen($dir)), '/'), (string) file_get_contents($p)));
        }
        usort($out, fn (Finding $a, Finding $b) => [self::SEV[$a->severity], $a->file, $a->line] <=> [self::SEV[$b->severity], $b->file, $b->line]);
        return $out;
    }

    public static function severityRank(string $s): int { return self::SEV[$s] ?? 9; }

    /** @param Finding[] $fs */
    public static function text(array $fs): string
    {
        if (!$fs) {
            return "No findings.\n";
        }
        $o = '';
        foreach ($fs as $f) {
            $o .= sprintf("%-8s %s %s:%d\n         %s\n         > %s\n         Fix: %s\n", strtoupper($f->severity), $f->rule, $f->file, $f->line, $f->message, $f->snippet, $f->fix);
        }
        return $o;
    }

    /** @param Finding[] $fs */
    public static function json(array $fs): string
    {
        return json_encode(array_map(fn (Finding $f) => get_object_vars($f), $fs), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /** @param Finding[] $fs */
    public static function page(array $fs): string
    {
        $h = fn (string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
        $rows = '';
        foreach ($fs as $f) {
            $rows .= "<tr><td class=\"{$f->severity}\">{$f->severity}</td><td>{$f->rule}</td><td>{$h($f->file)}:{$f->line}</td><td>{$h($f->message)}<br><code>{$h($f->snippet)}</code><br><span class=\"sub\">Fix: {$h($f->fix)}</span></td></tr>";
        }
        $n = count($fs);
        return <<<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>wp-plugin-audit</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}td.critical{color:#f85149;font-weight:700}td.high{color:#f0883e;font-weight:700}td.medium{color:#e3b341;font-weight:700}td.low{color:#8b98a8}code{background:#161d26;padding:1px 5px;border-radius:4px;word-break:break-all}</style></head><body><h1>wp-plugin-audit</h1><p class="sub">Static security audit for WordPress plugins. PHP, no dependencies. Report on the synthetic plugins in examples/.</p><p><b>$n</b> findings.</p><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>What and how to fix</th></tr>$rows</table></body></html>

HTML;
    }
}
