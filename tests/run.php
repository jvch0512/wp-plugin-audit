<?php
declare(strict_types=1);
require __DIR__ . '/../src/Audit.php';

use WpPluginAudit\Audit;

$fail = 0; $n = 0;
function check(string $name, bool $ok): void { global $fail, $n; $n++; if (!$ok) { $fail++; echo "FAIL: $name\n"; } }
function rules(string $code): array { return array_values(array_unique(array_map(fn ($f) => $f->rule, Audit::scanSource('t.php', "<?php\nif ( ! defined( 'ABSPATH' ) ) { exit; }\n" . $code)))); }

check('eval is critical', rules('eval($x);') === ['WP003']);
check('system call is flagged', in_array('WP003', rules('system("ls");'), true));
check('sql concatenation with request data', in_array('WP001', rules('$wpdb->query("DELETE FROM t WHERE id=" . $_GET["id"]);'), true));
check('prepared statement is safe', rules('$wpdb->query($wpdb->prepare("DELETE FROM t WHERE id=%d", $_GET["id"]));') === []);
check('taint flows through a variable', in_array('WP001', rules('$id = $_POST["id"]; $wpdb->get_results("SELECT * FROM t WHERE id = " . $id);'), true));
check('absint clears taint', rules('$id = absint($_POST["id"]); $wpdb->get_results("SELECT * FROM t WHERE id = " . $id);') === []);
check('unescaped echo is XSS', in_array('WP002', rules('echo $_GET["q"];'), true));
check('escaped echo is fine', rules('echo esc_html($_GET["q"]);') === []);
check('unserialize request data', in_array('WP004', rules('$d = unserialize($_COOKIE["s"]);'), true));
check('unserialize with allowed_classes is accepted', rules('$d = unserialize($_COOKIE["s"], ["allowed_classes" => false]);') === []);
check('include from request', in_array('WP007', rules('include $_GET["page"];'), true));
check('permission_callback __return_true', in_array('WP008', rules("register_rest_route('a/v1','/b',['permission_callback' => '__return_true']);"), true));
check('ajax handler without guards', in_array('WP005', rules("add_action('wp_ajax_x', 'h');\nfunction h() {\n  update_option('a', 1);\n}\n"), true));
check('ajax handler with nonce and capability is fine', !in_array('WP005', rules("add_action('wp_ajax_x', 'h');\nfunction h() {\n  check_ajax_referer('x');\n  current_user_can('manage_options');\n}\n"), true));
check('nopriv handler that writes', in_array('WP006', rules("add_action('wp_ajax_nopriv_x', 'h');\nfunction h() {\n  check_ajax_referer('x');\n  update_option('a', 1);\n}\n"), true));
check('commented code is ignored', rules('// eval($x);') === []);
check('missing ABSPATH guard', in_array('WP010', array_map(fn ($f) => $f->rule, Audit::scanSource('t.php', "<?php\nfunction a() {}\n")), true));
$fs = Audit::scanDir(__DIR__ . '/../examples');
check('sample: vulnerable plugin has a critical finding', $fs[0]->severity === 'critical');
check('sample: safe plugin is clean', count(array_filter($fs, fn ($f) => str_starts_with($f->file, 'safe-plugin'))) === 0);
check('html escapes output', !str_contains(Audit::page([new WpPluginAudit\Finding('<x>', 1, 'WP001', 'high', '<b>', 'f', '<script>')]), '<script>'));
try { Audit::scanDir('/nonexistent'); check('missing dir throws', false); } catch (InvalidArgumentException) { check('missing dir throws', true); }
echo $fail ? "$fail of $n failed\n" : "all $n passed\n";
exit($fail ? 1 : 0);
