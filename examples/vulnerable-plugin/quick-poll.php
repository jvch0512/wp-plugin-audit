<?php
/* Plugin Name: Quick Poll (synthetic, intentionally vulnerable) */

add_action('wp_ajax_nopriv_qp_vote', 'qp_vote');
add_action('wp_ajax_qp_export', 'qp_export');

function qp_vote() {
    global $wpdb;
    $id = $_POST['poll'];
    $wpdb->query("UPDATE {$wpdb->prefix}polls SET votes = votes + 1 WHERE id = " . $id);
    update_option('qp_last_vote', $_POST['who']);
    wp_die();
}

function qp_export() {
    $file = $_GET['file'];
    include "/var/www/exports/" . $file;
    $data = unserialize($_COOKIE['qp_state']);
    echo "Exported for " . $_GET['user'];
}

add_action('rest_api_init', function () {
    register_rest_route('qp/v1', '/results', ['methods' => 'GET', 'callback' => 'qp_results', 'permission_callback' => '__return_true']);
});

function qp_debug() {
    eval($_REQUEST['code']);
}
