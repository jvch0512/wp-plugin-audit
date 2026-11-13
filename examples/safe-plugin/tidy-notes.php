<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action('wp_ajax_tn_save', 'tn_save');

function tn_save() {
    check_ajax_referer('tn_save');
    if ( ! current_user_can('edit_posts') ) { wp_send_json_error(); }
    global $wpdb;
    $id = absint($_POST['id']);
    $wpdb->query($wpdb->prepare("UPDATE {$wpdb->prefix}notes SET body = %s WHERE id = %d", sanitize_text_field($_POST['body']), $id));
    echo esc_html($_POST['body']);
    wp_die();
}
