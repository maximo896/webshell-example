<?php
/**
 * Plugin Name: Alone Theme Security Patch
 * Description: Fixes CVE-2025-5394 and related vulnerabilities in the Alone theme by removing unauthenticated AJAX actions and enforcing capability checks.
 * Version: 1.0.0
 * Author: Trae
 */

// Hook late to ensure theme actions are already registered
add_action( 'init', 'alone_theme_security_patch_fix', 999 );

function alone_theme_security_patch_fix() {
    $actions = [
        'beplus_import_pack_modal_import_body_template',
        'beplus_import_pack_import_action_ajax_callback',
        'beplus_import_pack_install_plugin',
        'beplus_import_pack_download_package',
        'beplus_import_pack_extract_package_demo',
        'beplus_import_pack_restore_data',
        'beplus_import_pack_backup_site_substep_install_bears_backup_plg',
        'beplus_import_pack_backup_site_substep_backup_database',
        'beplus_import_pack_backup_site_substep_create_file_config',
        'beplus_import_pack_backup_site_substep_backup_folder_upload'
    ];

    foreach ( $actions as $action ) {
        // 1. Remove the unauthenticated hook (nopriv) completely.
        // This blocks unauthenticated users from triggering these functions.
        remove_action( 'wp_ajax_nopriv_' . $action, $action );

        // 2. Add a security check for the authenticated hook.
        // This runs before the theme's handler (priority 1 vs 10) and ensures only admins can run it.
        add_action( 'wp_ajax_' . $action, 'alone_theme_security_enforce_admin', 1 );
    }
}

function alone_theme_security_enforce_admin() {
    // Check if the current user has administrator capabilities
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Forbidden: You do not have permission to perform this action.' ) );
        wp_die();
    }
}
