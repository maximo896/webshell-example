<?php
/**
 * Plugin Name: Energia Theme Security Patch
 * Description: Fixes Critical Arbitrary File Upload Vulnerability (RCE) in Energia Theme <= 1.1.2. This patch disables the vulnerable 'get_started' AJAX action.
 * Version: 1.0.0
 * Author: Security Patch
 * Author URI: https://example.com
 * License: GPLv2 or later
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Remove the vulnerable AJAX hooks registered by the Energia theme.
 * We hook into 'init' with a high priority (999) to ensure this runs 
 * AFTER the theme has registered its own hooks.
 */
function energia_security_patch_remove_vulnerable_hooks() {
    // The vulnerable function name in energia/inc/get-started.php
    $vulnerable_function = 'energia_get_started';

    // Remove the unauthenticated hook (The most dangerous one)
    if ( has_action( 'wp_ajax_nopriv_get_started', $vulnerable_function ) ) {
        remove_action( 'wp_ajax_nopriv_get_started', $vulnerable_function );
        error_log( '[Energia Security Patch] Removed vulnerable action: wp_ajax_nopriv_get_started' );
    }

    // Remove the authenticated hook (Also vulnerable as it lacks CSRF and Capability checks)
    if ( has_action( 'wp_ajax_get_started', $vulnerable_function ) ) {
        remove_action( 'wp_ajax_get_started', $vulnerable_function );
        error_log( '[Energia Security Patch] Removed vulnerable action: wp_ajax_get_started' );
    }
}
add_action( 'init', 'energia_security_patch_remove_vulnerable_hooks', 999 );

/**
 * Optional: Add a safe replacement if necessary.
 * Since the original function was used for installing plugins during theme setup,
 * disabling it is the safest immediate fix. Administrators can install plugins manually.
 */
