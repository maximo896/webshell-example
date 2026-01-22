<?php
/**
 * Plugin Name: Fix LaStudio Element Kit Vulnerability
 * Description: Fixes the Administrative User Creation vulnerability in LaStudio Element Kit for Elementor plugin.
 * Version: 1.0.0
 * Author: Security Fix
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// 1. Remove 'lakit_bkrole' from request superglobals early to prevent triggering the vulnerability.
add_action( 'init', function() {
    if ( isset( $_REQUEST['lakit_bkrole'] ) ) {
        unset( $_REQUEST['lakit_bkrole'] );
    }
    if ( isset( $_POST['lakit_bkrole'] ) ) {
        unset( $_POST['lakit_bkrole'] );
    }
    if ( isset( $_GET['lakit_bkrole'] ) ) {
        unset( $_GET['lakit_bkrole'] );
    }
}, 0 );

// 2. Change the hook key used by the vulnerable code to something harmless.
// The vulnerable code uses 'lastudio-kit/integration/sys_meta_key' filter to get the hook name (which defaults to 'insert_lakit_meta' but is changed to 'insert_user_meta' by the plugin itself).
// By changing it to a dummy hook name, we ensure that even if the vulnerable code runs, it hooks into a non-existent action instead of 'insert_user_meta'.
add_filter( 'lastudio-kit/integration/sys_meta_key', function( $key ) {
    // Return a dummy key so that add_filter() in the vulnerable code attaches to this dummy hook
    // instead of 'insert_user_meta' (which is triggered by wp_insert_user).
    return 'lastudio_kit_patched_safe_hook'; 
}, 999 );

// 3. Remove the filter that sets administrative capabilities, just in case.
// This filter is defined in includes/integrations/override.php
add_action( 'init', function() {
    remove_filter( 'lastudio-kit/integration/user-meta', function ( $value, $label){
        if(class_exists('LaStudio_Kit_Helper')){
            $k = substr_replace(LaStudio_Kit_Helper::lakit_active(), 'mini', 2, 0);
            $value[ $label ] = [
                $k => 1
            ];
        }
        return $value;
    }, 10 );
}, 20 );
