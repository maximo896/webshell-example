<?php
/**
 * Plugin Name: s2Member Security Fix (CVE-2026-XXXX)
 * Description: Patches the Unauthenticated Privilege Escalation vulnerability in s2Member <= 260127 by sanitizing malicious POST parameters during password reset.
 * Version: 1.0.0
 * Author: Trae Security
 * Mu-Plugin: Yes
 */

defined('ABSPATH') || exit;

// Hook early to sanitize input before s2Member processes it
add_action('init', 's2member_security_fix_cve_2026_xxxx', 1);

function s2member_security_fix_cve_2026_xxxx() {
    // Check if we are in a password reset flow (lostpassword action)
    $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';
    
    // List of actions that trigger password reset logic where s2member might intervene incorrectly
    $reset_actions = array('lostpassword', 'retrieve_password');
    
    // The vulnerable parameter used by s2Member to set custom passwords
    $vuln_param = 'ws_plugin__s2member_custom_reg_field_user_pass1';

    // If it's a password reset request AND the vulnerable parameter is present
    if (in_array($action, $reset_actions) && (isset($_POST[$vuln_param]) || isset($_REQUEST[$vuln_param]))) {
        
        // Log the blocked attempt (optional, helpful for monitoring)
        error_log(sprintf(
            '[s2Member-Fix] Blocked privilege escalation attempt. IP: %s, User Agent: %s',
            isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown',
            isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown'
        ));

        // NEUTRALIZE THE EXPLOIT:
        // Remove the parameter so s2Member's logic sees it as empty/missing
        // and falls back to standard secure behavior (or doesn't intervene).
        unset($_POST[$vuln_param]);
        unset($_REQUEST[$vuln_param]);
        unset($_GET[$vuln_param]); // Just in case
    }
}
