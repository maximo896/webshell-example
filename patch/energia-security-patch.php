<?php
/**
 * Plugin Name: Energia Theme Security Patch
 * Description: Fixes Critical Arbitrary File Upload Vulnerability (RCE) in Energia Theme <= 1.1.2 by overriding the vulnerable function with a secure version.
 * Version: 1.1.0
 * Author: Security Patch
 * Author URI: https://example.com
 * License: GPLv2 or later
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Override the vulnerable 'energia_get_started' function.
 * This works because the theme wraps its definition in `if ( ! function_exists(...) )`.
 * Since mu-plugins load before the theme, this secure version will take precedence.
 */
function energia_get_started() {
    // SECURITY FIX 1: Capability Check
    // Only allow users who can install plugins to access this function.
    // This blocks unauthenticated attackers (the main vulnerability) and low-privileged users.
    if ( ! current_user_can( 'install_plugins' ) ) {
        wp_send_json( [
            'stt'  => false,
            'msg'  => esc_html__( 'Permission denied. You are not authorized to perform this action.', 'energia' ),
            'data' => [],
        ] );
        die();
    }

    // SECURITY FIX 2: CSRF Protection (Optional but recommended)
    // Note: Since the theme's JS does not send a nonce, enforcing check_ajax_referer() would break the feature.
    // However, the Capability Check above effectively mitigates the RCE risk for the vast majority of scenarios.
    // If you want to fix CSRF, you would also need to patch the JS file.

    try {
        if ( isset( $_POST["activate"] ) && ! empty( $_POST["activate"] ) ) {
            $result = [
                'stt'  => false,
                'msg'  => esc_html__( 'Plugin CMS Portal have not installed yet!', 'energia' ),
                'data' => [],
            ];
            
            // Ensure get_plugins is available
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            $installed_plugins_data = get_plugins();
            foreach ( $installed_plugins_data as $installed_plugin_file => $installed_plugin_data ) {
                $_installed_plugin_file = explode( '/', $installed_plugin_file );
                if ( $_installed_plugin_file[0] == 'cms-portal' ) {
                    // null|WP_Error Null on success, WP_Error on invalid file.
                    $active_result = activate_plugin( $installed_plugin_file );

                    if ( ! is_null( $active_result ) ) {
                        $result = [
                            'stt'  => false,
                            'msg'  => esc_html__( 'Fail to activate plugin CMS Portal!', 'energia' ),
                            'data' => [],
                        ];
                    } else {
                        $current_theme = wp_get_theme();
                        if ( is_child_theme() ) {
                            $current_theme = $current_theme->parent();
                        }

                        $result = [
                            'stt'  => true,
                            'msg'  => esc_html__( 'Successfully!', 'energia' ),
                            'data' => [
                                'redirect_url' => admin_url( 'admin.php?page=' . $current_theme->get( 'TextDomain' ) )
                            ],
                        ];
                    }
                }
            }
        } else {
            if ( ! isset( $_POST["download_link"] ) || empty( $_POST["download_link"] ) ) {
                throw new Exception( __( 'Something went wrong!', 'energia' ) );
            }

            // SECURITY FIX 3: Basic URL Validation
            // Ensure the link is a valid URL. 
            // We could restrict domains here, but since the JS fetches from an API, the domain might change.
            // The capability check is the primary defense.
            if ( filter_var( $_POST["download_link"], FILTER_VALIDATE_URL ) === false ) {
                 throw new Exception( __( 'Invalid download link.', 'energia' ) );
            }

            $is_installed           = false;
            
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            
            $installed_plugins_data = get_plugins();
            foreach ( $installed_plugins_data as $installed_plugin_file => $installed_plugin_data ) {
                $_installed_plugin_file = explode( '/', $installed_plugin_file );
                if ( $_installed_plugin_file[0] == 'cms-portal' ) {
                    $is_installed = true;
                    // null|WP_Error Null on success, WP_Error on invalid file.
                    $active_result = activate_plugin( $installed_plugin_file );

                    if ( ! is_null( $active_result ) ) {
                        $result = [
                            'stt'  => false,
                            'msg'  => esc_html__( 'Fail to activate plugin!', 'energia' ),
                            'data' => [],
                        ];
                    } else {
                        $current_theme = wp_get_theme();
                        if ( is_child_theme() ) {
                            $current_theme = $current_theme->parent();
                        }

                        $result = [
                            'stt'  => true,
                            'msg'  => esc_html__( 'Successfully!', 'energia' ),
                            'data' => [
                                'redirect_url' => admin_url( 'admin.php?page=' . $current_theme->get( 'TextDomain' ) )
                            ],
                        ];
                    }
                }
            }

            if ( ! $is_installed ) {
                require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
                include_once ABSPATH . 'wp-admin/includes/plugin-install.php';

                $skin           = new WP_Ajax_Upgrader_Skin();
                $upgrader       = new Plugin_Upgrader( $skin );
                $install_result = $upgrader->install( $_POST["download_link"] );

                if ( ! $install_result ) {
                    $result = [
                        'stt'  => false,
                        'msg'  => __( 'Fail to install plugin!', 'energia' ),
                        'data' => [],
                    ];
                } else {
                    // Refresh plugins list
                    wp_clean_plugins_cache();
                    $installed_plugins_data = get_plugins();
                    
                    foreach ( $installed_plugins_data as $installed_plugin_file => $installed_plugin_data ) {
                        $_installed_plugin_file = explode( '/', $installed_plugin_file );
                        if ( $_installed_plugin_file[0] == 'cms-portal' ) {
                            // null|WP_Error Null on success, WP_Error on invalid file.
                            $active_result = activate_plugin( $installed_plugin_file );

                            if ( ! is_null( $active_result ) ) {
                                $result = [
                                    'stt'  => false,
                                    'msg'  => esc_html__( 'Fail to activate plugin!', 'energia' ),
                                    'data' => [],
                                ];
                            } else {
                                $current_theme = wp_get_theme();
                                if ( is_child_theme() ) {
                                    $current_theme = $current_theme->parent();
                                }

                                $result = [
                                    'stt'  => true,
                                    'msg'  => esc_html__( 'Successfully!', 'energia' ),
                                    'data' => [
                                        'redirect_url' => admin_url( 'admin.php?page=' . $current_theme->get( 'TextDomain' ) )
                                    ],
                                ];
                            }
                        }
                    }
                }
            }
        }
    } catch ( Exception $e ) {
        $result = [
            'stt'  => false,
            'msg'  => $e->getMessage(),
            'data' => '',
        ];
    }

    wp_send_json( $result );
    die();
}
