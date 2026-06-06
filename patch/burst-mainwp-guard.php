<?php
/**
 * Plugin Name: Burst MainWP Guard
 * Description: MU-plugin guard for Burst Statistics 3.4.0 MainWP auth bypass attempts.
 * Version: 1.0.0
 * Author: Local Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * This guard intentionally runs early and blocks the vulnerable compatibility
 * header before Burst can use it to switch the current user.
 */
add_action( 'muplugins_loaded', 'bmg_block_burst_mainwp_bypass', 0 );
add_action( 'plugins_loaded', 'bmg_block_burst_mainwp_bypass', 0 );
add_action( 'rest_api_init', 'bmg_block_burst_mainwp_bypass', 0 );

function bmg_block_burst_mainwp_bypass(): void {
	static $checked = false;

	if ( $checked ) {
		return;
	}
	$checked = true;

	if ( ! bmg_has_burst_mainwp_header() ) {
		return;
	}

	/*
	 * If you actively use Burst's MainWP integration, replace this hard block
	 * with an IP allowlist for your MainWP dashboard server.
	 */
	bmg_forbid( 'Blocked Burst MainWP compatibility header.' );
}

function bmg_has_burst_mainwp_header(): bool {
	$value = $_SERVER['HTTP_X_BURSTMAINWP'] ?? '';

	if ( ! is_string( $value ) ) {
		return false;
	}

	return trim( $value ) === '1';
}

function bmg_forbid( string $message ): void {
	if ( function_exists( 'status_header' ) ) {
		status_header( 403 );
	} else {
		header( 'HTTP/1.1 403 Forbidden', true, 403 );
	}

	if ( function_exists( 'wp_die' ) ) {
		wp_die(
			esc_html( $message ),
			'Forbidden',
			[
				'response' => 403,
			]
		);
	}

	header( 'Content-Type: text/plain; charset=utf-8' );
	echo esc_html( $message );
	exit;
}

