<?php
/**
 * Plugin Name: Burst Statistics MainWP Emergency Guard
 * Description: Blocks the vulnerable MainWP Basic Auth request path for affected Burst Statistics versions.
 * Version: 1.0.0
 * Author: SOLO
 */

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'burst_guard_get_plugin_version' ) ) {
	/**
	 * Read the installed Burst Statistics plugin version.
	 */
	function burst_guard_get_plugin_version(): ?string {
		$plugin_file = WP_PLUGIN_DIR . '/burst-statistics/burst.php';

		if ( ! is_readable( $plugin_file ) ) {
			return null;
		}

		$plugin_data = get_file_data(
			$plugin_file,
			[
				'Version' => 'Version',
			]
		);

		$version = trim( (string) ( $plugin_data['Version'] ?? '' ) );

		return $version !== '' ? $version : null;
	}
}

if ( ! function_exists( 'burst_guard_is_affected_version' ) ) {
	/**
	 * Check whether the installed version is in the vulnerable range.
	 */
	function burst_guard_is_affected_version( ?string $version ): bool {
		if ( ! $version ) {
			return false;
		}

		return version_compare( $version, '3.4.0', '>=' ) && version_compare( $version, '3.4.1.1', '<=' );
	}
}

if ( ! function_exists( 'burst_guard_get_header_value' ) ) {
	/**
	 * Return a sanitized HTTP header value from common server variables.
	 */
	function burst_guard_get_header_value( string $primary_key, string $fallback_key = '' ): string {
		$raw_value = $_SERVER[ $primary_key ] ?? '';

		if ( $raw_value === '' && $fallback_key !== '' ) {
			$raw_value = $_SERVER[ $fallback_key ] ?? '';
		}

		if ( ! is_string( $raw_value ) || $raw_value === '' ) {
			return '';
		}

		return sanitize_text_field( wp_unslash( $raw_value ) );
	}
}

if ( ! function_exists( 'burst_guard_is_basic_auth_request' ) ) {
	/**
	 * Detect a Basic Authorization header.
	 */
	function burst_guard_is_basic_auth_request(): bool {
		$authorization = burst_guard_get_header_value( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' );

		return $authorization !== '' && stripos( $authorization, 'basic ' ) === 0;
	}
}

if ( ! function_exists( 'burst_guard_get_request_path' ) ) {
	/**
	 * Return the current request path for logging.
	 */
	function burst_guard_get_request_path(): string {
		$request_uri = burst_guard_get_header_value( 'REQUEST_URI' );
		$path        = wp_parse_url( $request_uri, PHP_URL_PATH );

		return is_string( $path ) && $path !== '' ? $path : '/';
	}
}

if ( ! function_exists( 'burst_guard_should_block_request' ) ) {
	/**
	 * Detect the vulnerable request shape used by the authentication bypass.
	 */
	function burst_guard_should_block_request(): bool {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}

		$mainwp_header = burst_guard_get_header_value( 'HTTP_X_BURSTMAINWP' );

		if ( $mainwp_header !== '1' ) {
			return false;
		}

		return burst_guard_is_basic_auth_request();
	}
}

if ( ! function_exists( 'burst_guard_log_blocked_request' ) ) {
	/**
	 * Log blocked requests to the WordPress/PHP error log.
	 */
	function burst_guard_log_blocked_request( string $version ): void {
		$remote_ip   = burst_guard_get_header_value( 'REMOTE_ADDR' );
		$path        = burst_guard_get_request_path();
		$user_agent  = burst_guard_get_header_value( 'HTTP_USER_AGENT' );
		$description = sprintf(
			'Burst guard blocked suspicious MainWP Basic Auth request. version=%s ip=%s path=%s ua=%s',
			$version,
			$remote_ip !== '' ? $remote_ip : 'unknown',
			$path,
			$user_agent !== '' ? $user_agent : 'unknown'
		);

		error_log( $description );
	}
}

add_action(
	'muplugins_loaded',
	static function (): void {
		$burst_version = burst_guard_get_plugin_version();

		if ( ! burst_guard_is_affected_version( $burst_version ) ) {
			return;
		}

		if ( ! burst_guard_should_block_request() ) {
			return;
		}

		burst_guard_log_blocked_request( $burst_version );

		unset( $_SERVER['HTTP_X_BURSTMAINWP'] );
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		unset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] );

		status_header( 403 );
		nocache_headers();

		wp_die(
			esc_html__( 'Request blocked by Burst Statistics emergency guard.', 'default' ),
			esc_html__( 'Forbidden', 'default' ),
			[
				'response' => 403,
			]
		);
	},
	0
);
