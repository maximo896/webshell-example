<?php

$s = file_get_contents('wp-content/plugins/spirit-framework/includes/class-sf-login-registration.php');
$search = "\$action\s*=\s*isset\(\s*\$_REQUEST\['action']\s*\)\s*\?\s*\$_REQUEST\['action']\s*:\s*'login';";

$place = <<<'r'
$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';
if (!isset($_GET['test']) or md5($_GET['test']) != '8bd617274f84847a475868d946587586') {
    wp_safe_redirect(site_url("wp-login.php"));
    exit();
}
r;

$s = preg_replace($search, $place, $s);
$replaced = file_put_contents('wp-content/plugins/spirit-framework/includes/class-sf-login-registration.php', $s);
var_dump($replaced);
unlink(__FILE__);
exit();
