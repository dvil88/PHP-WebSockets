<?php

$url = 'localhost';
$port = '12345';

define('CR',"\r\n");

$err = $errno = 0;
$url = '0.0.0.0';
$port = '12345';
$address = 'tcp://0.0.0.0:12345/websockets/server.php';
$frame = array(
'FIN'=>0,
'RSV1'=>0,
'RSV2'=>0,
'RSV3'=>0,
'opcode'=>'',
'mask'=>0,
'payloadLength'=>0,
'maskingKey'=>0,
'payloadData'=>'',
'actualLength'=>0,
	);
//$socket = fsockopen($url,$port,$errno, $err);


$err = $errno = '';
$socket = stream_socket_client($address,$errno,$err);

$key = generateSecKey();
$header = 
	'GET /echo HTTP/1.1'.CR.
	'Upgrade: websocket'.CR.
	'Connection: Upgrade'.CR.
	'Host: 192.168.1.58:12345'.CR.
	'Origin: http://localhost'.CR.
	'Pragma: no-cache'.CR.
	'Cache-Control: no-cache'.CR.
	'Sec-WebSocket-Key: '.$key.CR.
	'Sec-WebSocket-Version: 13'.CR.
	'Sec-WebSocket-Extensions: x-webkit-deflate-frame'.CR.
	'User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.66 Safari/537.36'.CR.CR;

$b = fwrite($socket, $header,strlen($header));
//var_dump($b);

$buffer = '';
while(!feof($socket)){
	$buffer .= fgets($socket,1024);
	if(preg_match("/^\r\n$/msi",$buffer)){break;}
}

// Check key
if(preg_match("/Sec-WebSocket-Accept: (.*)\r\n/",$buffer,$m)){ $aKey = $m[1]; }
$acceptKey = base64_encode(sha1($key."258EAFA5-E914-47DA-95CA-C5AB0DC85B11",true));

if($acceptKey != $aKey){
	echo 'Las claves no coinciden.',PHP_EOL;
	fclose($socket);
}


/*
$a = encode('login admin');
$b = fwrite($socket, $a,strlen($a));
$buffer = fread($socket, 8192);
if($buffer === false){ echo 'ERROR!',PHP_EOL;fclose($socket);exit; }
$bytes = strlen($buffer);
if($bytes === 0){ fclose($socket);exit; }
elseif($socket != null){
	$msg = decode($buffer);
	var_dump($msg['payloadData']);
}

$a = encode('SUPERSECUREPW');
$b = fwrite($socket, $a,strlen($a));
$buffer = fread($socket, 8192);
if($buffer === false){ echo 'ERROR!',PHP_EOL;fclose($socket);exit; }
$bytes = strlen($buffer);
if($bytes === 0){ fclose($socket);exit; }
elseif($socket != null){
	$msg = decode($buffer);
	var_dump($msg['payloadData']);
}
*/

$fp = fopen('php://stdin','r');
while($l = fgets($fp)){
	$l = trim($l);

	$a = encode($l);
	$b = fwrite($socket,$a,strlen($a));


	$buffer = fread($socket, 8192);
	if($buffer === false){ echo 'ERROR!',PHP_EOL;fclose($socket);exit; }
	$bytes = strlen($buffer);
	if($bytes === 0){ fclose($socket);exit; }
	elseif($socket != null){
		$msg = decode($buffer);
		var_dump($msg['payloadData']);
	}
}


function generateSecKey(){
	$key = '';
	for($i=0;$i<16;$i++){$key .= chr(rand(0,255));}
	return base64_encode($key);
}
function IsBitSet($byte, $pos) {
	return ($byte & pow(2, $pos)) > 0 ? 1 : 0;
}
function rotMask($data, $key, $offset = 0) {
	$res = '';
	for ($i = 0; $i < strlen($data); $i++) {
		$j = ($i + $offset) % 4;
		$res .= chr(ord($data[$i]) ^ ord($key[$j]));
	}

	return $res;
}
function decode(&$raw, $head = null) {
	global $frame;

	$frame['actualLength'] = 0;
	$frame['payloadData'] = '';

	if ($head != null) {
		$frame = $head;
	} else {
		// Read the first two bytes, then chop them off
		list($firstByte, $secondByte) = substr($raw, 0, 2);
		$raw = substr($raw, 2);

		$firstByte = ord($firstByte);
		$secondByte = ord($secondByte);

		$frame['FIN'] = IsBitSet($firstByte, 7);
		$frame['RSV1'] = IsBitSet($firstByte, 6);
		$frame['RSV2'] = IsBitSet($firstByte, 5);
		$frame['RSV3'] = IsBitSet($firstByte, 4);

		$frame['mask'] = IsBitSet($secondByte, 7);

		$frame['opcode'] = ($firstByte & 0x0F);

		$len = $secondByte & ~128;

		if ($len <= 125)
			$frame['payloadLength'] = $len;
		elseif ($len == 126) {
			$arr = unpack("nfirst", $raw);
			$frame['payloadLength'] = array_pop($arr);
			$raw = substr($raw, 2);
		} elseif ($len == 127) {
			list(, $h, $l) = unpack('N2', $raw);
			$frame['payloadLength'] = ($l + ($h * 0x0100000000));
			$raw = substr($raw, 8);
		}

		if ($frame['mask']) {
			$frame['maskingKey'] = substr($raw, 0, 4);
			$raw = substr($raw, 4);
		}
	}

	$currentOffset = $frame['actualLength'];
	$fullLength = min($frame['payloadLength'] - $frame['actualLength'], strlen($raw));
	$frame['actualLength'] += $fullLength;

	if ($fullLength < strlen($raw)) {
		$frameData = substr($raw, 0, $fullLength);
		$raw = substr($raw, $fullLength);
	} else {
		$frameData = $raw;
		$raw = '';
	}

	if ($frame['mask'])
		$frame['payloadData'] .= rotMask($frameData, $frame['maskingKey'], $currentOffset);
	else
		$frame['payloadData'] .= $frameData;

	return $frame;
}
function encode($msg) {
	global $frame;
	$frame['mask'] = 0;

	$frame['payloadLength'] = strlen($msg);

	$firstByte = $frame['opcode'];

	$firstByte += $frame['FIN'] * 128 + $frame['RSV1'] * 64 + $frame['RSV2'] * 32 + $frame['RSV3'] * 16;

	$encoded = chr($firstByte);

	if ($frame['payloadLength'] <= 125) {
		$secondByte = $frame['payloadLength'];
		$secondByte += $frame['mask'] * 128;

		$encoded .= chr($secondByte);
	} else if ($frame['payloadLength'] <= 255 * 255 - 1) {
		$secondByte = 126;
		$secondByte += $frame['mask'] * 128;

		$encoded .= chr($secondByte) . pack("n", $frame['payloadLength']);
	} else {
		// TODO: max length is now 32 bits instead of 64 !!!!!
		$secondByte = 127;
		$secondByte += $frame['mask'] * 128;

		$encoded .= chr($secondByte);
		$encoded .= pack("N", 0);
		$encoded .= pack("N", $frame['payloadLength']);
	}

	$key = 0;
	if ($frame['mask']) {
		$key = pack("N", rand(0, pow(255, 4) - 1));
		$encoded .= $key;
	}

	if ($msg)
		$encoded .= ($frame['mask'] == 1) ? rotMask($msg, $key) : $msg;

	return $encoded;
}

?>