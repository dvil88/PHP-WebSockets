#!/php -q
<?php

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();

$master  = WebSocket('tcp://0.0.0.0:12345');
$sockets = array($master);
$users   = array();
$login = false;
$admin	 = array();
$adminPassword = 'SUPERSECUREPW';
$debug   = true;
$frame = array();

while(true){
	clearstatcache();

	$changed = $sockets;

	if (@stream_select($changed, $write = array(), $except = NULL, NULL) === false) {
		console("Select failed!");
		break;
	}

	foreach($changed as $socket){
		stream_set_blocking($socket, 0);
		if($socket==$master){
			$client = stream_socket_accept($master);
			if($client<0){ console("socket_accept() failed"); continue; }
			else{ connect($client); }
		}else{
			$buffer = fread($socket, 8192);
			if($buffer === false){ disconnect($socket); }
			
			$bytes = strlen($buffer);

			if($bytes === 0){ disconnect($socket);}
			elseif($socket != null){
				$user = getuserbysocket($socket);
				if(!$user->handshake){ dohandshake($user,$buffer); }
				else{ process($user,$buffer); }
			}
		}
	}
}

//---------------------------------------------------------------
function process($user,$msg){
	global $users;
	global $login;
	global $adminPassword;
	global $admin;

	$frame = decode($msg);

	$action = $frame['payloadData'];
	say("< ".$action);

	if(preg_match('/^login admin$/msi', $action)){
		send($user->socket,"Enter your password:");
		$login = true;
		return;
	}

	if($login){
		//password
		if($action == $adminPassword){
			$admin[$user->id] = '';
			send($user->socket,"Logged IN");
			$login = false;
			return;
		}
	}

	if(isset($admin[$user->id])){
		foreach($users as $k=>$u){
			if(isset($admin[$u->id])){continue;}
			send($u->socket,$action);
		}
		return;
	}

	send($user->socket,'OK');

}

function send($client,$msg){
	say("> ".$msg);
	$msg = encode($msg);
	$bytes = fwrite($client,$msg,strlen($msg));
	if($bytes === false){
		disconnect($socket);
	}
}

function WebSocket($address){
	$err = $errno = 0;
	$port = parse_url($address, PHP_URL_PORT);
	$context = stream_context_create();
	$master = stream_socket_server($address, $errno, $err, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

	echo "Server Started : ".date('Y-m-d H:i:s')."\n";
	echo "Master socket  : ".$master."\n";
	echo "Listening on   : ".$address." port ".$port."\n\n";

	if($master === false){
		echo 'ERROR: '.$err.PHP_EOL;
	}

	return $master;
}

function connect($socket){
	global $sockets,$users;
	$user = new User();
	$user->id = uniqid();
	$user->socket = $socket;
	array_push($users,$user);
	array_push($sockets,$socket);
	console($socket." CONNECTED!");
}

function disconnect($socket){
	global $sockets,$users;
	$found=null;
	$n=count($users);
	for($i=0;$i<$n;$i++){
		if($users[$i]->socket==$socket){ $found=$i; break; }
	}
	if(!is_null($found)){ array_splice($users,$found,1); }
	$index = array_search($socket,$sockets);
	//socket_close($socket);
	fclose($socket);
	console($socket." DISCONNECTED!");
	if($index>=0){ array_splice($sockets,$index,1); }
}

function dohandshake($user,$buffer){
	console("\nRequesting handshake...");
	console($buffer);
	if(preg_match("/Sec-WebSocket-Key: (.*)\r\n/",$buffer,$m)){ $key = $m[1]; }
	console('Handshaking...');


	// Generate accept key
	$accept = base64_encode(sha1($key."258EAFA5-E914-47DA-95CA-C5AB0DC85B11",true));
	// Generate upgrade message
	$upgrade  = "HTTP/1.1 101 WebSocket Switching Protocols\r\n" .
	"Upgrade: websocket\r\n" .
	"Connection: Upgrade\r\n" .
	"Sec-WebSocket-Accept: ".$accept."\r\n\r\n";

	//socket_write($user->socket,$upgrade.chr(0),strlen($upgrade.chr(0)));
	$bytes = fwrite($user->socket,$upgrade,strlen($upgrade));
	if($bytes === false){
		console('Error writing');
		return false;
	}
	$user->handshake=true;
	console($upgrade);
	console("Done handshaking...");
	return true;
}

function getheaders($req){
	$r=$h=$o=null;

	if(preg_match("/GET (.*) HTTP/"   ,$req,$match)){ $r=$match[1]; }
	if(preg_match("/Host: (.*)\r\n/"  ,$req,$match)){ $h=$match[1]; }
	if(preg_match("/Origin: (.*)\r\n/",$req,$match)){ $o=$match[1]; }
	if(preg_match("/Sec-WebSocket-Key: (.*)\r\n/",$req,$match)){ $key=$match[1]; }
	$key1 = '';if(preg_match("/Sec-WebSocket-Key1: (.*)\r\n/",$req,$match)){ $key1=$match[1]; }
	$key2 = '';if(preg_match("/Sec-WebSocket-Key2: (.*)\r\n/",$req,$match)){ $key2=$match[1]; }
	if(preg_match("/\r\n(.*?)\$/",$req,$match)){ $data=$match[1]; }
	return array($r,$h,$o,$key,$key1,$key2,$data);
}

function getuserbysocket($socket){
	global $users;

	$found = null;
	foreach($users as $user){
		if($user->socket==$socket){ $found=$user; break; }
	}
	return $found;
}

function     say($msg=""){ echo $msg."\n"; }
function    wrap($msg=""){ return chr(0).$msg.chr(255); }
function  unwrap($msg=""){ return substr($msg,1,strlen($msg)-2); }
function console($msg=""){ global $debug; if($debug){ echo $msg."\n"; } }

class User{
	var $id;
	var $socket;
	var $handshake;
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
