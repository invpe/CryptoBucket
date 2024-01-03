<?php
/*
    Funny BTC Lottery miner on solo pool made in php
	https://reference.cash/mining/stratum-protocol
*/ 

$GLOBALS['bitcoinwallet']="1KNbJNBmoQCDsSfgc2ZU8gif85Q4YSuRDX";
$GLOBALS['poolsocket'] = 0;
 
function POOL_disconnect($socket)
{
    if (!is_resource($GLOBALS['poolsocket']) || get_resource_type($GLOBALS['poolsocket']) !== 'stream') {
        return false;
    } 
    fclose($GLOBALS['poolsocket']); 
}
function SOCKET_ReadNewLine($socket) {
    $message = '';
    while (true) {
        // Read one byte at a time
        $byte = fread($socket, 1);

        // Check for end of line or end of file
        if ($byte === "\n" || $byte === false) {
            break;
        }

        // Append the byte to the message
        $message .= $byte;
    }

    // Return the line read from the socket
    return $message;
}
 
function POOL_connect()
{
	echo "[POOL] Connecting\n";
    $GLOBALS['poolsocket'] = fsockopen("solo.ckpool.org","3333");

    if(!$GLOBALS['poolsocket'])
    {
        echo "[POOL] Can't connect to pool server\n"; 
        return false;
    }
  	echo "[POOL] Connected\n";
    $messageout = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"PHP/1.0.0\"]}\n";
    fwrite($GLOBALS['poolsocket'],$messageout);
 
    // Read 
	$messagein = SOCKET_ReadNewLine($GLOBALS['poolsocket']);
    $messageinj = json_decode($messagein,true);
    $extranonce1 = $messageinj['result'][1];
    $extranonce2size = $messageinj['result'][2];
 
    // Read difficulty params
	$messagein = SOCKET_ReadNewLine($GLOBALS['poolsocket']);
    $messageinj = json_decode($messagein,true); 
     
    // Authorize
    $btcwallet=$GLOBALS['bitcoinwallet'];
    $messageout = "{\"params\": [\"".$btcwallet."\", \"password\"], \"id\": 2, \"method\": \"mining.authorize\"}\n";
	fwrite($GLOBALS['poolsocket'],$messageout);

	$messagein = SOCKET_ReadNewLine($GLOBALS['poolsocket']);
    $messageinj = json_decode($messagein,true); 
	
	$poolarray = array();

	$poolarray['extranonce1'] = $extranonce1;
	$poolarray['extranonce2size'] = $extranonce2size;
	$poolarray['jobid'] = $messageinj['params'][0];
	$poolarray['prevhash'] = $messageinj['params'][1];
	$poolarray['merklebranch']=$messageinj['params'][4];
	$poolarray['version']=$messageinj['params'][5];
	$poolarray['nbits']=$messageinj['params'][6];
	$poolarray['ntime']=$messageinj['params'][7];


    return $poolarray;
} 
function reverseHexStringToLittleEndian($hexString) {
    // Split the string into byte pairs
    $bytePairs = str_split($hexString, 2);

    // Reverse the order of the byte pairs
    $littleEndianBytePairs = array_reverse($bytePairs);

    // Join the byte pairs back into a string
    return implode('', $littleEndianBytePairs);
}
function doubleSha256($input) {
    return hash('sha256', hex2bin(hash('sha256', hex2bin($input))));
}
function double_sha256_hash($hexString) {
    // Convert the hex string to binary
    $binaryString = hex2bin($hexString);

    // Apply the first SHA-256 hash
    $hash = hash('sha256', $binaryString, true);

    // Apply the second SHA-256 hash
    $doubleHash = hash('sha256', $hash, true);

    // Convert the result back to a hex string
    return bin2hex($doubleHash);
}

function calcMerkleRoot(array $branch) {
    $total_count = count($branch);

    // Convert each input hash to little-endian
    $list = array_map(function($hash) {
        return implode('', array_reverse(str_split($hash, 2)));
    }, $branch);

    // Calculate the Merkle Root
    while ($total_count > 1) {
        if ($total_count % 2 === 1) {
            $list[] = end($list); // Duplicate the last element if the count is odd
            $total_count++;
        }

        for ($i = 0, $j = 0; $i < $total_count; $i += 2, $j++) {
            $list[$j] = doubleSha256($list[$i] . $list[$i + 1]);
        }

        $total_count = $j;
    }

    // Convert the final hash to big-endian
    return implode('', array_reverse(str_split($list[0], 2)));
}
function decodeNBits($nbits) {
    $exp = $nbits >> 24;
    $mant = $nbits & 0xffffff;

    $shift = 8 * ($exp - 3);
    $sb = intdiv($shift, 8);
    $rb = $shift % 8;

    // Prepare the target array (32 bytes, initialized to 0)
    $target = array_fill(0, 32, 0);

    // Set the bytes in little-endian order
    $target[$sb] = ($mant << $rb) & 0xff;
    if ($sb + 1 < 32) $target[$sb + 1] = ($mant >> (8 - $rb)) & 0xff;
    if ($sb + 2 < 32) $target[$sb + 2] = ($mant >> (16 - $rb)) & 0xff;
    if ($sb + 3 < 32) $target[$sb + 3] = ($mant >> (24 - $rb)) & 0xff;

    // Convert the target to a hexadecimal string
    $targetHex = '';
    foreach ($target as $byte) {
        $targetHex .= str_pad(dechex($byte), 2, "0", STR_PAD_LEFT);
    }

    return $targetHex;
}
function toHexString($input) {
    $hexString = '';
    for ($i = 0; $i < strlen($input); $i += 2) {
        $byte = substr($input, $i, 2);
        $hexString .= chr(hexdec($byte));
    }
    return $hexString;
}
function serializeHashBlock($version, $prevhash, $merkle_root, $ntime, $nbits,$nonce) {
    // Helper function to convert a 32-byte hexadecimal string to a binary string
    $hexToBinary = function ($hexString) {
        return pack('H*', $hexString);
    };

    // Convert version, ntime, nbits, and nonce to 4-byte little-endian binary strings
    $versionBinary = pack('V', $version); // 'V' is for 32-bit unsigned integer (little-endian)
    $ntimeBinary = pack('V', $ntime);
    $nbitsBinary = pack('V', $nbits);

    // Convert prevhash and merkle_root to binary strings
    $prevhashBinary = $hexToBinary($prevhash);
    $merkleRootBinary = $hexToBinary($merkle_root);

    // Concatenate all binary strings
     $binaryData = $versionBinary . $prevhashBinary . $merkleRootBinary . $ntimeBinary . $nbitsBinary;

    return bin2hex($binaryData);
}
function little_endian_bit_comparison($a, $b, $byte_len) {
    for ($i = $byte_len - 1; $i >= 0; --$i) {
        $aVal = ord($a[$i]);
        $bVal = ord($b[$i]);

        if ($aVal < $bVal)
            return -1;
        else if ($aVal > $bVal)
            return 1;
    }
    return 0;
}
function generate_extranonce2($size) {
    $extranonce2 = "";
    for ($i = 0; $i < $size; ++$i) {
        // Generate a random byte
        $randomValue = rand(0, 255);  // Equivalent to getting one byte

        // Convert the byte to a hexadecimal string and ensure two characters
        $hexString = str_pad(dechex($randomValue), 2, "0", STR_PAD_LEFT);

        $extranonce2 .= $hexString;
    }
    return $extranonce2;
}

 

while(1)
{ 
     
    $poolarray = POOL_connect();      
    $iterations = 5000000;
    $startnonce = rand(0,PHP_INT_MAX-$iterations);

    echo "[MINING] Nonce start ".$startnonce."\n";
    $starttime=time();
 
    // TESTBLOCK Nonce: 274148111
    /*
    $poolarray = array();
    $poolarray['version']=1;
    $poolarray['merklebranch']=  [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
    ];
    $poolarray['prevhash']="000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250";
    $poolarray['nbits']=453281356;
    $poolarray['ntime']=1293623863;
    */
    // Build a block
    $blockmerkleroot    = reverseHexStringToLittleEndian(calcMerkleRoot($poolarray['merklebranch']));
    $blockprevhash      = reverseHexStringToLittleEndian($poolarray['prevhash']);
    $blocktargethex     = decodeNBits(hexdec($poolarray['nbits']));     //// TO JES THEX!!
    
    print_r($poolarray);
    $hashrate=0;
    for($i = 0; $i < $iterations; $i++)
    {

        $nonce=$startnonce+$i;
        $gsblock = serializeHashBlock($poolarray['version'],$blockprevhash,$blockmerkleroot,$poolarray['ntime'],$poolarray['nbits'],$nonce);
        $gsblock.=reverseHexStringToLittleEndian(dechex($nonce)); 
        $binaryString = hex2bin($gsblock);

        if ($binaryString === false) 
        {   
            break;            
        }
        // Apply the first SHA-256 hash
        $hash = hash('sha256', $binaryString, true);

        // Apply the second SHA-256 hash (returns bin)
        $doubleHash = hash('sha256', $hash, true);         

        if (little_endian_bit_comparison($doubleHash, hex2bin($blocktargethex), 32) < 0) {
            echo "[MINING] Found ".$nonce."\n";

            $extranonce2 = generate_extranonce2($poolarray['extranonce2size']);
                $payload = json_encode([
                "params" => [
                    $GLOBALS['bitcoinwallet'],
                    $poolarray['jobid'],
                    $extranonce2,
                    $poolarray['ntime'],
                    $nonce
                ],
                "id" => 1,
                "method" => "mining.submit"
            ]);
            print_r($payload);

            fwrite($GLOBALS['poolsocket'],$payload);    
            $messagein = SOCKET_ReadNewLine($GLOBALS['poolsocket']); 
            file_put_contents("found.txt", time().",".$poolarray['jobid'].",".$poolarray['prevhash'].",".$nonce.",".$gsblock."\n".$messagein."\n",FILE_APPEND);

            break;
        }
        $hashrate++;

    }

    POOL_disconnect($GLOBALS['poolsocket']); 
	
    $totaltime = time() - $starttime; 
    if($totaltime>0 && $hashrate>0)
    {
        $hashperminute = $hashrate / $totaltime;
        echo "[GSHELL] Time taken: " . $totaltime . " seconds, hashrate ".$hashperminute." h/s\n";
    } 
 
}
?>
