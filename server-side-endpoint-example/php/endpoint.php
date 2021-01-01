<?php

// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);

/* Constants */
// database column names
const ID = 'id';
const HASH = 'hash';
const TYPE = 'type';
const PROBABILITY = 'probability';

// database table names
const CONTROL = 'antispam_control';
const RESULT = 'antispam_results';
const ITEMS = 'antispam_items';

const PDO_VALUE_PREFIX = ':';
const DESCRIPTION = 'This text is used as a salt for hash (sha-256). Keep this text unchanged. For more information about this anti spam library visit https://github.com/iiic/anticspam or https://iiic.dev/anticspam';
const HTTP_METHOD_POST = 'POST';
const DATA_TYPES = [
	'urls' => 'url',
	'emails' => 'email',
	'texts' => 'text',
	'hundredths' => 'hundredth'
];

// database queries
const CONTROL_QUERY = 'SELECT ' . ID . ', privateKey, origins FROM `' . CONTROL . '`';
const SELECT_RESULTS_QUERY = 'SELECT ' . ID . ', ' . PROBABILITY . ' FROM `' . RESULT . '` WHERE `'. HASH .'`=' . PDO_VALUE_PREFIX . HASH . ' AND `' . TYPE . '`=' . PDO_VALUE_PREFIX . TYPE;
const INSERT_RESULT_QUERY = 'INSERT INTO `' . RESULT . '` (';
const INSERT_ITEM_QUERY = 'INSERT IGNORE INTO `' . ITEMS . '` (`' . RESULT . '_id`, `' . CONTROL . '_id`, datetime) VALUES ';

// headers
const ORIGIN_HEADER = 'origin';
const PUBLIC_KEY_HEADER = 'x-public-key';
const HEADER_VALUE_DIVIDER = PDO_VALUE_PREFIX;

/* Functions */
function findItemBy(PDO $pdo, string $publicKey) : ?object
{
	/** @var PDOStatement $statement */
	$statement = $pdo->prepare(CONTROL_QUERY);
	$statement->execute();
	$result = $statement->fetch(PDO::FETCH_OBJ);

	if( $result && $result->origins ) {
		$result->origins = json_decode($result->origins);
	}

	return $result === false ? null : $result;
}

function getKeyAndOriginFrom(array $headers) : ?array
{
	foreach ($headers as $key => $value) {
		if (strtolower($key) === PUBLIC_KEY_HEADER) {
			$publicKey = $value;
		} else if (strtolower($key) === ORIGIN_HEADER) {
			$origin = str_replace('http://', '', str_replace('https://', '', $value));
		}
	}

	return (!isset($publicKey) || !isset($origin)) ? null : [$publicKey, $origin];
}

function getResult(PDO $pdo, string $hash, string $type) : ?array
{
	$data = [
		HASH => $hash,
		TYPE => DATA_TYPES[$type],
	];

	/** @var PDOStatement $statement */
	$statement = $pdo->prepare(SELECT_RESULTS_QUERY);
	$statement->bindParam(PDO_VALUE_PREFIX . HASH, $hash, PDO::PARAM_STR);
	$statement->bindValue(PDO_VALUE_PREFIX . TYPE, DATA_TYPES[$type], PDO::PARAM_STR);
	$statement->execute();
	$pair = $statement->fetch(PDO::FETCH_ASSOC);

	if ($pair[ID]) {
		return [$pair[ID], $pair[PROBABILITY]];
	}

	/** @var PDOStatement $statement */
	$statement = $pdo->prepare(INSERT_RESULT_QUERY . implode(', ', array_keys($data)) . ') VALUES (' . PDO_VALUE_PREFIX . implode(', ' . PDO_VALUE_PREFIX, array_keys($data)) . ')');
	if ($statement->execute($data)) {
		return [$pdo->lastInsertId(), null];
	}
	return null;
}

function storeSingleItems(PDO $pdo, array $rows)
{
	/** @var PDOStatement $statement */
	$statement = $pdo->prepare(INSERT_ITEM_QUERY . substr(str_repeat('(?, ?, now()), ', (count($rows)/2)), 0, -2));
	return $statement->execute($rows);
}

/* Program */
$pdo = new PDO('mysql:host=localhost;dbname=iiic.dev', 'root', '*****');

header('content-type: application/json; charset=utf-8');
header('access-control-allow-headers: ' . PUBLIC_KEY_HEADER . ', content-type, ' . ORIGIN_HEADER);
header('access-control-allow-methods: ' . HTTP_METHOD_POST);
header('access-control-allow-origin: *');

if ($_SERVER['REQUEST_METHOD'] === HTTP_METHOD_POST) {
	$rawData = file_get_contents('php://input');
	$httpHeaders = getallheaders();
	if ($rawData && $httpHeaders) {
		$antispamRequest = json_decode($rawData);
		list($publicKey, $origin) = getKeyAndOriginFrom($httpHeaders);
		if ($publicKey && $origin) {
			$controlInfo = findItemBy($pdo, $publicKey);
			if ($controlInfo && in_array($origin, $controlInfo->origins, true)) {
				$rows = [];
				foreach ($antispamRequest as $type => $items) {
					foreach ($items as $hash) {
						list($resultId, $summaryResult) = getResult($pdo, $hash, $type);
						array_push($rows, $resultId, $controlInfo->id);
					}
				}
				storeSingleItems($pdo, $rows);
				$complexity = 1000000; // temp
				$summaryResult = random_int(0, $complexity) / $complexity; // temp
				$signature = bin2hex(mhash(MHASH_SHA256, $summaryResult . $rawData . $controlInfo->privateKey . DESCRIPTION));
				$response = json_encode((object) [
					'status' => 'ok',
					'result' => $summaryResult,
					'signature' => $signature,
				]);
				echo $response;
				exit;
			}
		}
	}
	echo '{"status":"error"}';
	exit;
}

echo '{"status":"only ' . HTTP_METHOD_POST . ' data allowed"}';
