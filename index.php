<?php

require 'vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use Firebase\JWT\JWT;

$secret = 'MUxJTVZXVVIyWFRWQlJKTFA4V1NHOFpSNDdOSzVCWk8=';
$authToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50X2lkIjoiQUNWMklES0tUQiIsImRpc3BsYXlOYW1lIjoiSFx1MWViMW5nIFRoXHUxZWNiIExcdTAwZWEiLCJhdmF0YXJVcmwiOm51bGwsInBvcnRhbF9pZCI6IlBUNzVYRUhaOFAiLCJhY2NvdW50X3BvcnRhbF9pZCI6IlBBSFdHM1lGQk8iLCJleHAiOjE2NTUwMDUwNTEsImtleV9pZCI6IktFTDRURFQ5MjQifQ.d3Y4RVhsib0pkbo_NKvq98TqcliWZbMm1glFXtR_0QQ';
$config = Configuration::forSymmetricSigner(
	new Sha256(),
	InMemory::plainText($secret)
);

// lcobucci generate Token.
function getToken()
{
	global $config;
	$now   = new DateTimeImmutable();
	$authTokenPayload = [
		"displayName" => "Hằng Thị Lê",
		"avatarUrl" => null,
		"portal_id" => "PT75XEHZ8P",
		"account_portal_id" => "PAHWG3YFBO",
		"key_id" => "KEL4TDT924"
	];

	$builder = $config->builder()
				->expiresAt($now->modify('+30 day'));
	foreach ($authTokenPayload as $key => $value) {
		$builder->withClaim($key, $value);
	}
	$token = $builder->getToken($config->signer(), $config->signingKey());
	return $token->toString();
}

//lcobucci decode Token
function checkToken($authToken)
{
	global $config;
	try {
		$token = $config->parser()->parse($authToken);
		echo($token->toString());
	} catch (Exception $e) {
		echo $e->getMessage();
	}
}

//firebase decode Token 
function checkTokenFirebase($authToken)
{
	global $secret;
	try {
		$token = JWT::decode($authToken, $secret, array('HS256'));
		print_r($token);
	} catch (Exception $e) {
		echo $e->getMessage();
	}
}

checkToken($authToken);  // echo authToken
checkTokenFirebase($authToken); // Signature verification failed
