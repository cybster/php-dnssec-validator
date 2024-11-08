<?php
include_once('validate.php');


if ($argc<2) {
    die("Usage: test.php <domainname>\n\n");
}
$domainname = $argv[1];

try {
    validateDomain($domainname);
    echo "$domainname validation successful\n";
} catch (Metaregistrar\DNS\DnsException $e) {
    echo "ERROR: ".$e->getMessage()."\n";
}
