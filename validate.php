<?php
/** 
 * This function makes use of dnsProtocol class, which is able to retrieve DNS records from nameservers 
 * With this information, validateDomain can check if the DNSSEC information on a domain name is valid
 */
require_once __DIR__ . "/vendor/autoload.php";

use Metaregistrar\DNS\dnsProtocol;
use Metaregistrar\DNS\dnsException;
use Metaregistrar\DNS\dnsNSresult;
use Metaregistrar\DNS\dnsDSresult;
use Metaregistrar\DNS\dnsRRSIGresult;
use Metaregistrar\DNS\dnsDNSKEYresult;

function validateDomain(string $domainname): bool
{
    $parentkeys = [];
    $domainname = strtolower($domainname);
    $dns = new dnsProtocol(false);
    $tld = substr($domainname, strpos($domainname, '.') + 1);
    $dnsservers = $dns->registrynameservers($tld);
    
    if (!is_array($dnsservers)) {
        throw new dnsException("DNSSEC validation not supported yet for the domain name " . $domainname);
    }

    foreach ($dnsservers as $dnsserver) {
        $dns->setServer($dnsserver);
        $result = $dns->Query($domainname, 'NS');
        if ($result->getNameserverResultCount() > 0) {
            $ns = $result->getNameserverResults();
            foreach ($ns as $n) {
                /* @var $n dnsNSresult */
                $nameservers[] = $n->getNameserver();
            }
            $result = $dns->Query($domainname, 'DS');
            if ($result->getResourceResultCount() === 0) {
                throw new dnsException("No DS record found at parent: Domain name is not secured");
            } else {
                $ds = $result->getResourceResults();
                foreach ($ds as $d) {
                    /* @var $d dnsDSresult */
                    $pk = [
                        'key' => $d->getKey(),
                        'keytag' => $d->getKeytag(),
                        'algorithm' => $d->getAlgorithm(),
                        'matched' => false
                    ];
                    $parentkeys[] = $pk;
                }
            }
            break;
        }
    }

    if (isset($nameservers) && is_array($nameservers)) {
        foreach ($nameservers as $ns) {
            $dns->setServer($ns);
            $result = $dns->Query($domainname, 'RRSIG');
            if ($result->getResourceResultCount() === 0) {
                throw new dnsException("No RRSIG records found on " . $ns . " for domain name " . $domainname);
            }
            $rrsigs = $result->getResourceResults();
            foreach ($rrsigs as $rrsig) {
                /* @var $rrsig dnsRRSIGresult */
                if ($rrsig->getTypeCovered() === 'SOA') {
                    $rr[$ns] = $rrsig;
                }
            }
            $result2 = $dns->Query($domainname, 'DNSKEY');
            if ($result2->getResourceResultCount() === 0) {
                throw new dnsException("No DNSKEY records found on " . $ns . " for domain name " . $domainname);
            }
            $ds = $result2->getResourceResults();
            foreach ($ds as $childkey) {
                /* @var $childkey dnsDNSKEYresult */
                if ($childkey->getSep()) {
                    $dnskey[$ns] = $childkey;
                }
            }
            if (!isset($rr[$ns]) || !isset($dnskey[$ns])) {
                throw new dnsException("No matching DNSKEY record found on " . $ns . " for " . $domainname);
            }
            validateRRSIG($domainname, $rr[$ns], $ds);
            validateDNSKEY($domainname, $dnskey[$ns], $parentkeys);
        }
    }
    return true;
}

// Define additional functions for compatibility here
