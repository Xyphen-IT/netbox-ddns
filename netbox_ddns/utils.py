from typing import List, Dict

import dns.rdatatype
import dns.resolver


def normalize_fqdn(dns_name: str) -> str:
    if not dns_name:
        return ''

    return dns_name.lower().rstrip('.') + '.'


def get_soa(dns_name: str) -> str:
    parts = dns_name.rstrip('.').split('.')
    for i in range(len(parts)):
        zone_name = normalize_fqdn('.'.join(parts[i:]))

        try:
            dns.resolver.query(zone_name, dns.rdatatype.SOA)
            return zone_name
        except dns.resolver.NoAnswer:
            # The name exists, but has no SOA. Continue one level further up
            continue
        except dns.resolver.NXDOMAIN as e:
            # Look for a SOA record in the authority section
            for query, response in e.responses().items():
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        return rrset.name.to_text()


def check_servers_authoritative(zone: str, nameservers: Dict[str, List[str]]) -> Dict[str, bool]:
    resolver = dns.resolver.Resolver()
    res = {}

    for ns, addr in nameservers.items():
        try:
            resolver.nameservers = [addr]
            answer = resolver.resolve(zone, dns.rdatatype.NS)
            if ns in answer.rrset.to_text():
                res[ns] = True
            else:
                res[ns] = False
        except dns.resolver.NoNameservers:
            res[ns] = False

    return res


def get_ip(address: str, family=0) -> List[str]:
    resolver = dns.resolver.Resolver()

    if family == 0:
        answer_a = [res.to_text() for res in resolver.resolve(address, dns.rdatatype.A)]
        answer_aaaa = [res.to_text() for res in resolver.resolve(address, dns.rdatatype.AAAA)]
        return answer_a + answer_aaaa
    else:
        answer = resolver.resolve(address, dns.rdatatype.AAAA if family == 6 else dns.rdatatype.A)
        return [res.to_text() for res in answer]
