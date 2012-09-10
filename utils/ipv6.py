
import dns.name


def prefixToReverseName(v6prefix):
    v6bits = v6prefix.strip(':').split(':')
    v6bits = [x.rjust(4, '0') for x in v6bits]
    v6bits = list(''.join(v6bits))
    v6bits.reverse()

    return dns.name.Name(v6bits + ['ip6', 'arpa', ''])
