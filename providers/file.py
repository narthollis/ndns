
import dns.name
import dns.zone
import dns.message

"""
This is a very basic dns provider that reads a zone file and
loads it into memory. The initial implemtation only supports
SOA, NS, A, AAAA, CNAME, MX and TXT records.
"""


class FileProvider:
    def __init__(self, file, zone):
        print (file, zone)
        self.zone = dns.name.from_text(zone)
        self.data = dns.zone.from_file(file, zone)

        self.filters = []

    def getZones(self, clientaddress):
        print(self.zone)
        return [self.zone]

    def getResponse(self, request, clientaddress):
        response = dns.message.make_response(request)

        for question in response.question:
            rdataset = self.data.find_rdataset(question.name, question.rdtype)
            rrset = response.find_rrset(
                response.answer,
                question.name,
                rdataset.rdclass,
                rdataset.rdtype,
                rdataset.covers,
                None,
                True
            )

            import types
            for item in rdataset:
                print(type(item))
                for key in dir(item):
                    i = item.__getattribute__(key)
                    if isinstance(type(i), types.MethodType):
                        continue
                    print (key, ':', i)
                rrset.add(item)

        return response

    def getFilters(self):
        return self.filters

    def addFilter(self, dnsfilter):
        self.filters.append(dnsfilter)
