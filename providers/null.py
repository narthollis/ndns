'''
This is a generic provider object indended to be subclassed.

It is not useful for actual work
'''

class NullProvider:
    
    def __init__(self):
        self.filters = [] 
    
    def getZones(self, clientaddress):
        return []
    
    def getNameservers(self, zone):
        return []
    
    def getResponse(self, query, zone, qtype, qclass, clientaddress):
        return (None,None)
    
    def getFilters(self):
        return self.filters
    
    def addFilter(self, f):
        self.filters.append(f)