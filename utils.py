import struct

def label2str(label):
    s = struct.pack("!B", len(label))
    s += label
    return s
    
def labels2str(labels):
    s = b''
    for label in labels:
        s += label2str(label)
    s += struct.pack("!B", 0)
    return s