

# Convenience functions for packing/unpacking to a dict for BSON representation
def load_from_dict(src, obj, attr):
    setattr(obj, attr, src[attr])


def pack_into_dict(dest, obj, attr):
    dest[attr] = getattr(obj, attr)
