#!/usr/bin/python3
"""Convert upstream --use* option values to bytes. Do not change tests."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ['PYNFS_ROOT'], 'nfs4.1'))
import use_local
import testserver
original = testserver.OptionParser.parse_args

class ByteOption(bytes):
    def __getitem__(self, key):
        value = super().__getitem__(key)
        return bytes([value]) if isinstance(key, int) else value

def parse_args(self, *args, **kwargs):
    opts, args = original(self, *args, **kwargs)
    for key, value in vars(opts).items():
        if key.startswith('use') and key != 'usefh' and isinstance(value, str):
            setattr(opts, key, ByteOption(os.fsencode(value)))
    return opts, args

testserver.OptionParser.parse_args = parse_args
if __name__ == '__main__':
    testserver.main()
