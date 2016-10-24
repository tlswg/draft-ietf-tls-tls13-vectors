#!/usr/bin/env python3
# This takes the output from NSS (SSLTRACE=10 is fine) and produces markdown.
# That markdown should be roughly readable.

import codecs
import fileinput
import re

group_name = {29: 'x25519'}

def warning(msg):
    warning.count += 1
    print('>>>Warning<<< %s' % msg)
warning.count = 0

class PeerRole:
    """ PeerRole tracks which peer is which based on the pointer value that is logged. """
    roles = {}

    def __init__(self):
        # Fall back on these if we haven't got good information
        self.pending = ('client', 'server')

    def report(self, role):
        print('{%s}' % role)

    def lookup(self, ptr):
        if ptr not in self.roles:
            return self.pending[0]
        return self.roles[ptr]

    def commit(self, ptr, role):
        if ptr in self.roles and self.roles[ptr] != role:
            warning('setting %s to %s, already %s' %
                    (ptr, role, self.roles[ptr]))
            return '<error>'
        if len(self.pending) > 0 and self.pending[0] == role:
            self.pending = self.pending[1:]
        self.roles[ptr] = role
        return role
# |roles| tracks which fd pointer matches which role (client/server)
roles = PeerRole()

class HandleHandshake:
    """ HandleHandshake tracks handshake messages.  It also assigns roles. """
    pattern = re.compile('\d+: SSL3\[(\d+)\]: append handshake header: type ([a-z_]+) ')
    message_role = {'client_hello': 'client', 'server_hello': 'server'}

    def __init__(self, m):
        self.message = m.group(2)
        if self.message in self.message_role:
            self.role = roles.commit(m.group(1), self.message_role[self.message])
        else:
            self.role = roles.lookup(m.group(1))

    def handle(self, line):
        return True

    def snake_to_camel(self, s):
        return ''.join([x[0].upper() + x[1:].lower() for x in s.split('_')])

    def report(self):
        roles.report(self.role)
        print(': send a %s handshake message' % self.snake_to_camel(self.message))

hex_codec = codecs.getencoder('hex')
def hex(b):
    h = hex_codec(b)[0].decode('ascii')
    r = ''
    for i in list(range(0, len(h), 16)):
        if r != '':
            r += ' '
        r += h[i:i+16]
    return r

class BinaryReader:
    value_pattern = re.compile('   (?:[\da-f]{2} ){1,16} ')

    def pattern(text, socket=False):
        if socket:
            return re.compile('\d+: SSL\[(\d+)\]: %s \[Len: (\d+)\]' % text)
        return re.compile('\d+: SSL: %s \[Len: (\d+)\]' % text)

    def __init__(self, m):
        if m is None:
            warning('unable to find length')
            return
        self.size = int(m.groups()[-1], base=10)
        self.value = b''

    def handle(self, line):
        m = self.value_pattern.match(line)
        if m is None:
            # We have to consume a line that includes <NULL>
            if line.strip(' \r\n') == '<NULL>' and self.size == 0:
                return False
            if len(self.value) != self.size:
                warning('expected a value of size %d, got %d' %
                        (self.size, len(self.value)))
            return True

        self.value += bytes.fromhex(m.group(0).replace(' ', ''))
        return False

    def report(self, label, indent=1):
        ws = ' ' * 2 * indent
        print('%s%s (%d octets):' % (ws, label, len(self.value)))
        if len(self.value) == 0:
            print('%s: (empty)' % ws)
        colon = ':'
        for i in list(range(0, len(self.value), 32)):
            print('%s%s %s' % (ws, colon, hex(self.value[i:i+32])))
            colon = ' '
        print()

class HandleRecord:
    pattern = BinaryReader.pattern('(Send record \(plain text\)|send \(encrypted\) record data:)', socket=True)

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.cleartext = m.group(2).find('enc') < 0
        self.binary = BinaryReader(m)

    def handle(self, line):
        return self.binary.handle(line)

    def report(self):
        if self.cleartext:
            roles.report(self.role)
            print(': send record:')
            label = 'cleartext'
        else:
            label = 'ciphertext'
        print()
        self.binary.report(label)

class HandlePrivateKey:
    pattern = re.compile('\d+: SSL\[(\d+)\]: Create ECDH ephemeral key (\d+)')
    key_size = BinaryReader.pattern('(Public|Private) Key', socket=True)

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.group = int(m.group(2), base=10)
        self.reader = None
        self.public = None
        self.private = None

    def handle(self, line):
        m = self.key_size.match(line)
        if m is not None:
            k = m.group(2).lower()
            self.reader = BinaryReader(m)
            if k == 'public':
                self.public = self.reader
            elif k == 'private':
                self.private = self.reader
            else:
                warning('Unknown key type %s' % k)
                return True
            return False

        if self.reader is None:
            return True

        done = self.reader.handle(line)
        if done:
            self.reader = None
        return False

    def report(self):
        roles.report(self.role)
        print(': create an ephemeral %s key pair:' % group_name[self.group])
        print()
        if self.private is not None:
            self.private.report('private key')
        else:
            warning('no private key')
        if self.public is not None:
            self.public.report('public key')
        else:
            warning('no public key')

class HandleExtractSecret:
    pattern = re.compile('\d+: TLS13\[(\d+)\]: compute (early|handshake|master) secrets? \((server|client)\)')
    extract_patterns = [['salt', BinaryReader.pattern('HKDF Extract: IKM1/Salt')],
                        ['ikm', BinaryReader.pattern('HKDF Extract: IKM2')],
                        ['secret', BinaryReader.pattern('HKDF Extract')]]

    def __init__(self, m):
        self.role = roles.commit(m.group(1), m.group(3))
        self.type = m.group(2)
        self.values = []
        self.reader = None

    def handle(self, line):
        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False

        if len(self.values) == len(self.extract_patterns):
            return True

        (n, p) = self.extract_patterns[len(self.values)]
        m = p.match(line)
        if m is None:
            print(line)
            warning('no %s for extract secret' % n)
            return True
        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        print(': extract %s secret:' % self.type)
        print()
        for (n, v) in self.values:
            v.report(n)

hkdf_patterns = [['ignore', re.compile('HKDF Expand: label=\[TLS 1\.3, \] \+ \'[\w, ]+\',requested length=\d+')],
                 ['PRK', BinaryReader.pattern('PRK')],
                 ['hash', BinaryReader.pattern('Hash')],
                 ['info', BinaryReader.pattern('Info')],
                 ['output', BinaryReader.pattern('Derived key')]]

class HandleDeriveSecret:
    pattern = re.compile('\d+: TLS13\[(\d+)\]: deriving secret \'([\w ]+)\'')
    derive_patterns = [['handshake hash', BinaryReader.pattern('Combined handshake hash computed ')]] + \
                      hkdf_patterns

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.type = m.group(2)
        self.values = []
        self.reader = None

    def handle(self, line):
        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False

        if len(self.values) == len(self.derive_patterns):
            if self.values[0][1].value != self.values[3][1].value:
                # Compare handshake hash with hash2
                warning('handshake hash changed')
            del self.values[3] # hash (again)
            del self.values[1] # ignore
            return True

        (n, p) = self.derive_patterns[len(self.values)]
        m = p.match(line)
        if m is None:
            print(line)
            warning('no %s for derive secret' % n)
            return True
        if n == 'ignore':
            self.values.append(True)
            return False
        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        print(': derive %s:' % self.type)
        print()
        for (n, v) in self.values:
            v.report(n)

class HandleTrafficKeys:
    pattern = re.compile('\d+: TLS13\[(\d+)\]: deriving traffic keys phase=\'([\w ]+)\'')

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.type = m.group(2)
        self.key_values = []
        self.iv_values = []
        self.values = self.key_values
        self.reader = None

    def handle(self, line):
        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False

        if len(self.values) == len(hkdf_patterns):
            del self.values[2] # hash
            del self.values[0] # ignore
            if self.values is self.key_values:
                self.values = self.iv_values
            else:
                return True

        (n, p) = hkdf_patterns[len(self.values)]
        m = p.match(line)
        if m is None:
            print(line)
            warning('no %s for traffic key derivation' % n)
            return True
        if n == 'ignore':
            self.values.append(True)
            return False
        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        print(': derive traffic keys %s:' % self.type)
        print()
        if self.key_values[0][1].value != self.iv_values[0][1].value:
            warning('key and iv have different PRK')
        self.key_values[0][1].report('PRK')
        for (n, v) in self.key_values[1:]:
            v.report('key ' + n)
        for (n, v) in self.iv_values[1:]:
            v.report('iv ' + n)

handlers = [HandleHandshake,
            HandleRecord,
            HandlePrivateKey,
            HandleExtractSecret,
            HandleDeriveSecret,
            HandleTrafficKeys]
def pick_handler(line):
    for h in handlers:
        m = h.pattern.match(line)
        if m is not None:
            return h(m)
    return None

def main():
    handler = None
    for line in fileinput.input():
        if handler is not None:
            done = handler.handle(line)
            if not done:
                continue
            print()
            handler.report()

        handler = pick_handler(line)

if __name__ == '__main__':
    main()
    exit(warning.count)
