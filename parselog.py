#!/usr/bin/env python3

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

    def lookup(self, ptr):
        if ptr not in self.roles:
            return '<role>'
        return self.roles[ptr]
    
    def commit(self, ptr, role):
        if ptr in self.roles and self.roles[ptr] != role:
            warning('setting %s to %s, already %s' %
                    (ptr, role, self.roles[ptr]))
            return '<error>'
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

    def report(self):
        print('%s: send a %s handshake message' % (self.role, self.message))

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

    def report(self, label, indent = 0):
        print('%s%s [%d]' % (':   ' * indent, label, len(self.value)))
        colon = ':'
        for i in list(range(0, len(self.value), 64)):
            print('%s%s   %s' % (' ' * 4 * indent, colon, hex(self.value[i:i+32])))
            colon = ' '

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
            print('%s: send record:' % self.role)
            label = 'cleartext'
        else:
            label = 'ciphertext'
        self.binary.report(label, 1)

class HandlePrivateKey:
    pattern = re.compile('Create ECDH ephemeral key (\d+)')
    key_size = BinaryReader.pattern('(Public|Private) Key')
    
    def __init__(self, m):
        self.group = int(m.group(1), base=10)
        self.reader = None
        self.public = None
        self.private = None

    def handle(self, line):
        m = self.key_size.match(line)
        if m is not None:
            k = m.group(1).lower()
            self.reader = BinaryReader(m)
            if k == 'public':
                self.public = self.reader
            elif k == 'private':
                self.private = self.reader
            else:
                print(': Unknown key type %s' % k)
                return True
            return False

        if self.reader is None:
            return True

        done = self.reader.handle(line)
        if done:
            self.reader = None
        return False

    def report(self):
        print('<role>: creates an ephemeral %s key pair:' %
              group_name[self.group])
        if self.private is not None:
            self.private.report('private key', 1)
        else:
            warning('no private key')
        if self.public is not None:
            self.public.report('public key', 1)
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
        print('%s: extract %s secret:' % (self.role, self.type))
        for (n, v) in self.values:
            v.report(n, 1)

class HandleDeriveSecret:
    pattern = re.compile('\d+: TLS13\[(\d+)\]: deriving secret \'([\w ]+)\'')
    derive_patterns = [['handshake hash', BinaryReader.pattern('Combined handshake hash computed ')],
                       ['ignore', re.compile('HKDF Expand: label=\[TLS 1\.3, \] \+ \'[\w ]+\',requested length=\d+')],
                       ['PRK', BinaryReader.pattern('PRK')],
                       ['hash2', BinaryReader.pattern('Hash')],
                       ['info', BinaryReader.pattern('Info')],
                       ['key', BinaryReader.pattern('Derived key')]]

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
            del self.values[3] # hash2
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
        print('%s: derive %s:' % (self.role, self.type))
        for (n, v) in self.values:
            v.report(n, 1)

handlers = [HandleHandshake, HandleRecord, HandlePrivateKey, HandleExtractSecret, HandleDeriveSecret]
def pick_handler(line):
    for h in handlers:
        m = h.pattern.match(line)
        if m is not None:
            return h(m)
    return None

handler = None
for line in fileinput.input():
    if handler is not None:
        done = handler.handle(line)
        if not done:
            continue
        handler.report()

    handler = pick_handler(line)

exit(warning.count)
