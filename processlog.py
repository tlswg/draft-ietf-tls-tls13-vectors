#!/usr/bin/env python
# This takes the output from NSS (SSLTRACE=10 is fine) and produces markdown.
# That markdown should be roughly readable.

import codecs
import fileinput
import os
import re
import sys

handshake_number = 0
report_handshake = 1

def log(msg=''):
    """Write log messages to file descriptor 3 for the first handshake and 4 for
    the second."""
    os.write(2 + handshake_number, msg + '\n')

def warning(msg):
    warning.count += 1
    sys.stderr.write('>>>Warning<<< %s\n' % msg)
warning.count = 0

class PeerRole:
    """ PeerRole tracks which peer is which based on the pointer value that is logged. """

    def __init__(self):
        self.reset()

    def reset(self):
        self.roles = {}
        self.pending = ('client', 'server')

    def report(self, role):
        log('{%s}' % role)

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

class HandleConnecting:
    # This only latches on the client resetting so that we count just once
    pattern = re.compile('client: Changing state from INIT to CONNECTING')

    def __init__(self, m):
        global handshake_number
        handshake_number += 1
        roles.reset()

    def handle(self, line):
        return True

    def report(self):
        pass

class HandleHandshake:
    """ HandleHandshake tracks handshake messages.  It also assigns roles. """
    pattern = re.compile('\d+: SSL3\[(-?\d+)\]: append handshake header: type ([a-z_]+) ')
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
        log(': send a %s handshake message' % self.snake_to_camel(self.message))

hex_encoder = codecs.getencoder('hex')
hex_decoder = codecs.getdecoder('hex')

def binary_pattern(text, socket=False):
    if socket:
        return re.compile('\d+: SSL\[(-?\d+)\]: %s \[Len: (\d+)\]' % text)
    return re.compile('\d+: SSL: %s \[Len: (\d+)\]' % text)

class BinaryReader:
    value_pattern = re.compile('   (?:[\da-f]{2} ){1,16} ')

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

        self.value += hex_decoder(m.group(0).replace(' ', ''))[0]
        return False

    def hex(self, b):
        h = hex_encoder(b)[0].decode('ascii')
        r = ''
        for i in list(range(0, len(h), 16)):
            if r != '':
                r += ' '
            r += h[i:i+16]
        return r

    def report(self, label, indent=1):
        ws = ' ' * 2 * indent
        log('%s%s (%d octets):' % (ws, label, len(self.value)))
        if len(self.value) == 0:
            log('%s: (empty)' % ws)
        colon = ':'
        for i in list(range(0, len(self.value), 32)):
            log('%s%s %s' % (ws, colon, self.hex(self.value[i:i+32])))
            colon = ' '
        log()

class HandleRecord:
    pattern = binary_pattern('(Send record \(plain text\)|send \(encrypted\) record data:)', socket=True)

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.cleartext = m.group(2).find('enc') < 0
        self.binary = BinaryReader(m)

    def handle(self, line):
        return self.binary.handle(line)

    def report(self):
        if self.cleartext:
            roles.report(self.role)
            log(': send record:')
            log()
            label = 'cleartext'
        else:
            label = 'ciphertext'
        self.binary.report(label)

class HandlePrivateKey:
    pattern = re.compile('\d+: SSL\[(-?\d+)\]: Create ECDH ephemeral key (\d+)')
    key_pattern = binary_pattern('(Public|Private) Key', socket=True)
    group_name = {23: 'P-256', 29: 'x25519'}

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.group = int(m.group(2), base=10)
        self.reader = None
        self.keys = {}

    def handle(self, line):
        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False
            self.reader = None

        m = self.key_pattern.match(line)
        if m is None:
            return True

        k = m.group(2).lower()
        if k in self.keys:
            warning('duplicate key %s' % k)
            return True

        self.reader = BinaryReader(m)
        self.keys[k] = self.reader
        return False

    def report(self):
        roles.report(self.role)
        log(': create an ephemeral %s key pair:' % self.group_name[self.group])
        log()
        if 'private' in self.keys:
            self.keys['private'].report('private key')
        else:
            warning('no private key')
        if 'public' in self.keys:
            self.keys['public'].report('public key')
        else:
            warning('no public key')

class DeduplicateValues:
    def __init__(self):
        self.secrets = {}

    def strip(self, x):
        return [[i[0], i[1].value] for i in x]

    def match(self, role, values):
        """Save a set of values and report which role generated them, if any."""
        for k in self.secrets.keys():
            if self.strip(self.secrets[k]) == self.strip(values):
                return k
        self.secrets[role] = values
        return None

class HandleExtractSecret:
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: compute (early|handshake|master) secrets? \((server|client)\)')
    extract_patterns = [['salt', binary_pattern('HKDF Extract: IKM1/Salt')],
                        ['ikm', binary_pattern('HKDF Extract: IKM2')],
                        ['secret', binary_pattern('HKDF Extract')]]
    dedupe = DeduplicateValues()

    def __init__(self, m):
        self.role = roles.commit(m.group(1), m.group(3))
        self.label = m.group(2)
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
            log(line)
            warning('no %s for extract secret' % n)
            return True

        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        msg = 'extract secret "%s"' % self.label
        dupe = self.dedupe.match(self.role, self.values)
        if dupe is not None:
            log(': %s (same as %s)' % (msg, dupe))
            return
        log(': %s:' % msg)
        log()
        for (n, v) in self.values:
            v.report(n)

class HandleHkdf:
    hkdf_patterns = [['ignore', re.compile('HKDF Expand: label=\[TLS 1\.3, \] \+ \'[\w, ]+\',requested length=\d+')],
                     ['PRK', binary_pattern('PRK')],
                     ['handshake hash', binary_pattern('Hash')],
                     ['info', binary_pattern('Info')],
                     ['output', binary_pattern('Derived key')]]
    message_pattern = binary_pattern('Handshake hash computed over saved messages')
    dedupe = DeduplicateValues()

    def __init__(self):
        self.values = []
        self.reader = None

    def handle(self, line):
        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False

        if len(self.values) == len(self.hkdf_patterns):
            del self.values[0] # ignore
            return True

        (n, p) = self.hkdf_patterns[len(self.values)]
        m = p.match(line)
        if m is None:
            # Sometimes we get an extra blob inserted, we need to read that, but
            # not save it or anything like that.
            m = self.message_pattern.match(line)
            if m is not None:
                self.reader = BinaryReader(m)
                return False
            warning(line)
            warning('no %s for %s' % (n, self.name))
            return True
        if n == 'ignore':
            self.values.append(True)
            return False
        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        if self.label is not None:
            msg = '%s "%s"' % (self.name, self.label)
        else:
            msg = self.name
        dupe = self.dedupe.match(self.role, self.values)
        if dupe is not None:
            log(': %s (same as %s)' % (msg, dupe))
            return
        log(': %s:' % msg)
        log()
        for (n, v) in self.values:
            v.report(n)

class HandleDeriveSecret(HandleHkdf):
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: deriving secret \'([\w ]+)\'')
    name = 'derive secret'

    def __init__(self, m):
        HandleHkdf.__init__(self)
        self.role = roles.lookup(m.group(1))
        self.label = m.group(2)

class HandleFinished(HandleHkdf):
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: (client|server) calculate finished')
    name = 'calculate finished'
    label = None
    handshake_hash_pattern = binary_pattern('Handshake hash', socket=True)

    def __init__(self, m):
        HandleHkdf.__init__(self)
        self.role = roles.lookup(m.group(1))
        self.handshake_hash = None

    def handle(self, line):
        if self.handshake_hash is None:
            m = self.handshake_hash_pattern.match(line)
            if m is None:
                warning(line)
                warning('no handshake hash for finished calculation')
                return True
            self.handshake_hash = BinaryReader(m)
            self.reader = self.handshake_hash
            return False
        return HandleHkdf.handle(self, line)

class HandleTrafficKeys:
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: deriving (read|write) traffic keys phase=\'([\w ]+)\'')
    dedupe = DeduplicateValues()

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.direction = m.group(2)
        self.label = m.group(3)
        self.key_values = []
        self.iv_values = []
        self.values = self.key_values
        self.reader = None

    def handle(self, line):
        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False

        if len(self.values) == len(HandleHkdf.hkdf_patterns):
            del self.values[2] # hash
            del self.values[0] # ignore
            if self.values is self.key_values:
                self.values = self.iv_values
            else:
                return True

        (n, p) = HandleHkdf.hkdf_patterns[len(self.values)]
        m = p.match(line)
        if m is None:
            log(line)
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
        msg = 'derive %s traffic keys using label "%s"' % (self.direction, self.label)
        dupe = self.dedupe.match('%s %s traffic keys' % (self.role, self.direction), self.values)
        if dupe is not None:
            log(': %s (same as %s)' % (msg, dupe))
            return
        log(': %s:' % msg)
        log()
        if self.key_values[0][1].value != self.iv_values[0][1].value:
            warning('key and iv have different PRK')
        self.key_values[0][1].report('PRK')
        for (n, v) in self.key_values[1:]:
            v.report('key ' + n)
        for (n, v) in self.iv_values[1:]:
            v.report('iv ' + n)


handlers = [HandleConnecting,
            HandleHandshake,
            HandleRecord,
            HandlePrivateKey,
            HandleExtractSecret,
            HandleDeriveSecret,
            HandleFinished,
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
            log()
            handler.report()

        handler = pick_handler(line)

if __name__ == '__main__':
    main()
    exit(warning.count)
