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
    os.write(2 + handshake_number, (msg + '\n').encode('utf8'))

current_line_number = 0
current_line = ''

def warning(msg):
    global current_line_number
    global current_line
    warning.count += 1
    sys.stderr.write('%4d: %s' % (current_line_number, current_line))
    sys.stderr.write('Warning: %s\n' % msg)
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
    pattern = re.compile('^client: Changing state from INIT to CONNECTING')

    def __init__(self, m):
        global handshake_number
        handshake_number += 1
        roles.reset()

    def handle(self, line):
        return True

    def report(self):
        pass

hex_encoder = codecs.getencoder('hex')
hex_decoder = codecs.getdecoder('hex')

def binary_pattern(text, socket=False):
    if socket:
        return re.compile('^\d+: SSL\[(-?\d+)\]: %s \[Len: (\d+)\]' % text)
    return re.compile('^\d+: SSL: %s \[Len: (\d+)\]' % text)

def log_binary(ws, label, value):
    def hex(b):
        h = hex_encoder(b)[0].decode('ascii')
        r = ''
        for i in list(range(0, len(h), 2)):
            if r != '':
                r += ' '
            r += h[i:i+2]
        return r

    log('%s%s (%d octets):' % (ws, label, len(value)))
    if len(value) == 0:
        log('%s: (empty)' % ws)
    colon = ':'
    for i in list(range(0, len(value), 32)):
        log('%s%s %s' % (ws, colon, hex(value[i:i+32])))
        colon = ' '
    log()


class BinaryReader:
    value_pattern = re.compile('^   (?:[\da-f]{2} ){1,16} ')

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

    def report(self, label, indent=1):
        ws = ' ' * 2 * indent
        if len(self.value) == 0 and label == 'salt':
            log('%s%s:' % (ws, label))
            log('%s: (absent)' % ws)
            log()
            return
        log_binary(ws, label, self.value)


class HandleHandshake:
    """ HandleHandshake tracks handshake messages.  It also assigns roles. """
    pattern = re.compile('^\d+: SSL3\[(-?\d+)\]: append handshake header: type ([a-z_]+) ')
    message_role = {'client_hello': 'client', 'server_hello': 'server'}
    junk = re.compile('^(?:\d+: )?(?:append variable|number|data):$')
    append = binary_pattern('Append to Handshake', socket=True)
    handshake_hash_input = binary_pattern('handshake hash input:', socket=True)

    def __init__(self, m):
        self.message = m.group(2)
        if self.message in self.message_role:
            self.role = roles.commit(m.group(1), self.message_role[self.message])
        else:
            self.role = roles.lookup(m.group(1))
        self.binary = None
        self.ignore = None
        self.data = b''

    def handle(self, line):
        if self.binary is not None:
            if not self.binary.handle(line):
                return False
            self.data += self.binary.value
            self.binary = None
        elif self.ignore is not None:
            if not self.ignore.handle(line):
                return False
            self.ignore = None

        if self.junk.match(line) is not None:
            return False

        m = self.append.match(line)
        if m is not None:
            self.binary = BinaryReader(m)
            return False

        # NSS sometimes logs inputs to the handshake hash, which duplicate the
        # logged data and confuses things.  Ignore that.
        m = self.handshake_hash_input.match(line)
        if m is not None:
            self.ignore = BinaryReader(m)
            return False

        return True

    def snake_to_camel(self, s):
        return ''.join([x[0].upper() + x[1:].lower() for x in s.split('_')])

    def report(self):
        roles.report(self.role)
        msg = self.snake_to_camel(self.message)
        log(': send a %s handshake message' % msg)
        log()
        log_binary('  ', msg, self.data)


class HandleRecord:
    pattern = re.compile('^\d+: SSL3\[(-?\d+)\] SendRecord type: (\w+)')
    inner_pattern = binary_pattern('Send record \(plain text\)', socket=True)

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.binary = None
        self.type = m.group(2)

    def handle(self, line):
        if self.binary is None:
            m = self.inner_pattern.match(line)
            if m is None:
                warning('no plaintext found for send record')
                return True
            self.binary = BinaryReader(m)
            return False

        return self.binary.handle(line)

    def report(self):
        roles.report(self.role)
        log(': send %s record:' % self.type)
        log()
        self.binary.report('payload')

class HandleEncrypted:
    pattern = binary_pattern('send \(encrypted\) record data:', socket=True)

    def __init__(self, m):
        self.role = roles.lookup(m.group(1))
        self.binary = BinaryReader(m)

    def handle(self, line):
        return self.binary.handle(line)

    def report(self):
        self.binary.report('ciphertext')

class HandlePrivateKey:
    pattern = re.compile('^\d+: SSL\[(-?\d+)\]: Create ECDH ephemeral key (\d+)')
    key_pattern = binary_pattern('(Public|Private) Key', socket=True)
    group_name = {23: 'P-256', 24: 'P-384', 29: 'x25519'}

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
                if ',' in k:
                    return k[0:k.index(',')]
                return k
        self.secrets[role] = values
        return None

class HandleHkdf:
    hkdf_patterns = [['label', re.compile('HKDF Expand: label=\'([\w ]+)\',requested length=\d+')],
                     ['PRK', binary_pattern('PRK')],
                     ['hash', binary_pattern('Hash')],
                     ['info', binary_pattern('Info')],
                     ['output', binary_pattern('Derived key')]]
    message_pattern = binary_pattern('Handshake hash computed over saved messages',
                                     socket=True)
    handshake_hash_pattern = binary_pattern('Handshake hash', socket=True)
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
            if m is None:
                m = self.handshake_hash_pattern.match(line)
            if m is not None:
                self.reader = BinaryReader(m)
                return False
            warning('no %s for %s' % (n, self.name))
            return True
        if n == 'label':
            self.label = m.group(1)
            self.values.append(True)
            return False
        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        if self.label is not None:
            msg = '%s "%s"' % (self.name, self.label)
            key = '%s, %s' % (self.role, self.label)
        else:
            msg = self.name
            key = self.role
        dupe = self.dedupe.match(key, self.values)
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

    def __init__(self, m):
        HandleHkdf.__init__(self)
        self.role = roles.lookup(m.group(1))
        self.handshake_hash = None

    def handle(self, line):
        if self.handshake_hash is None:
            m = self.handshake_hash_pattern.match(line)
            if m is None:
                warning('no handshake hash for finished calculation')
                return True
            self.handshake_hash = BinaryReader(m)
            self.reader = self.handshake_hash
            return False
        return HandleHkdf.handle(self, line)

class HandleResumptionSecretServer(HandleHkdf):
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: send new session ticket message (\d+)')
    name = 'generate resumption secret'
    # Don't insist that this be run for every invocation
    run = True

    def __init__(self, m):
        HandleHkdf.__init__(self)
        self.role = roles.lookup(m.group(1))
        self.label = m.group(2)

class HandleResumptionSecretClient():
    pattern = re.compile('\d+: SSL\[(-?\d+)\]: Caching session ticket \[Len: (\d+)\]')
    # Don't insist that this be run for every invocation
    run = True

    def __init__(self, m):
        self.ticket = BinaryReader(m)
        self.ticket_done = False
        self.hkdf = HandleHkdf()
        self.hkdf.role = roles.lookup(m.group(1))
        self.hkdf.name = 'generate resumption secret'

    def handle(self, line):
        if not self.ticket_done:
            self.ticket_done = self.ticket.handle(line)
            if not self.ticket_done:
                return False
        return self.hkdf.handle(line)

    def report(self):
        self.hkdf.report()

class HandleMasterSecret:
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: compute (early|handshake|master) secrets? \((server|client)\)')
    extract_patterns = [['salt', binary_pattern('HKDF Extract: IKM1/Salt')],
                        ['IKM', binary_pattern('HKDF Extract: IKM2')],
                        ['secret', binary_pattern('HKDF Extract')]]
    dedupe = DeduplicateValues()

    def __init__(self, m):
        self.role = roles.commit(m.group(1), m.group(3))
        self.label = m.group(2)
        self.values = []
        self.reader = None
        self.derive_done = self.label == 'early'
        if not self.derive_done:
            self.derive = HandleHkdf()
            self.derive.name = 'derive secret for %s' % self.label
            self.derive.role = self.role
        else:
            self.derive = None

    def handle(self, line):
        if not self.derive_done:
            self.derive_done = self.derive.handle(line)
            if not self.derive_done:
                return False

        if self.reader is not None:
            done = self.reader.handle(line)
            if not done:
                return False

        if len(self.values) == len(self.extract_patterns):
            return True

        (n, p) = self.extract_patterns[len(self.values)]
        m = p.match(line)
        if m is None:
            warning('no %s for master secret' % n)
            return True

        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        if self.derive is not None:
            self.derive.report()
            log()
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

class HandleTrafficKeys:
    pattern = re.compile('\d+: TLS13\[(-?\d+)\]: deriving (read|write) traffic keys epoch=\d+ \(([\w ]+)\)')
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
            warning('no %s for traffic key derivation' % n)
            return True
        if n == 'label':
            self.values.append(True)
            return False
        self.reader = BinaryReader(m)
        self.values.append([n, self.reader])
        return False

    def report(self):
        roles.report(self.role)
        msg = 'derive %s traffic keys for %s' % (self.direction, self.label)
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
            HandleEncrypted,
            HandlePrivateKey,
            HandleMasterSecret,
            HandleDeriveSecret,
            HandleFinished,
            HandleResumptionSecretServer,
            HandleResumptionSecretClient,
            HandleTrafficKeys]
def pick_handler(line):
    for h in handlers:
        m = h.pattern.match(line)
        if m is not None:
            h.run = True
            return h(m)
    return None

def main():
    global current_line_number
    global current_line
    handler = None
    for line in fileinput.input():
        current_line_number += 1
        current_line = line
        if handler is not None:
            done = handler.handle(line)
            if not done:
                continue
            log()
            handler.report()

        handler = pick_handler(line)

    for h in handlers:
        if not h.run:
            warning('handler %s not run' % h)

if __name__ == '__main__':
    main()
    exit(warning.count)
