import base64
import binascii
import collections
import hashlib
import io
import struct

import stem.prereq
import stem.util.connection
import stem.util.str_tools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from stem.descriptor import (
  PGP_BLOCK_END,
  Descriptor,
  _descriptor_content,
  _descriptor_components,
  _read_until_keywords,
  _bytes_for_block,
  _value,
  _parse_simple_line,
  _parse_timestamp_line,
  _parse_key_block,
  _random_date,
  _random_crypto_blob,
)

if stem.prereq._is_lru_cache_available():
  from functools import lru_cache
else:
  from stem.util.lru_cache import lru_cache

REQUIRED_FIELDS = {
    'hs-descriptor',
    'descriptor-lifetime',
    'descriptor-signing-key-cert',
    'revision-counter',
    'superencrypted',
    'signature',
}


INTRODUCTION_POINTS_ATTR = {
    'link_specifier': None,
    'onion_key': None,
    'auth_key': None,
    'enc_key': None,
    'enc_key_cert': None,
    'legacy_key': None,
    'legacy_key_cert': None,
}

# introduction-point fields that can only appear once

SINGLE_INTRODUCTION_POINT_FIELDS = [
    'introduction-point',
    'onion-key',
    'auth-key',
    'enc-key',
    'enc-key-cert',
    'legacy-key',
    'legacy-key-cert',
]

class IntroductionPoints(collections.namedtuple('IntroductionPoints', INTRODUCTION_POINTS_ATTR.keys())):
    pass


def _parse_file(descriptor_file, validate = False, onion_address = None, **kwargs):
  while True:
    descriptor_content = _read_until_keywords('signature', descriptor_file)

    # we've reached the 'signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    descriptor_content += _read_until_keywords(block_end_prefix, descriptor_file, True)

    if descriptor_content:
      if descriptor_content[0].startswith(b'@type'):
        descriptor_content = descriptor_content[1:]

      yield Hsv3Descriptor(bytes.join(b'', descriptor_content), validate, onion_address=onion_address, **kwargs)
    else:
      break  # done parsing file


def _parse_hs_descriptor_line(descriptor, entries):
  value = _value('hs-descriptor', entries)

  if value.isdigit():
    descriptor.hs_descriptor = int(value)
  else:
    raise ValueError('version line must have a positive integer value: %s' % value)


def _parse_create2_formats_line(descriptor, entries):
  value = _value('create2-formats', entries)

  if value.isdigit():
    descriptor.create2_formats = int(value)
  else:
    raise ValueError('create2-formats line must have a positive integer value: %s' % value)


def _parse_identity_ed25519_line(descriptor, entries):
  _parse_key_block('descriptor-signing-key-cert', 'ed25519_certificate', 'ED25519 CERT')(descriptor, entries)

  if descriptor.ed25519_certificate:
    cert_lines = descriptor.ed25519_certificate.split('\n')

    if cert_lines[0] == '-----BEGIN ED25519 CERT-----' and cert_lines[-1] == '-----END ED25519 CERT-----':
      descriptor.certificate = stem.descriptor.certificate.Ed25519Certificate.parse(''.join(cert_lines[1:-1]))


def _parse_superencrypted_line(descriptor, entries):
  _, block_type, block_contents = entries['superencrypted'][0]

  if not block_contents or block_type != 'MESSAGE':
    raise ValueError("'superencrypted' should be followed by a MESSAGE block, but was a %s" % block_type)

  descriptor.superencrypted_encoded = block_contents

  try:
    descriptor.introduction_points_content = _bytes_for_block(block_contents)
  except TypeError:
    raise ValueError("'introduction-points' isn't base64 encoded content:\n%s" % block_contents)

  descriptor.introduction_points_salt = descriptor.introduction_points_content[:16]
  descriptor.introduction_points_encrypted = descriptor.introduction_points_content[16:-32]
  descriptor.introduction_points_mac = descriptor.introduction_points_content[-32:]




def _parse_hs_descriptor_lifetime(descriptor, entries):
  value = _value('descriptor-lifetime', entries)

  if value.isdigit():
    descriptor.descriptor_lifetime = int(value)
  else:
    raise ValueError('descriptor-lifetime line must have a positive integer value: %s' % value)


def _parse_revision_counter(descriptor, entries):
  value = _value('revision-counter', entries)

  if value.isdigit():
    descriptor.revision_counter = int(value)
  else:
    raise ValueError('revision-counter line must have a positive integer value: %s' % value)


_parse_signature = _parse_simple_line('signature', 'signature')


class Hsv3Descriptor(Descriptor):
  """
  """

  TYPE_ANNOTATION_NAME = 'hsv3-descriptor'

  ATTRIBUTES = {
    'hs_descriptor': (None, _parse_hs_descriptor_line),
    'descriptor_lifetime': (None, _parse_hs_descriptor_lifetime),
    'descriptor_signing_key_cert': (None, _parse_identity_ed25519_line),
    'revision_counter': (None, _parse_revision_counter),
    'superencrypted_encoded': (None, _parse_superencrypted_line),
    'create2-formats': (None, _parse_create2_formats_line),
    'signature': (None, _parse_signature),
  }

  PARSER_FOR_LINE = {
    'hs-descriptor': _parse_hs_descriptor_line,
    'descriptor-lifetime': _parse_hs_descriptor_lifetime,
    'descriptor-signing-key-cert': _parse_identity_ed25519_line,
    'revision-counter': _parse_revision_counter,
    'superencrypted': _parse_superencrypted_line,
    'create2-formats': _parse_create2_formats_line,
    'signature': _parse_signature,
  }

  def __init__(self, raw_contents, validate = False, skip_crypto_validation = False, onion_address = None):
    print(f"FUCK: onion_address: {onion_address}")
    self.onion_address = onion_address
    super(Hsv3Descriptor, self).__init__(raw_contents, lazy_load = not validate)
    entries = _descriptor_components(raw_contents, validate, non_ascii_fields = ('introduction-points'))

    if validate:
      for keyword in REQUIRED_FIELDS:
        if keyword not in entries:
          raise ValueError("Hidden service descriptor must have a '%s' entry" % keyword)
        elif keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in a hidden service descriptor" % keyword)

      if 'hs-descriptor' != list(entries.keys())[0]:
        raise ValueError("Hidden service descriptor must start with a 'hs-descriptor' entry")
      elif 'signature' != list(entries.keys())[-1]:
        raise ValueError("Hidden service descriptor must end with a 'signature' entry")

      # print(f"### entries: {entries}")
      self._parse(entries, validate)

      if not skip_crypto_validation and stem.prereq.is_crypto_available():
        print(f"#### descriptor_signing_key_cert: {self.descriptor_signing_key_cert}")
        print(f"#### certificate: {self.certificate}")
        print(f"#### signature: {self.signature}")
        signed_digest = self.certificate.validate(self)
	# self.blinded_public_key1 = self.certificate.key			# easy to mix these up :)
	# self.blinded_public_key2 = self.certificate.extensions[0].data	# easy to mix these up :)
        # XXX does the above validate()^ do enough?
        # XXX do we need to compute and store the below digest?
        # digest_content = self._content_range('hs-descriptor ', '\nsignature ')
        # content_digest = hashlib.sha1(digest_content).hexdigest().upper()

        # if signed_digest != content_digest:
        #   raise ValueError('Decrypted digest does not match local digest (calculated: %s, local: %s)' % (signed_digest, content_digest))

        # SECRET_DATA = blinded-public-key
        # STRING_CONSTANT = "hsdir-superencrypted-data"
        # credential = H("credential" | public-identity-key)
        # subcredential = H("subcredential" | credential | blinded-public-key).
        # subcredential = H("subcredential" | H("credential" | public-identity-key) | blinded-public-key)
        # public-identity-key comes from the onion address
        # blinded-public-key comes from the cert in the descriptor
        # onion_address = base32(PUBKEY || CHECKSUM || VERSION) + ".onion"
        onion_addr_bytes = base64.b32decode(self.onion_address.upper())
        print(f"onion_addr_bytes: {onion_addr_bytes}")
        pubkey, checksum, version = struct.unpack('!32s2sb', onion_addr_bytes)
        print(f"pubkey: {pubkey}")
        print(f"checksum: {checksum}")
        print(f"version: {version}")
        # XXX verify checksum
        self.public_identity_key = pubkey
        credential = hashlib.sha3_256(b"credential" + self.public_identity_key).digest()
        subcredential1 = hashlib.sha3_256(b"subcredential" + credential + self.certificate.key).digest()
        subcredential2 = hashlib.sha3_256(b"subcredential" + credential + self.certificate.extensions[0].data).digest()
        
        print(f"subcredential1: {subcredential1}")
        print(f"subcredential2: {subcredential2}")
        # secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)
        secret_input1 = self.certificate.key + subcredential1 + struct.pack('>Q', self.revision_counter)
        secret_input2 = self.certificate.extensions[0].data + subcredential2 + struct.pack('>Q', self.revision_counter)
        print(f"secret_input1: {secret_input1}")
        print(f"secret_input2: {secret_input2}")
        kdf1 = hashlib.shake_256()
        kdf2 = hashlib.shake_256()
        kdf1.update(secret_input1 + self.introduction_points_salt + b"hsdir-superencrypted-data")
        kdf2.update(secret_input2 + self.introduction_points_salt + b"hsdir-superencrypted-data")
        keys1 = hashlib.shake_256.digest(kdf1, 32 + 16 + 32)
        keys2 = hashlib.shake_256.digest(kdf2, 32 + 16 + 32)
        print(f"keys1: {keys1}")
        print(f"keys2: {keys2}")
        # keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
        # SECRET_KEY = first S_KEY_LEN bytes of keys
        # SECRET_IV  = next S_IV_LEN bytes of keys
        # MAC_KEY    = last MAC_KEY_LEN bytes of keys
        sec_key1 = keys1[:32]
        sec_key2 = keys2[:32]
        sec_iv1 = keys1[32:32+16]
        sec_iv2 = keys2[32:32+16]
        mac_key1 = keys1[32+16:]
        mac_key2 = keys2[32+16:]
        cipher1 = Cipher(algorithms.AES(sec_key1), modes.CTR(sec_iv1), default_backend())
        cipher2 = Cipher(algorithms.AES(sec_key2), modes.CTR(sec_iv2), default_backend())
        decryptor1 = cipher1.decryptor()
        decryptor2 = cipher2.decryptor()
        decrypted1 = decryptor1.update(self.introduction_points_encrypted) + decryptor1.finalize()
        decrypted2 = decryptor2.update(self.introduction_points_encrypted) + decryptor2.finalize()
        print(f"decrypted1: {decrypted1}")
        print(f"decrypted2: {decrypted2}")
        end_index = decrypted2.find(b"\n-----END MESSAGE-----", 0)
        self.first_layer_plaintext = decrypted2[:end_index+len("\n-----END MESSAGE-----")]
        begin = self.first_layer_plaintext.find(b"\n-----BEGIN MESSAGE-----\n")
        begin += len(b"\n-----BEGIN MESSAGE-----\n")
        end = self.first_layer_plaintext.find(b"\n-----END MESSAGE-----", 0)
        self.second_layer_ciphertext_b64 = self.first_layer_plaintext[begin:end]
        self.second_layer_ciphertext = base64.b64decode(self.second_layer_ciphertext_b64)
        print(f"second_layer_ciphertext_b64: {self.second_layer_ciphertext_b64}")

        # XXX only doing non-client-auth for now
        inner_salt = self.second_layer_ciphertext[:16]
        inner_encrypted = self.second_layer_ciphertext[16:-32]
        inner_mac = self.second_layer_ciphertext[-32:]
        credential_inner = hashlib.sha3_256(b"credential" + self.public_identity_key).digest()
        subcredential_inner = hashlib.sha3_256(b"subcredential" + credential_inner + self.certificate.extensions[0].data).digest()
        secret_input_inner = self.certificate.extensions[0].data + subcredential_inner + struct.pack('>Q', self.revision_counter)
        kdf_inner = hashlib.shake_256()
        kdf_inner.update(secret_input_inner + inner_salt + b"hsdir-encrypted-data")
        keys_inner = hashlib.shake_256.digest(kdf_inner, 32 + 16 + 32)
        print(f"keys_inner: {keys_inner}")
        print(f"len(keys_inner): {len(keys_inner)}")
        sec_key_inner = keys_inner[:32]
        sec_iv_inner = keys_inner[32:32+16]
        mac_key_inner = keys_inner[32+16:]
        cipher_inner = Cipher(algorithms.AES(sec_key_inner), modes.CTR(sec_iv_inner), default_backend())
        decryptor_inner = cipher_inner.decryptor()
        self.decrypted_inner = decryptor_inner.update(inner_encrypted) + decryptor_inner.finalize()
        print(f"decrypted_inner: {self.decrypted_inner.decode()}")
    else:
      self._entries = entries

  @staticmethod
  def _parse_introduction_points(content):
    """
    Provides the parsed list of IntroductionPoints for the unencrypted content.
    """

    introduction_points = []
    content_io = io.BytesIO(content)

    while True:
      content = b''.join(_read_until_keywords('introduction-point', content_io, ignore_first = True))

      if not content:
        break  # reached the end

      attr = dict(INTRODUCTION_POINTS_ATTR)
      entries = _descriptor_components(content, False)

      for keyword, values in list(entries.items()):
        value, block_type, block_contents = values[0]
        if keyword in SINGLE_INTRODUCTION_POINT_FIELDS and len(values) > 1:
          raise ValueError("'%s' can only appear once in an introduction-point block, but appeared %i times" % (keyword, len(values)))
        elif keyword == 'introduction-point':
          attr['link_specifier'] = value
        elif keyword == 'onion-key':
          attr['onion_key'] = value
        elif keyword == 'auth-key':
          attr['auth_key'] = stem.descriptor.certificate.Ed25519Certificate.parse(
                  ''.join(block_contents.splitlines()[1:-1]))
        elif keyword == 'enc-key':
          attr['enc_key'] = value
        elif keyword == 'enc-key-cert':
          attr['enc_key_cert'] = stem.descriptor.certificate.Ed25519Certificate.parse(
                  ''.join(block_contents.splitlines()[1:-1]))
        elif keyword == 'legacy-key':
          attr['legacy_key'] = block_contents
        elif keyword == 'legacy-key-cert':
          attr['legacy_key_cert'] = block_contents

      introduction_points.append(IntroductionPoints(**attr))

    return introduction_points

  @lru_cache()
  def introduction_points(self, authentication_cookie = None):
    content = self.decrypted_inner[self.decrypted_inner.find(b'\n')+1:]
    return Hsv3Descriptor._parse_introduction_points(content)
