# Copyright 2017-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for `Tor Ed25519 certificates
<https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt>`_, which are
used to validate the key used to sign server descriptors.

.. versionadded:: 1.6.0

**Module Overview:**

::

  Ed25519Certificate - Ed25519 signing key certificate
    | +- Ed25519CertificateV1 - version 1 Ed25519 certificate
    |      |- is_expired - checks if certificate is presently expired
    |      +- validate - validates signature of a server descriptor
    |
    +- parse - reads base64 encoded certificate data

  Ed25519Extension - extension included within an Ed25519Certificate

.. data:: CertType (enum)

  Purpose of Ed25519 certificate. As new certificate versions are added this
  enumeration will expand.

  ==============  ===========
  CertType        Description
  ==============  ===========
  **SIGNING**     signing a signing key with an identity key
  **LINK_CERT**   TLS link certificate signed with ed25519 signing key
  **AUTH**        authentication key signed with ed25519 signing key
  XXX update with hsv3 stuff
  ==============  ===========

.. data:: ExtensionType (enum)

  Recognized exception types.

  ====================  ===========
  ExtensionType         Description
  ====================  ===========
  **HAS_SIGNING_KEY**   includes key used to sign the certificate
  ====================  ===========

.. data:: ExtensionFlag (enum)

  Flags that can be assigned to Ed25519 certificate extensions.

  ======================  ===========
  ExtensionFlag           Description
  ======================  ===========
  **AFFECTS_VALIDATION**  extension affects whether the certificate is valid
  **UNKNOWN**             extension includes flags not yet recognized by stem
  ======================  ===========
"""

import base64
import binascii
import collections
import datetime
import hashlib

import stem.prereq
import stem.util.enum
import stem.util.str_tools

ED25519_HEADER_LENGTH = 40
ED25519_SIGNATURE_LENGTH = 64
ED25519_ROUTER_SIGNATURE_PREFIX = b'Tor router descriptor signature v1'
ED25519_HSV3_DESCRIPTOR_PREFIX = b'Tor onion service descriptor sig v3'

CertType = stem.util.enum.UppercaseEnum('SIGNING', 'LINK_CERT', 'AUTH', 'DESC_SIGNING', 'IP_AUTH', 'IP_ENC')
ExtensionType = stem.util.enum.Enum(('HAS_SIGNING_KEY', 4),)
ExtensionFlag = stem.util.enum.UppercaseEnum('AFFECTS_VALIDATION', 'UNKNOWN')


class Ed25519Extension(collections.namedtuple('Ed25519Extension', ['type', 'flags', 'flag_int', 'data'])):
  """
  Extension within an Ed25519 certificate.

  :var int type: extension type
  :var list flags: extension attribute flags
  :var int flag_int: integer encoding of the extension attribute flags
  :var bytes data: data the extension concerns
  """


class Ed25519Certificate(object):
  """
  Base class for an Ed25519 certificate.

  :var int version: certificate format version
  :var str encoded: base64 encoded ed25519 certificate
  """

  def __init__(self, version, encoded):
    self.version = version
    self.encoded = encoded

  @staticmethod
  def parse(content):
    """
    Parses the given base64 encoded data as an Ed25519 certificate.

    :param str content: base64 encoded certificate

    :returns: :class:`~stem.descriptor.certificate.Ed25519Certificate` subclsss
      for the given certificate

    :raises: **ValueError** if content is malformed
    """

    try:
      decoded = base64.b64decode(stem.util.str_tools._to_bytes(content))

      if not decoded:
        raise TypeError('empty')
    except (TypeError, binascii.Error) as exc:
      raise ValueError("Ed25519 certificate wasn't propoerly base64 encoded (%s):\n%s" % (exc, content))

    version = stem.util.str_tools._to_int(decoded[0:1])

    if version == 1:
      return Ed25519CertificateV1(version, content, decoded)
    else:
      raise ValueError('Ed25519 certificate is version %i. Parser presently only supports version 1.' % version)


class Ed25519CertificateV1(Ed25519Certificate):
  """
  Version 1 Ed25519 certificate, which are used for signing tor server
  descriptors.

  :var CertType type: certificate purpose
  :var datetime expiration: expiration of the certificate
  :var int key_type: format of the key
  :var bytes key: key content
  :var list extensions: :class:`~stem.descriptor.certificate.Ed25519Extension` in this certificate
  :var bytes signature: certificate signature
  """

  def __init__(self, version, encoded, decoded):
    super(Ed25519CertificateV1, self).__init__(version, encoded)

    if len(decoded) < ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH:
      raise ValueError('Ed25519 certificate was %i bytes, but should be at least %i' % (len(decoded), ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH))

    cert_type = stem.util.str_tools._to_int(decoded[1:2])

    if cert_type in (0, 1, 2, 3):
      raise ValueError('Ed25519 certificate cannot have a type of %i. This is reserved to avoid conflicts with tor CERTS cells.' % cert_type)
    elif cert_type == 4:
      self.type = CertType.SIGNING
    elif cert_type == 5:
      self.type = CertType.LINK_CERT
    elif cert_type == 6:
      self.type = CertType.AUTH
    elif cert_type == 7:
      raise ValueError('Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.')
    elif cert_type == 8:
      self.type = CertType.DESC_SIGNING  # short-term desc signing key
    elif cert_type == 9:
      self.type = CertType.IP_AUTH  # intro-point auth key
    elif cert_type == 0xb:  # XXX spec uses hex
      self.type = CertType.IP_ENC   # [0B] ed25519 key derived from the curve25519 intro point encryption key,
    else:
      raise ValueError("BUG: Ed25519 certificate type is decoded from one byte. It shouldn't be possible to have a value of %i." % cert_type)

    # expiration time is in hours since epoch
    try:
      self.expiration = datetime.datetime.utcfromtimestamp(stem.util.str_tools._to_int(decoded[2:6]) * 3600)
    except ValueError as exc:
      raise ValueError('Invalid expiration timestamp (%s): %s' % (exc, stem.util.str_tools._to_int(decoded[2:6]) * 3600))

    self.key_type = stem.util.str_tools._to_int(decoded[6:7])
    self.key = decoded[7:39]
    self.signature = decoded[-ED25519_SIGNATURE_LENGTH:]

    self.extensions = []
    extension_count = stem.util.str_tools._to_int(decoded[39:40])
    remaining_data = decoded[40:-ED25519_SIGNATURE_LENGTH]

    for i in range(extension_count):
      if len(remaining_data) < 4:
        raise ValueError('Ed25519 extension is missing header field data')

      extension_length = stem.util.str_tools._to_int(remaining_data[:2])
      extension_type = stem.util.str_tools._to_int(remaining_data[2:3])
      extension_flags = stem.util.str_tools._to_int(remaining_data[3:4])
      extension_data = remaining_data[4:4 + extension_length]

      if extension_length != len(extension_data):
        raise ValueError("Ed25519 extension is truncated. It should have %i bytes of data but there's only %i." % (extension_length, len(extension_data)))

      flags, remaining_flags = [], extension_flags

      if remaining_flags % 2 == 1:
        flags.append(ExtensionFlag.AFFECTS_VALIDATION)
        remaining_flags -= 1

      if remaining_flags:
        flags.append(ExtensionFlag.UNKNOWN)

      if extension_type == ExtensionType.HAS_SIGNING_KEY and len(extension_data) != 32:
        raise ValueError('Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was %i.' % len(extension_data))

      self.extensions.append(Ed25519Extension(extension_type, flags, extension_flags, extension_data))
      remaining_data = remaining_data[4 + extension_length:]

    if remaining_data:
      raise ValueError('Ed25519 certificate had %i bytes of unused extension data' % len(remaining_data))

  def is_expired(self):
    """
    Checks if this certificate is presently expired or not.

    :returns: **True** if the certificate has expired, **False** otherwise
    """

    return datetime.datetime.now() > self.expiration

  def validate(self, server_descriptor):
    """
    Validates our signing key and that the given descriptor content matches its
    Ed25519 signature.

    :param stem.descriptor.server_descriptor.Ed25519 server_descriptor: relay
      server descriptor to validate

    :raises:
      * **ValueError** if signing key or descriptor are invalid
      * **ImportError** if cryptography module is unavailable or ed25519 is
        unsupported
    """

    if not stem.prereq._is_crypto_ed25519_supported():
      raise ImportError('Certificate validation requires the cryptography module and ed25519 support')

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    descriptor_content = server_descriptor.get_bytes()
    signing_key = None

    print(f"### certificate: {server_descriptor.certificate}")
    print(f"### certificate.key: {server_descriptor.certificate.key}")
    print(f"### extensions: {server_descriptor.certificate.extensions}")
    if hasattr(server_descriptor, "ed25519_master_key") and server_descriptor.ed25519_master_key:
      signing_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(stem.util.str_tools._to_bytes(server_descriptor.ed25519_master_key) + b'='))
    elif server_descriptor.certificate:
      # XXX hacky
      signing_key = Ed25519PublicKey.from_public_bytes(self.extensions[0].data)
      print(f"### certificate.key: {signing_key}")
    else:
      for extension in self.extensions:
        if extension.type == ExtensionType.HAS_SIGNING_KEY:
          signing_key = Ed25519PublicKey.from_public_bytes(extension.data)
          break

    if not signing_key:
      raise ValueError('Server descriptor missing an ed25519 signing key')

    try:
      print(f"### encoded: {self.encoded}")
      signed_bytes = base64.b64decode(stem.util.str_tools._to_bytes(self.encoded))[:-ED25519_SIGNATURE_LENGTH]
      print(f"### len(signed_bytes) = {len(signed_bytes)}")
      print(f"### signed_bytes[0] = {hex(signed_bytes[0])}")
      print(f"### signed_bytes[-1] = {hex(signed_bytes[-1])}")
      signing_key.verify(self.signature, signed_bytes)
    except InvalidSignature:
      raise ValueError('Ed25519KeyCertificate signing key is invalid (Signature was forged or corrupt)')

    # ed25519 signature validates descriptor content up until the signature itself

    # XXX this is hacky. basically, i needed to add the "else" case for Hsv3Descriptors
    if type(server_descriptor).__name__ == "ServerDescriptor":
      if b'router-sig-ed25519 ' not in descriptor_content:
        raise ValueError("Descriptor doesn't have a router-sig-ed25519 entry.")

      signed_content = descriptor_content[:descriptor_content.index(b'router-sig-ed25519 ') + 19]
      descriptor_sha256_digest = hashlib.sha256(ED25519_ROUTER_SIGNATURE_PREFIX + signed_content).digest()

      missing_padding = len(server_descriptor.ed25519_signature) % 4
      signature_bytes = base64.b64decode(stem.util.str_tools._to_bytes(server_descriptor.ed25519_signature) + b'=' * missing_padding)

      try:
        verify_key = Ed25519PublicKey.from_public_bytes(self.key)
        verify_key.verify(signature_bytes, descriptor_sha256_digest)
      except InvalidSignature:
        raise ValueError('Descriptor Ed25519 certificate signature invalid (Signature was forged or corrupt)')
    else:
      if b'signature' not in descriptor_content:
        raise ValueError("Descriptor doesn't have a signature entry")

      signed_content = ED25519_HSV3_DESCRIPTOR_PREFIX + descriptor_content[:descriptor_content.index(b'signature ')]
      print(f"### signed_content: {signed_content}")
      print(f"### len(signed_content) = {len(signed_content)}")
      print(f"### signed_content[0] = {hex(signed_content[0])}")
      print(f"### signed_content[-1] = {hex(signed_content[-1])}")
      descriptor_sha256_digest = hashlib.sha256(signed_content).digest()
      print(f"### sha256(descriptor): {descriptor_sha256_digest}")

      missing_padding = len(server_descriptor.signature) % 4
      signature_bytes = base64.b64decode(stem.util.str_tools._to_bytes(server_descriptor.signature) + b'=' * missing_padding)
      try:
        # key_bytes = self.extensions[0].data
        key_bytes = self.key
        print(f"### signature_bytes: {signature_bytes}")
        print(f"### len(signature_bytes): {len(signature_bytes)}")
        print(f"### key_bytes: {key_bytes}")
        print(f"### len(key_bytes): {len(key_bytes)}")
        verify_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        print(f"### verify_key: {verify_key}")
        # XXX !!! looks like tor is signing the whole content and not a hash digest
        #verify_key.verify(signature_bytes, descriptor_sha256_digest)
        verify_key.verify(signature_bytes, signed_content)
      except InvalidSignature:
        raise ValueError('Descriptor Ed25519 certificate signature invalid (Signature was forged or corrupt)')
