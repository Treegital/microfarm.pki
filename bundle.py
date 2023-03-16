import typing as t
import branding_iron.certificate
import branding_iron.keys
import branding_iron.crypto
from functools import cached_property, cache
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def colon_format(hashed: bytes) -> str:
    return ":".join((format(i, '02x') for i in hashed))


class Bundle:
    chain: t.List[x509.Certificate]  # closest parent first.
    fingerprint: str
    certificate: x509.Certificate
    private_key: t.Any

    def __init__(self,
                 certificate: x509.Certificate,
                 private_key: t.Any,
                 chain: t.Iterable[x509.Certificate]):
        self.chain = list(chain)
        self.certificate = certificate
        self.private_key = private_key
        self.fingerprint = colon_format(
            certificate.fingerprint(hashes.SHA256()))
        self.__post_init__()

    def __post_init__(self):
        pass

    @cache
    def to_pkcs12(
            self,
            friendly_name: bytes,
            password: bytes) -> bytes:
        return branding_iron.certificate.encrypt_pkcs12(
            friendly_name,
            self.certificate,
            self.private_key,
            chain=self.chain,
            password=password
        )

    @cache
    def dump_private_key(self, password: bytes) -> bytes:
        return branding_iron.keys.pem_encrypt_key(
            self.private_key, passphrase=password
        )

    @cached_property
    def pem_cert(self) -> bytes:
        return branding_iron.certificate.pem_encrypt_x509(self.certificate)

    @cached_property
    def pem_chain(self) -> bytes:
        return branding_iron.certificate.pem_encrypt_x509chain(*self.chain)

    @property
    def full_pem_chain(self) -> bytes:
        return self.pem_cert + self.pem_chain


class PKI(Bundle):

    def __post_init__(self):
        self.trust_store = branding_iron.crypto.trust_store(
            self.certificate, *self.chain
        )

    def create_certificate(
            self,
            subject: x509.Name,
            public_key,
            startdate: t.Optional[datetime] = None,
            enddate: t.Optional[datetime] = None):

        not_before = branding_iron.certificate.validity_start(startdate)
        not_after = branding_iron.certificate.validity_end(enddate)

        if not_before < self.certificate.not_valid_before:
            raise ValueError(
                "Generated certificate cannot be valid before issuer's.")
        if not_after > self.certificate.not_valid_after:
            raise ValueError(
                "Generated certificate cannot be valid after issuer's.")

        builder = branding_iron.certificate.create_cert_builder(
            subject=subject,
            public_key=public_key,
            issuer_name=self.certificate.subject,
            startdate=not_before,
            enddate=not_after,
            is_ca=False
        )

        if isinstance(self.private_key,
                      branding_iron.keys.PrivateKeyNoSignAlgorithm):
            algorithm = None
        else:
            algorithm = hashes.SHA256()

        return builder.sign(
            private_key=self.private_key,
            algorithm=algorithm
        )

    def create_bundle(
            self,
            subject: x509.Name,
            startdate: t.Optional[datetime] = None,
            enddate: t.Optional[datetime] = None) -> Bundle:
        private_key = branding_iron.keys.new_rsa_key()
        public_key = private_key.public_key()
        certificate = self.create_certificate(subject, public_key)
        return Bundle(certificate, private_key, [self.certificate, *self.chain])

    def verify_certificate(self, cert: x509.Certificate):
        return branding_iron.crypto.validate_certificate(
            cert, self.trust_store
        )
