import typing as t
from pathlib import Path
from branding_iron import keys, pki, certificate
from branding_iron.identity import Identity
from branding_iron.crypto import pkcs7_detached_signature
from . import PKI


def data_to_file(path: t.Union[Path, str], data: bytes):
    path = Path(path)  # idempotent.
    if path.exists():
        if not path.is_file():
            raise TypeError('{path!r} should be a file.')
        else:
            print(f'Overriding existing file: {path}')
    with path.open('wb') as fd:
        fd.write(data)


def create_root_certificate(settings: dict):
    identity = Identity(**settings['identity'])
    private_key = keys.new_ed448_key()

    startdate = certificate.validity_start()
    enddate = certificate.validity_end(startdate, delta=3650)  # 10 years

    cert = pki.create_root_ca_cert(
        identity,
        private_key,
        startdate=startdate,
        enddate=enddate
    )
    return cert, private_key


def create_intermediate_certificate(settings, issuer_cert, issuer_key):
    identity = Identity(**settings['identity'])
    private_key = keys.new_ed25519_key()
    startdate = certificate.validity_start()
    enddate = certificate.validity_end(startdate, delta=1095)  # 3 years
    cert = pki.create_intermediate_ca_cert(
        identity,
        issuer_cert_subject=issuer_cert.subject,
        issuer_key=issuer_key,
        startdate=startdate,
        enddate=enddate,
        intermediate_private_key=private_key
    )
    return cert, private_key


def create_pki(settings: dict, debug: bool = False):
    root, root_key = create_root_certificate(settings['root'])
    data_to_file(
        settings['root']['cert_path'],
        certificate.pem_encrypt_x509(root)
    )
    data_to_file(
        settings['root']['key_path'],
        keys.pem_encrypt_key(
            root_key,
            settings['root']['password'].encode()
        )
    )

    inter, inter_key = create_intermediate_certificate(
        settings['intermediate'],
        root,
        root_key
    )
    data_to_file(
        settings['intermediate']['cert_path'],
        certificate.pem_encrypt_x509(inter)
    )
    data_to_file(
        settings['intermediate']['key_path'],
        keys.pem_encrypt_key(
            inter_key,
            settings['intermediate']['password'].encode()
        )
    )


def data_from_file(path: t.Union[Path, str]) -> t.Optional[bytes]:
    path = Path(path)  # idempotent.
    if not path.exists():
        raise FileNotFoundError(f'`{path}` does not exist.')

    if not path.is_file():
        raise TypeError(f'`{path}` should be a file.')

    with path.open('rb') as fd:
        data = fd.read()

    return data


def load_pki(settings):
    root_cert = certificate.pem_decrypt_x509(
        data_from_file(settings['root']['cert_path'])
    )
    intermediate_cert = certificate.pem_decrypt_x509(
        data_from_file(settings['intermediate']['cert_path'])
    )
    intermediate_key = keys.pem_decrypt_key(
        data_from_file(settings['intermediate']['key_path']),
        settings['intermediate']['password'].encode()
    )
    return PKI(intermediate_cert, intermediate_key, [root_cert])


def sign(data: bytes, cert_pem: bytes, chain_pem: bytes, privkey_pem: bytes, secret: bytes):
    key =  keys.pem_decrypt_key(privkey_pem, secret)
    cert = certificate.pem_decrypt_x509(cert_pem)
    chain = certificate.pem_decrypt_x509chain(chain_pem)
    signed = pkcs7_detached_signature(data, cert, key, chain)
    return signed
