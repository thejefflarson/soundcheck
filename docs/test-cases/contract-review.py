# contract-review test case
# Mode 3 (contract-review) should find the contract-mismatch bug here: a
# "trust-anchor confusion" pattern modeled on the Botan GHSA-v782-6fq4-q827
# (CVE-2026-34580) bug.
#
# A single-pass static review (mode 2 / security-review) reads
# `certificate_known` and `validate_chain` in isolation and sees no issue.
# The bug only resolves when you observe that the validator SHORT-CIRCUITS
# as soon as `certificate_known` returns true — and `certificate_known`
# returns true on subject-name match, not identity.
#
# This is the class contract-review is built to catch.

class Certificate:
    def __init__(self, subject_dn, public_key, serial):
        self.subject_dn = subject_dn
        self.public_key = public_key
        self.serial = serial

    def __eq__(self, other):
        return (self.subject_dn == other.subject_dn
                and self.public_key == other.public_key
                and self.serial == other.serial)


class CertificateStore:
    def __init__(self):
        self.trusted = []  # list[Certificate]

    def add_trusted_root(self, cert):
        self.trusted.append(cert)

    # Buggy helper: name implies "is this cert known to the store?" but
    # the body returns true on subject-DN match alone, ignoring public_key
    # and serial. A caller that uses this to short-circuit trust-anchor
    # validation is exploitable.
    def certificate_known(self, cert):
        for trusted_cert in self.trusted:
            if trusted_cert.subject_dn == cert.subject_dn:
                return True
        return False

    def trust_anchor_for(self, cert):
        for trusted_cert in self.trusted:
            if trusted_cert == cert:
                return trusted_cert
        return None


def validate_chain(end_entity, intermediates, store):
    """Validate a certificate chain ending at a trusted root."""
    # The bug: this short-circuits as soon as `certificate_known` returns
    # true, treating the candidate as a trust anchor — but the helper only
    # checks subject DN. An attacker who presents a cert whose subject DN
    # matches any trusted root gets that cert treated as a root.
    for candidate in [end_entity] + intermediates:
        if store.certificate_known(candidate):
            return True

    anchor = store.trust_anchor_for(end_entity)
    return anchor is not None


def attacker_scenario(store, real_root):
    # Attacker forges a cert with the same subject DN as a trusted root
    # but their own public key and a chosen serial. validate_chain accepts
    # it as a trust anchor.
    forged = Certificate(
        subject_dn=real_root.subject_dn,
        public_key="ATTACKER_PUBLIC_KEY",
        serial="ATTACKER_SERIAL",
    )
    return validate_chain(forged, [], store)
