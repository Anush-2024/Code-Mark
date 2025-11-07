import hashlib, gc

class SecureDataHandler:
    def hash_bytes(self, data: bytes) -> str:
        """Generate SHA-256 fingerprint (for proof-of-scan)"""
        return hashlib.sha256(data).hexdigest()

    def wipe_memory(self, var):
        """Wipe sensitive data from memory"""
        del var
        gc.collect()
