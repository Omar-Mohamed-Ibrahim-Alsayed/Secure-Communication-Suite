import hashlib

def sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode())
    hash_hex = sha256.hexdigest()
    return hash_hex

def md5_hash(data):
    md5 = hashlib.md5()
    md5.update(data.encode())
    hash_hex = md5.hexdigest()
    return hash_hex
