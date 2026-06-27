import hashlib
 
# Algorithms known to be cryptographically weak - blocked regardless of hashlib support
BLOCKED_ALGORITHMS = {"md5", "sha1"}
 
def hash_value(plaintext: str, algorithm: str) -> str:
    """
    Hash a plaintext string using any algorithm supported by Python's hashlib
    and return the hex digest.
 
    The algorithm parameter accepts any name recognized by hashlib.new(), such as:
        sha256, sha3_256, sha3_512, blake2b, blake2s, sha512, sha384
 
    As new algorithms are added to Python's hashlib, they become available here
    automatically with no code changes required.
 
    Raises ValueError if the algorithm is cryptographically weak (md5, sha1)
    or if hashlib does not recognize the algorithm name.
    """
    algo = algorithm.strip().lower()
 
    if algo in BLOCKED_ALGORITHMS:
        raise ValueError(
            f"Algorithm '{algorithm}' is cryptographically weak and is not permitted. "
            f"Blocked algorithms: {sorted(BLOCKED_ALGORITHMS)}"
        )
 
    try:
        h = hashlib.new(algo, plaintext.encode())
        return h.hexdigest()
    except ValueError:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported algorithms include: {sorted(hashlib.algorithms_guaranteed - BLOCKED_ALGORITHMS)}"
        )
 