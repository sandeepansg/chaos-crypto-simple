"""
S-box generation from shared secrets for the Feistel cipher.
"""
import hashlib
import struct
import math
from chebyshev.security import SecurityParams


class SBoxGenerator:
    """Generates secure S-boxes from shared secrets."""

    def __init__(self, shared_secret, box_size=None):
        """Initialize with a shared secret to generate S-boxes."""
        # Validate input
        if not isinstance(shared_secret, int):
            raise TypeError("shared_secret must be an integer")

        validated_params = SecurityParams.validate_sbox_params(box_size)
        self.box_size = validated_params["box_size"]
        self.shared_secret = shared_secret
        
    def generate(self):
        """
        Generate an S-box using the shared secret as seed.
        
        Returns:
            list: An S-box mapping values 0 to (box_size-1)
        """
        # Convert shared secret to bytes
        secret_bytes = self.shared_secret.to_bytes(
            (self.shared_secret.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        # Initialize S-box with identity mapping
        sbox = list(range(self.box_size))
        
        # Calculate how many bytes we need for each index
        bytes_per_index = max(1, math.ceil(math.log2(self.box_size) / 8))
        
        # Generate key material using SHA-256
        bytes_needed = self.box_size * bytes_per_index
        chunks_needed = (bytes_needed + 31) // 32  # SHA-256 produces 32 bytes
        
        key_material = b''
        for i in range(chunks_needed):
            h = hashlib.sha256()
            h.update(secret_bytes + str(i).encode())
            key_material += h.digest()
        
        # Fisher-Yates shuffle using the key material as randomness
        for i in range(self.box_size - 1, 0, -1):
            # Extract bytes for randomness
            start_idx = i * bytes_per_index % len(key_material)
            end_idx = min(start_idx + bytes_per_index, len(key_material))
            j_bytes = key_material[start_idx:end_idx]
            
            # If we didn't get enough bytes, pad with zeros
            if len(j_bytes) < bytes_per_index:
                padding = bytes(bytes_per_index - len(j_bytes))
                j_bytes = j_bytes + padding
            
            # Convert bytes to integer
            if bytes_per_index <= 4:
                # Use struct.unpack for efficiency
                if bytes_per_index == 1:
                    j = j_bytes[0]
                elif bytes_per_index == 2:
                    j = struct.unpack('>H', j_bytes)[0]
                elif bytes_per_index == 3:
                    j = struct.unpack('>I', j_bytes + b'\x00')[0] >> 8
                else:  # bytes_per_index == 4
                    j = struct.unpack('>I', j_bytes)[0]
            else:
                # For larger values, use int.from_bytes
                j = int.from_bytes(j_bytes, byteorder='big')
            
            # Use modulo to get index in range
            j = j % (i + 1)
            
            # Swap elements
            sbox[i], sbox[j] = sbox[j], sbox[i]
            
        return sbox