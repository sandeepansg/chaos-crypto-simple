"""
Simplified Feistel cipher implementation using dynamically generated S-boxes.
"""
import os
import hashlib
from chebyshev.security import SecurityParams


class FeistelCipher:
    """
    Simplified implementation of a Feistel cipher with dynamically generated S-boxes.
    
    This cipher uses a balanced Feistel network structure with configurable rounds
    and block sizes. It supports CBC mode encryption with PKCS#7 padding.
    """

    def __init__(self, sbox, rounds=None, block_size=None):
        """
        Initialize the Feistel cipher.

        Args:
            sbox: The S-box for substitution operations
            rounds: Number of rounds (default is determined by SecurityParams)
            block_size: Size of each block in bytes (default is determined by SecurityParams)
        """
        # Validate and adjust parameters to ensure security
        validated_params = SecurityParams.validate_feistel_params(rounds, block_size)
        self.rounds = validated_params["rounds"]
        self.block_size = validated_params["block_size"]
        
        # Ensure block size is even for proper splitting
        self.half_block_size = self.block_size // 2
        
        self.sbox = sbox
        self.sbox_size = len(sbox)
        
    def _pad_data(self, data):
        """
        Pad data to be a multiple of block_size using PKCS#7 padding.
        """
        padding_len = self.block_size - (len(data) % self.block_size)
        if padding_len == 0:
            padding_len = self.block_size  # Full padding block if already aligned
            
        padding = bytes([padding_len] * padding_len)
        return data + padding
        
    def _unpad_data(self, data):
        """
        Remove PKCS#7 padding from data.
        """
        if not data:
            return b''
            
        padding_len = data[-1]
        if padding_len > self.block_size or padding_len == 0:
            raise ValueError("Invalid padding length")
            
        return data[:-padding_len]
    
    def _generate_subkeys(self, key):
        """
        Generate round subkeys from the main key.
        """
        subkeys = []
        for i in range(self.rounds):
            h = hashlib.sha256()
            h.update(key + str(i).encode())
            # Use hash output as round key, repeat if needed to match half_block_size
            digest = h.digest()
            round_key = digest * (self.half_block_size // len(digest) + 1)
            subkeys.append(round_key[:self.half_block_size])
                
        return subkeys
    
    def _round_function(self, half_block, subkey):
        """
        Feistel round function F that provides confusion and diffusion.
        """
        # Create a mutable copy of the half block
        result = bytearray(len(half_block))
        
        # XOR with subkey
        for i in range(len(half_block)):
            result[i] = half_block[i] ^ subkey[i % len(subkey)]
            
        # Apply S-box substitution
        for i in range(len(result)):
            index = result[i] % self.sbox_size
            result[i] = self.sbox[index] & 0xFF
            
        # Simple diffusion function
        mixed = bytearray(len(result))
        for i in range(len(result)):
            # Rotate bits left by 1
            mixed[i] = ((result[i] << 1) | (result[i] >> 7)) & 0xFF
                
        return bytes(mixed)
        
    def _process_block(self, block, subkeys, encrypt=True):
        """
        Process a single block through the Feistel network.
        """
        # Split the block into left and right halves
        half_size = len(block) // 2
        L = bytearray(block[:half_size])
        R = bytearray(block[half_size:])
        
        # Apply Feistel rounds
        round_keys = subkeys if encrypt else reversed(subkeys)
        for subkey in round_keys:
            # Apply the round function to the right half
            F_output = self._round_function(bytes(R), subkey)
            
            # XOR the left half with the round function output
            L_new = bytearray(len(L))
            for i in range(len(L)):
                L_new[i] = L[i] ^ F_output[i % len(F_output)]
                
            # Swap L and R for next round
            L, R = R, L_new
            
        # Final swap (undo the last swap that occurred in the loop)
        return bytes(R) + bytes(L)
    
    def encrypt(self, plaintext, key=None):
        """
        Encrypt plaintext using the Feistel cipher in CBC mode with IV.
        """
        # Generate a random IV
        iv = os.urandom(self.block_size)
        
        # Use S-box as key if none provided
        if key is None:
            key_bytes = bytearray(32)
            for i in range(min(32, self.sbox_size)):
                key_bytes[i] = self.sbox[i] % 256
            key = bytes(key_bytes)
            
        # Generate round subkeys
        subkeys = self._generate_subkeys(key)
        
        # Pad the plaintext
        padded_plaintext = self._pad_data(plaintext)
        
        # Process each block in CBC mode
        blocks = [padded_plaintext[i:i+self.block_size] 
                 for i in range(0, len(padded_plaintext), self.block_size)]
        
        # First block XORed with IV
        prev_block = iv
        ciphertext_blocks = []
        
        for block in blocks:
            # XOR with previous ciphertext block (or IV for first block)
            xored_block = bytearray(self.block_size)
            for i in range(self.block_size):
                xored_block[i] = block[i] ^ prev_block[i]
                
            # Process through Feistel network
            encrypted_block = self._process_block(bytes(xored_block), subkeys, encrypt=True)
            ciphertext_blocks.append(encrypted_block)
            prev_block = encrypted_block
            
        # Prepend the IV to the ciphertext
        return iv + b''.join(ciphertext_blocks)
    
    def decrypt(self, ciphertext, key=None):
        """
        Decrypt ciphertext using the Feistel cipher in CBC mode.
        """
        # Check if ciphertext is long enough to contain IV
        if len(ciphertext) < self.block_size:
            raise ValueError(f"Ciphertext too short, must be at least {self.block_size} bytes")
            
        # Extract IV
        iv = ciphertext[:self.block_size]
        ciphertext = ciphertext[self.block_size:]
        
        # Handle empty ciphertext after IV
        if not ciphertext:
            return b''
            
        # Use S-box as key if none provided
        if key is None:
            key_bytes = bytearray(32)
            for i in range(min(32, self.sbox_size)):
                key_bytes[i] = self.sbox[i] % 256
            key = bytes(key_bytes)
            
        # Generate round subkeys
        subkeys = self._generate_subkeys(key)
        
        # Process each block in CBC mode
        blocks = [ciphertext[i:i+self.block_size] 
                 for i in range(0, len(ciphertext), self.block_size)]
        
        plaintext_blocks = []
        prev_block = iv
        
        for block in blocks:
            # Process through Feistel network (reverse order for decryption)
            decrypted_block = self._process_block(block, subkeys, encrypt=False)
            
            # XOR with previous ciphertext block (or IV for first block)
            plaintext_block = bytearray(len(decrypted_block))
            for i in range(len(decrypted_block)):
                plaintext_block[i] = decrypted_block[i] ^ prev_block[i % len(prev_block)]
                
            plaintext_blocks.append(bytes(plaintext_block))
            prev_block = block
            
        # Combine blocks and remove padding
        try:
            return self._unpad_data(b''.join(plaintext_blocks))
        except ValueError:
            # Handle padding errors gracefully
            return b''.join(plaintext_blocks)
            
    def get_cipher_info(self):
        """
        Get information about the cipher configuration.
        """
        return {
            "rounds": self.rounds,
            "block_size": self.block_size,
            "sbox_size": self.sbox_size
        }
