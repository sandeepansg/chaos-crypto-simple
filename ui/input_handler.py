"""
Input handler for the Chebyshev cryptosystem.
Handles all user input operations.
"""
from chebyshev.security import SecurityParams


class InputHandler:
    """Handles user inputs and validation."""

    @staticmethod
    def get_private_key_length():
        """Get private key length from user input."""
        min_val = SecurityParams.MIN_PRIVATE_BITS
        max_val = SecurityParams.MAX_PRIVATE_BITS
        default_val = SecurityParams.DEFAULT_PRIVATE_BITS
        
        print(f"Private key length options: min={min_val}, max={max_val}, default={default_val}")
        private_input = input(f"Enter private key length in bits [{min_val}-{max_val}, default={default_val}]: ")
        
        if not private_input.strip():
            return default_val  # Return the default value

        try:
            private_bits = int(private_input)
            if private_bits < min_val:
                print(f"Warning: Value too small. Using minimum value of {min_val} bits for security")
                return min_val
            elif private_bits > max_val:
                print(f"Warning: Value too large. Using maximum value of {max_val} bits for performance")
                return max_val
            return private_bits
        except ValueError:
            print(f"Invalid input. Using default value of {default_val}")
            return default_val

    @staticmethod
    def get_feistel_params():
        """Get Feistel cipher parameters from user input."""
        print("\nFeistel Cipher Configuration")
        print("-" * 30)
        
        # Get rounds
        min_rounds = SecurityParams.MIN_FEISTEL_ROUNDS
        default_rounds = SecurityParams.DEFAULT_FEISTEL_ROUNDS
        print(f"Feistel rounds options: min={min_rounds}, default={default_rounds}")
        rounds_input = input(f"Enter number of Feistel rounds [min={min_rounds}, default={default_rounds}]: ")
        
        rounds = default_rounds
        if rounds_input.strip():
            try:
                input_val = int(rounds_input)
                if input_val < min_rounds:
                    print(f"Warning: Value too small. Using minimum of {min_rounds} rounds")
                    rounds = min_rounds
                else:
                    rounds = input_val
            except ValueError:
                print(f"Invalid input. Using default of {default_rounds} rounds")
                
        # Get block size
        min_block = SecurityParams.MIN_BLOCK_SIZE
        max_block = SecurityParams.MAX_BLOCK_SIZE
        default_block = SecurityParams.DEFAULT_BLOCK_SIZE
        print(f"Block size options: min={min_block}, max={max_block}, default={default_block} bytes")
        block_input = input(f"Enter block size in bytes [{min_block}-{max_block}, default={default_block}]: ")
        
        block_size = default_block
        if block_input.strip():
            try:
                input_val = int(block_input)
                if input_val < min_block:
                    print(f"Warning: Value too small. Using minimum of {min_block} bytes")
                    block_size = min_block
                elif input_val > max_block:
                    print(f"Warning: Value too large. Using maximum of {max_block} bytes")
                    block_size = max_block
                else:
                    block_size = input_val
            except ValueError:
                print(f"Invalid input. Using default of {default_block} bytes")
                
        return rounds, block_size
        
    @staticmethod
    def get_sbox_params():
        """Get S-box parameters from user input."""
        print("\nS-Box Configuration")
        print("-" * 30)
        
        min_size = SecurityParams.MIN_SBOX_SIZE
        max_size = SecurityParams.MAX_SBOX_SIZE
        default_size = SecurityParams.DEFAULT_SBOX_SIZE
        
        print(f"S-box size options: min={min_size}, max={max_size}, default={default_size}")
        size_input = input(f"Enter S-box size [{min_size}-{max_size}, default={default_size}]: ")
        
        box_size = default_size
        if size_input.strip():
            try:
                input_val = int(size_input)
                if input_val < min_size:
                    print(f"Warning: Value too small. Using minimum of {min_size}")
                    box_size = min_size
                elif input_val > max_size:
                    print(f"Warning: Value too large. Using maximum of {max_size}")
                    box_size = max_size
                else:
                    box_size = input_val
            except ValueError:
                print(f"Invalid input. Using default of {default_size}")
                
        return box_size

    @staticmethod
    def get_entropy():
        """Get optional entropy for key generation."""
        return input("Enter text for additional entropy (optional): ")

    @staticmethod
    def get_sample_message():
        """Get a sample message to encrypt."""
        default_message = "This is a secure message exchanged using Chebyshev polynomials!"
        message = input(f"Enter a message to encrypt [default: '{default_message}']: ")
        return message.strip() if message.strip() else default_message
