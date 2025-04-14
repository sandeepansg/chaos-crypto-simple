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
        private_input = input(f"Enter private key length in bits [default={SecurityParams.DEFAULT_PRIVATE_BITS}]: ")
        if not private_input.strip():
            return SecurityParams.DEFAULT_PRIVATE_BITS  # Return the default value

        try:
            private_bits = int(private_input)
            if private_bits < SecurityParams.MIN_PRIVATE_BITS:
                print(f"Warning: Using minimum value of {SecurityParams.MIN_PRIVATE_BITS} bits for security")
                return SecurityParams.MIN_PRIVATE_BITS
            elif private_bits > SecurityParams.MAX_PRIVATE_BITS:
                print(f"Warning: Using maximum value of {SecurityParams.MAX_PRIVATE_BITS} bits for performance")
                return SecurityParams.MAX_PRIVATE_BITS
            return private_bits
        except ValueError:
            print(f"Invalid input. Using default value of {SecurityParams.DEFAULT_PRIVATE_BITS}")
            return SecurityParams.DEFAULT_PRIVATE_BITS

    @staticmethod
    def get_feistel_params():
        """Get Feistel cipher parameters from user input."""
        print("\nFeistel Cipher Configuration")
        print("-" * 30)
        
        # Get rounds
        rounds = SecurityParams.DEFAULT_FEISTEL_ROUNDS
        rounds_input = input(f"Enter number of Feistel rounds [default={SecurityParams.DEFAULT_FEISTEL_ROUNDS}]: ")
        if rounds_input.strip():
            try:
                rounds = max(int(rounds_input), SecurityParams.MIN_FEISTEL_ROUNDS)
            except ValueError:
                pass
                
        # Get block size
        block_size = SecurityParams.DEFAULT_BLOCK_SIZE
        block_input = input(f"Enter block size in bytes [default={SecurityParams.DEFAULT_BLOCK_SIZE}]: ")
        if block_input.strip():
            try:
                block_size = max(min(int(block_input), SecurityParams.MAX_BLOCK_SIZE), SecurityParams.MIN_BLOCK_SIZE)
            except ValueError:
                pass
                
        return rounds, block_size
        
    @staticmethod
    def get_sbox_params():
        """Get S-box parameters from user input."""
        print("\nS-Box Configuration")
        print("-" * 30)
        
        box_size = SecurityParams.DEFAULT_SBOX_SIZE
        size_input = input(f"Enter S-box size [default={SecurityParams.DEFAULT_SBOX_SIZE}]: ")
        if size_input.strip():
            try:
                box_size = max(min(int(size_input), SecurityParams.MAX_SBOX_SIZE), SecurityParams.MIN_SBOX_SIZE)
            except ValueError:
                pass
                
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