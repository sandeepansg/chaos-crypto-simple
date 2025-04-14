"""
Main entry point for the Chebyshev cryptosystem application.
"""
import time
from chebyshev.security import SecurityParams
from crypto.dh import ChebyshevDH
from crypto.feistel import FeistelCipher
from crypto.sbox import SBoxGenerator
from ui.interface import UserInterface


def run_demo():
    """Run a demonstration of the Chebyshev DH exchange and encryption."""
    ui = UserInterface()

    try:
        # Display header
        ui.show_header()

        # Get private key length
        private_bits = ui.get_private_key_length()

        # Show calculated security parameters
        params = SecurityParams.get_secure_params(private_bits)
        ui.show_param_info(params)

        # Get Feistel cipher parameters
        feistel_rounds, feistel_block_size = ui.get_feistel_params()

        # Get S-box size
        sbox_size = ui.get_sbox_params()

        # Get entropy
        entropy = ui.get_entropy()

        # Initialize system
        start_time = time.time()
        dh = ChebyshevDH(private_bits)
        init_time = time.time() - start_time

        # Display system info
        system_info = dh.get_system_info()
        ui.show_system_info(system_info, init_time)

        # Perform key exchange
        start_time = time.time()
        exchange = dh.simulate_exchange(entropy, entropy + "_bob")
        exchange_time = time.time() - start_time
        ui.show_exchange_results(exchange, exchange_time)

        # Generate S-box from shared secret
        start_time = time.time()
        sbox_gen = SBoxGenerator(exchange["alice_shared"], box_size=sbox_size)
        sbox = sbox_gen.generate()
        sbox_time = time.time() - start_time
        ui.show_sbox_generation(sbox, sbox_time)

        # Demo Feistel encryption
        start_time = time.time()
        cipher = FeistelCipher(sbox, rounds=feistel_rounds, block_size=feistel_block_size)
        
        # Show Feistel cipher parameters
        cipher_info = cipher.get_cipher_info()
        ui.show_feistel_params(cipher_info)

        # Get sample message
        message = ui.get_sample_message()

        # Encrypt and decrypt
        ciphertext = cipher.encrypt(message.encode())
        decrypted = cipher.decrypt(ciphertext)
        
        encryption_time = time.time() - start_time
        ui.show_encryption_results(message, ciphertext, decrypted, encryption_time)

    except KeyboardInterrupt:
        print("\nDemo aborted by user.")
    except Exception as e:
        print(f"\nError occurred: {str(e)}")


if __name__ == "__main__":
    run_demo()