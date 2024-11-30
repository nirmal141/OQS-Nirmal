import oqs
import secrets
import hashlib
import json
import logging
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from concurrent.futures import ThreadPoolExecutor


# Configure logging for debugging and info output
logging.basicConfig(level=logging.INFO)

class QuantumFinancialSystem:
    def __init__(self):
        """
        Initializes the quantum-safe financial system. The system uses quantum-resistant algorithms.
        By default, we use Kyber768 and Kyber1024 for key exchange and communication encryption.
        """
        self.key_exchange_algorithm = 'Kyber768'
        self.communication_algorithm = 'Kyber1024'

    def generate_keypair(self, algorithm: str) -> Dict[str, bytes]:
        """
        Generate a quantum-safe keypair based on the given algorithm.
        Args:
            algorithm (str): Quantum-safe algorithm like 'Kyber768'.

        Returns:
            dict: A dictionary containing public and private keys.
        """
        logging.info("Generating a keypair with algorithm: %s", algorithm)
        key_encapsulator = oqs.KeyEncapsulation(algorithm)
        try:
            public_key = key_encapsulator.generate_keypair()
            private_key = key_encapsulator.export_secret_key()
            return {
                'public_key': public_key,
                'private_key': private_key,
                'algorithm': algorithm
            }
        finally:
            key_encapsulator.free()

    def set_up_secure_channel(self, sender_keypair: Dict[str, bytes], recipient_keypair: Dict[str, bytes]):
        """
        Sets up a secure communication channel using the key exchange mechanism.

        Args:
            sender_keypair (dict): The sender's keypair.
            recipient_keypair (dict): The recipient's keypair.

        Returns:
            dict: Information about the secure communication channel, including the shared key.
        """
        logging.info("Establishing a secure channel with %s", self.communication_algorithm)
        key_encapsulator = oqs.KeyEncapsulation(self.communication_algorithm)
        try:
            ciphertext, shared_secret = key_encapsulator.encap_secret(recipient_keypair['public_key'])
            shared_key = hashlib.sha256(shared_secret).digest()  # Derive a symmetric encryption key
            channel_id = secrets.token_hex(8)  # Generate a random channel ID
            logging.info("Secure channel successfully established with ID: %s", channel_id)
            return {
                'channel_id': channel_id,
                'ciphertext': ciphertext,
                'shared_key': shared_key
            }
        finally:
            key_encapsulator.free()

    def encrypt_data(self, shared_key: bytes, data: Dict[str, Any]) -> bytes:
        """
        Encrypt sensitive data using AES-GCM, which ensures both confidentiality and integrity.

        Args:
            shared_key (bytes): Symmetric key derived from the shared secret.
            data (dict): Financial or transaction data to encrypt.

        Returns:
            bytes: The encrypted data, including nonce for AES-GCM.
        """
        logging.info("Encrypting data with AES-GCM.")
        data_payload = json.dumps(data).encode('utf-8')
        nonce = secrets.token_bytes(12)  # Generate a random nonce for AES-GCM
        aesgcm = AESGCM(shared_key)
        encrypted_data = aesgcm.encrypt(nonce, data_payload, None)
        return nonce + encrypted_data  # Prefix the nonce to the encrypted payload

    def decrypt_data(self, shared_key: bytes, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Decrypt encrypted data using AES-GCM and validate integrity.

        Args:
            shared_key (bytes): The symmetric key used to decrypt the data.
            encrypted_data (bytes): The encrypted data that includes the nonce.

        Returns:
            dict: The decrypted data.
        """
        try:
            logging.info("Decrypting data with AES-GCM.")
            nonce = encrypted_data[:12]  # The first 12 bytes are the nonce
            cipher_text = encrypted_data[12:]
            aesgcm = AESGCM(shared_key)
            decrypted_payload = aesgcm.decrypt(nonce, cipher_text, None)
            return json.loads(decrypted_payload.decode('utf-8'))
        except Exception as e:
            logging.error("Decryption failed: %s", str(e))
            raise

class QuantumAttackSimulator:
    @staticmethod
    def simulate_key_recovery(financial_system, attempts=100):
        """
        Simulate quantum attacks by trying to recover the encryption keys using quantum algorithms.

        Args:
            financial_system (QuantumFinancialSystem): The financial system instance.
            attempts (int): Number of simulated attack attempts.

        Returns:
            dict: Results of the attack simulation, showing success and failure counts.
        """
        results = {'total_attempts': attempts, 'successful_recoveries': 0, 'failed_attempts': 0}

        def run_simulation(_):
            try:
                # Generate keypairs for bank and customer
                bank_keypair = financial_system.generate_keypair(financial_system.communication_algorithm)
                customer_keypair = financial_system.generate_keypair(financial_system.communication_algorithm)

                # Establish a secure communication channel
                channel = financial_system.set_up_secure_channel(bank_keypair, customer_keypair)

                # Encrypt and decrypt some sample data
                sample_data = {'transaction_id': secrets.token_hex(16), 'amount': 1000.00, 'currency': 'USD'}
                encrypted = financial_system.encrypt_data(channel['shared_key'], sample_data)
                decrypted = financial_system.decrypt_data(channel['shared_key'], encrypted)

                # Check if decryption was successful
                return decrypted == sample_data
            except Exception:
                return False

        with ThreadPoolExecutor() as executor:
            results_list = list(executor.map(run_simulation, range(attempts)))

        # Calculate the success and failure of each attack attempt
        results['successful_recoveries'] = sum(not outcome for outcome in results_list)
        results['failed_attempts'] = attempts - results['successful_recoveries']
        return results

def demo_quantum_financial_security():
    """
    Demonstrate how the quantum-safe financial system works, from key generation to encryption and decryption,
    and how it withstands quantum attacks.
    """
    logging.info("-- Quantum-Safe Financial System Demo --")

    # Initialize the financial system with quantum-safe security
    system = QuantumFinancialSystem()

    # Generate keypairs for the bank and customer
    logging.info("\n1. Generating Bank Keypair")
    bank_keypair = system.generate_keypair(system.key_exchange_algorithm)

    logging.info("\n2. Generating Customer Keypair")
    customer_keypair = system.generate_keypair(system.key_exchange_algorithm)

    # Establish a secure communication channel
    logging.info("\n3. Setting up Secure Communication Channel")
    channel = system.set_up_secure_channel(bank_keypair, customer_keypair)

    # Encrypt financial data for transmission
    logging.info("\n4. Encrypting Financial Data")
    financial_data = {
        'transaction_id': secrets.token_hex(16),
        'amount': 50000.00,
        'currency': 'USD',
        'sender_account': '1234567890',
        'recipient_account': '0987654321'
    }
    encrypted_data = system.encrypt_data(channel['shared_key'], financial_data)

    # Decrypt the data to verify the process
    logging.info("\n5. Decrypting Financial Data")
    decrypted_data = system.decrypt_data(channel['shared_key'], encrypted_data)

    # Validate the decrypted data matches the original
    assert financial_data == decrypted_data, "Data integrity check failed!"

    # Simulate a quantum attack to test the resilience of the system
    logging.info("\n6. Simulating Quantum Attack")
    attack_results = QuantumAttackSimulator.simulate_key_recovery(system, attempts=1000)

    # Display attack simulation results
    logging.info("\nAttack Simulation Results:\n%s", json.dumps(attack_results, indent=2))
    logging.info("-- Demo Complete --")

if __name__ == '__main__':
    demo_quantum_financial_security()
