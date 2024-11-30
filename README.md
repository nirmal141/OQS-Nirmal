# Quantum-Safe Financial System

This project implements a quantum-safe financial system using post-quantum cryptographic algorithms for secure key exchange and AES-GCM encryption to protect sensitive financial data. The system is designed to demonstrate the application of quantum-safe algorithms in financial security, with a focus on secure communication and data encryption.

## Features

- **Quantum-Safe Key Exchange**: Uses post-quantum cryptographic algorithms such as Kyber for key exchange.
- **AES-GCM Encryption**: Encrypts financial data using AES-GCM encryption.
- **MITM Attack Simulation**: Simulates man-in-the-middle attacks to test the system's security.
- **Quantum Attack Simulation**: Simulates quantum attacks to test the resilience of quantum-safe protocols.
- **Real-Life Scenario Testing**: Includes functionalities to test the system against various attack scenarios and performance under load.

## Prerequisites

Before running the system, make sure you have the following dependencies installed:

- Python 3.7 or higher
- `pip` (Python package manager)

### Dependencies

The project requires several Python libraries. You can install them using `pip`.

1. **oqs**: The post-quantum cryptography library for implementing quantum-safe key exchange algorithms.
2. **cryptography**: Provides cryptographic recipes and primitives for secure encryption.
3. **secrets**: Python standard library for generating cryptographically strong random numbers.
4. **concurrent.futures**: To execute concurrent simulations (for attack scenarios).
5. **json**: To handle JSON data for storing encrypted financial transactions.

You can install the required dependencies using the following command:

```bash
pip install oqs cryptography

### USAGE
python3 quantum-crypto-test.py
