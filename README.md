This project addresses a cybersecurity challenge by developing a system that enables remote access to services based on valid credentials. Users can obtain credentials from various authorities and use them to access restricted services. The system focuses on ensuring security through confidentiality, integrity, and transparency, while minimizing reliance on trusted third parties. It aims to protect sensitive information and grant access based on credentials such as residency or birth information. The design emphasizes robust security, usability, and protection against large-scale attacks, while ensuring transparency in the system's operations.

# How to Run the Simulation

To run the simulation, first move to the directory containing the project files. If the OpenSSL path is not set in the environment variables, update the file `constants.py` with the correct path to OpenSSL.

Next, generate the necessary certificates and keys by running:
make all

During this process, you will be prompted to sign the certificates by typing `y` when requested. Since the generated files are already included in the project directory, this step can be skipped if they are already available.

Before running the Python simulation, ensure that the `cryptography` library is installed. If not, install it using:
pip install cryptography

Once everything is set up, start the simulation with:
python main.py

During the simulation, you will be asked to enter the PIN of the CIE (Electronic Identity Card) to sign messages. For the designated test user, the correct PIN to use is `0123456789`.
