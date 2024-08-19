import pandas as pd
from IPython.display import display
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Initialize the master table with employee data and roles
data = {
    'EmployeeID': [1, 2, 3],
    'Name': ['Alice', 'Bob', 'Charlie'],
    'Role': ['Finance_Manager', 'HR_Specialist', 'Supply_Chain_Analyst']
}

df = pd.DataFrame(data)
print("Initial Employee Data:")
print(df)

# Key Management with RSA and Diffie-Hellman
class KeyManager:
    def __init__(self):
        self.keys = {}
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    
    def generate_rsa_key_pair(self):
        """ Generate RSA key pair """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_key(self, key, is_private=True):
        """ Serialize key to PEM format """
        if is_private:
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    def add_role(self, role):
        """ Add a new role with its own RSA key pair """
        private_key, public_key = self.generate_rsa_key_pair()
        self.keys[role] = {
            'private_key': self.serialize_key(private_key),
            'public_key': self.serialize_key(public_key, is_private=False)
        }
        print(f"Role '{role}' added with new RSA key pair.")
    
    def remove_role(self, role):
        """ Remove a role and its RSA key pair """
        if role in self.keys:
            del self.keys[role]
            print(f"Role '{role}' removed.")
        else:
            print(f"Role '{role}' not found.")
    
    def get_role_keys(self, role):
        """ Get the RSA keys for a given role """
        return self.keys.get(role, None)
    
    def employee_login(self, employee_id):
        """ Generate new keys for login """
        role = df.loc[df['EmployeeID'] == employee_id, 'Role'].values[0]
        return self.get_role_keys(role)

    def employee_leaving(self, employee_id):
        """ Revoke access for an employee """
        role = df.loc[df['EmployeeID'] == employee_id, 'Role'].values[0]
        print(f"Employee {employee_id} leaving. Role '{role}' access revoked.")
    
    def generate_dh_key_pair(self):
        """ Generate Diffie-Hellman key pair """
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def exchange_dh_keys(self, private_key, peer_public_key):
        """ Exchange Diffie-Hellman keys and return the shared secret """
        peer_public_key = dh.DHPublicKey.from_encoded_point(self.dh_parameters, peer_public_key)
        shared_key = private_key.exchange(peer_public_key)
        return shared_key

    def derive_symmetric_key(self, shared_key):
        """ Derive a symmetric key from the shared secret """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'some_salt',  # In practice, use a unique salt
            backend=default_backend()
        )
        symmetric_key = base64.b64encode(kdf.derive(shared_key))
        return symmetric_key

def menu():
    print("\nMenu:")
    print("0. Display DB")
    print("1. Add a Role")
    print("2. Remove a Role")
    print("3. Get RSA Keys for a Role")
    print("4. Employee Login")
    print("5. Employee Leaving")
    print("6. Generate DH Key Pairs and Exchange Keys")
    print("7. Exit")

def main():
    key_manager = KeyManager()
    
    while True:
        menu()
        choice = input("Enter your choice: ")
        
        if choice == '0':
            display(df)
                    
        elif choice == '1':
            role = input("Enter role name to add: ")
            key_manager.add_role(role)
        
        elif choice == '2':
            role = input("Enter role name to remove: ")
            key_manager.remove_role(role)
        
        elif choice == '3':
            role = input("Enter role name to get RSA keys: ")
            keys = key_manager.get_role_keys(role)
            if keys:
                print("Private Key:\n", keys['private_key'].decode())
                print("Public Key:\n", keys['public_key'].decode())
            else:
                print("Role not found.")
        
        elif choice == '4':
            employee_id = int(input("Enter employee ID for login: "))
            keys = key_manager.employee_login(employee_id)
            if keys:
                print("Private Key:\n", keys['private_key'].decode())
                print("Public Key:\n", keys['public_key'].decode())
            else:
                print("Employee ID not found.")
        
        elif choice == '5':
            employee_id = int(input("Enter employee ID for leaving: "))
            key_manager.employee_leaving(employee_id)
        
        elif choice == '6':
            # Generate Diffie-Hellman key pairs
            private_key_a, public_key_a = key_manager.generate_dh_key_pair()
            private_key_b, public_key_b = key_manager.generate_dh_key_pair()
            
            # Serialize DH public keys for transmission
            public_key_a_pem = public_key_a.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_b_pem = public_key_b.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Exchange DH public keys and compute shared secrets
            shared_key_a = key_manager.exchange_dh_keys(private_key_a, public_key_b_pem)
            shared_key_b = key_manager.exchange_dh_keys(private_key_b, public_key_a_pem)
            
            # Derive symmetric keys from shared secrets
            symmetric_key_a = key_manager.derive_symmetric_key(shared_key_a)
            symmetric_key_b = key_manager.derive_symmetric_key(shared_key_b)
            
            print("\nGenerated Symmetric Key (A):", symmetric_key_a.decode())
            print("Generated Symmetric Key (B):", symmetric_key_b.decode())
        
        elif choice == '7':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()