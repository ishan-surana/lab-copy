import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Expanded dataset
data = {
    'EmployeeID': [1, 2, 3, 4, 5],
    'Name': ['Alice', 'Bob', 'Charlie', 'David', 'Eva'],
    'Role': ['Finance_Manager', 'HR_Specialist', 'Supply_Chain_Analyst', 'IT_Support', 'Marketing_Head']
}

df = pd.DataFrame(data)

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
    
    def generate_dh_key_pair(self):
        """ Generate Diffie-Hellman key pair """
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_dh_public_key(self, public_key):
        """ Serialize Diffie-Hellman public key to PEM format """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_dh_public_key(self, pem_data):
        """ Deserialize PEM-encoded Diffie-Hellman public key """
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

    def exchange_dh_keys(self, private_key, peer_public_key_pem):
        """ Exchange Diffie-Hellman keys and return the shared secret """
        peer_public_key = self.deserialize_dh_public_key(peer_public_key_pem)
        shared_key = private_key.exchange(peer_public_key)
        return shared_key

    def derive_symmetric_key(self, shared_key):
        """ Derive a symmetric key from the shared secret """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'some_salt',  # In practice, use a unique salt
            iterations=100000,
            backend=default_backend()
        )
        symmetric_key = base64.b64encode(kdf.derive(shared_key))
        return symmetric_key

    def perform_operation(self, employee_id, operation):
        """ Perform an operation requiring role-based access and key generation """
        # Validate employee
        employee = df[df['EmployeeID'] == employee_id]
        if employee.empty:
            print("Employee not found.")
            return
        
        role = employee['Role'].values[0]
        print(role)
        
        if operation in ['Add Role', 'Remove Role', 'Add Employee', 'Remove Employee'] and role not in ['Finance_Manager', 'HR_Specialist']:
            print(f"Role '{role}' is not authorized to perform this operation.")
            return
        
        # Generate and exchange keys for the operation
        private_key_a, public_key_a = self.generate_dh_key_pair()
        private_key_b, public_key_b = self.generate_dh_key_pair()
        
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
        shared_key_a = self.exchange_dh_keys(private_key_a, public_key_b_pem)
        shared_key_b = self.exchange_dh_keys(private_key_b, public_key_a_pem)
        
        # Derive symmetric keys from shared secrets
        symmetric_key_a = self.derive_symmetric_key(shared_key_a)
        symmetric_key_b = self.derive_symmetric_key(shared_key_b)
        
        print(f"\nSymmetric Key (A): {symmetric_key_a.decode()}")
        print(f"Symmetric Key (B): {symmetric_key_b.decode()}")

        # Perform the operation
        if operation == 'Add Role':
            self.add_role()
        elif operation == 'Remove Role':
            self.remove_role()
        elif operation == 'Add Employee':
            self.add_employee()
        elif operation == 'Remove Employee':
            self.remove_employee()
        elif operation == 'Employee Login':
            self.employee_login(employee_id)
        elif operation == 'Employee Leaving':
            self.employee_leaving(employee_id)

    def add_role(self):
        """ Add a new role with its own RSA key pair """
        role = input("Enter role name to add: ")
        private_key, public_key = self.generate_rsa_key_pair()
        self.keys[role] = {
            'private_key': self.serialize_key(private_key),
            'public_key': self.serialize_key(public_key, is_private=False)
        }
        print(f"Role '{role}' added with new RSA key pair.")
    
    def remove_role(self):
        """ Remove a role and its RSA key pair """
        role = input("Enter role name to remove: ")
        if role in self.keys:
            del self.keys[role]
            print(f"Role '{role}' removed.")
        else:
            print(f"Role '{role}' not found.")
    
    def add_employee(self):
        """ Add a new employee """
        global df
        employee_id = df['EmployeeID'].iloc[-1]+1
        name = input("Enter new employee name: ")
        role = input("Enter new employee role: ")
        new_employee = pd.DataFrame({'EmployeeID': [employee_id], 'Name': [name], 'Role': [role]})
        df = pd.concat([df, new_employee], ignore_index=True)
        print(f"Employee '{name}' added with Role '{role}'.")

    def remove_employee(self):
        """ Remove an employee """
        employee_id = int(input("Enter employee ID to remove: "))
        global df
        df = df[df['EmployeeID'] != employee_id]
        print(f"Employee with ID {employee_id} removed.")

    def employee_login(self, employee_id):
        """ Generate new keys for login """
        keys = self.get_role_keys(employee_id)
        if keys:
            print("Private Key:\n", keys['private_key'].decode())
            print("Public Key:\n", keys['public_key'].decode())
    
    def employee_leaving(self, employee_id):
        """ Handle an employee leaving """
        role = df.loc[df['EmployeeID'] == employee_id, 'Role'].values
        if role.size > 0:
            role = role[0]
            print(f"Employee with ID {employee_id} leaving. Role '{role}' access revoked.")
        else:
            print(f"Employee with ID {employee_id} not found.")

    def get_role_keys(self, employee_id):
        """ Get the RSA keys for a given employee's role """
        role = df.loc[df['EmployeeID'] == employee_id, 'Role'].values
        if role.size > 0:
            role = role[0]
            return self.keys.get(role, None)
        else:
            print(f"Employee with ID {employee_id} not found.")
            return None

def menu():
    print("\nMenu:")
    print("0. Display")
    print("1. Add Role")
    print("2. Remove Role")
    print("3. Add Employee")
    print("4. Remove Employee")
    print("5. Employee Login")
    print("6. Employee Leaving")
    print("7. Exit")

def main():
    key_manager = KeyManager()
    
    while True:
        menu()
        choice = input("Enter your choice: ")
        if choice == '0':
            print(df)
        elif choice == '1':
            key_manager.perform_operation(employee_id=int(input("Enter your employee ID: ")), operation='Add Role')
        elif choice == '2':
            key_manager.perform_operation(employee_id=int(input("Enter your employee ID: ")), operation='Remove Role')
        elif choice == '3':
            key_manager.perform_operation(employee_id=int(input("Enter your employee ID: ")), operation='Add Employee')
        elif choice == '4':
            key_manager.perform_operation(employee_id=int(input("Enter your employee ID: ")), operation='Remove Employee')
        elif choice == '5':
            key_manager.perform_operation(employee_id=int(input("Enter your employee ID: ")), operation='Employee Login')
        elif choice == '6':
            key_manager.perform_operation(employee_id=int(input("Enter your employee ID: ")), operation='Employee Leaving')
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()