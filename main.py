import sys
import getpass
import utils.database as db
import utils.auth as auth
import utils.encryption as enc

def setup_master_password():
    """
    Automatically sets the default master password on the first run.
    Users are highly encouraged to change this in the options menu.
    
    Inputs: None
    Outputs:
        bytes: The derived encryption key ready to be passed around.
    """
    print("\n=== Welcome to your new CLI Password Manager! ===")
    print("Initializing your secure vault for the first time...")
    
    default_pwd = "mysecret"
    auth.hash_and_save_master_password(default_pwd)
    
    print(f"\n[!] Setup Complete. Your default Master Password is: '{default_pwd}'")
    print("[!] Please use Option 5 in the menu to change it immediately for your security.\n")
            
    return enc.derive_key_from_password(default_pwd)

def login():
    """
    Prompts the user to log in and validates their master password.
    
    Inputs: None
    Outputs:
        bytes: The derived encryption key if successful, or None if failed.
    """
    print("\n=== CLI Password Manager ===")
    
    for attempt in range(3):
        pwd = getpass.getpass("Enter your Master Password: ")
        
        if auth.verify_master_password(pwd):
            print("Access Granted!")
            return enc.derive_key_from_password(pwd)
        else:
            print(f"Access Denied. {2 - attempt} attempts remaining.")
            
    print("Too many failed attempts. Exiting.")
    return None

def display_menu():
    """
    Prints the interactive menu options to the terminal.
    """
    print("\n--- Main Menu ---")
    print("1. Add a new password")
    print("2. View all saved passwords")
    print("3. Edit a password")
    print("4. Delete a password")
    print("5. Change Master Password")
    print("6. Exit")
    print("-----------------")

def main():
    """
    The orchestrator function. It manages setup, login, and the continuous main loop.
    """
    # 1. Ensure the database file & tables actually exist before we do anything.
    db.init_db()
    
    # 2. Check if the user needs to set up a master password, or just log in.
    if not auth.check_if_setup():
        session_key = setup_master_password()
    else:
        session_key = login()
        if session_key is None:
            # Login failed. sys.exit quits the python program immediately.
            sys.exit(1)
            
    # 3. Enter the main infinite loop of our CLI application.
    while True:
        display_menu()
        choice = input("Select an option (1-6): ").strip()
        
        if choice == '1':
            service = input("Enter the service (e.g., Google, Netflix): ").strip()
            username = input("Enter the username/email: ").strip()
            pwd = getpass.getpass("Enter the password for this service: ")
            
            # Encrypt the raw password into scrambled text BEFORE saving to the database.
            encrypted_pwd = enc.encrypt_password(session_key, pwd)
            db.add_password(service, username, encrypted_pwd)
            print(f"SUCCESS: Saved password for {service}.")
            
        elif choice == '2':
            # Grab all rows from the database.
            rows = db.get_all_passwords()
            if not rows:
                print("Your vault is currently empty.")
            else:
                print("\n--- Your Vault ---")
                # Each row is a tuple: (id, service, username, encrypted_password, created_at)
                for r in rows:
                    p_id, service, username, encrypted_hash, created_at = r
                    
                    # Decrypt the scramble text back into the real password we can read.
                    try:
                        decrypted_pwd = enc.decrypt_password(session_key, encrypted_hash)
                        print(f"[{p_id}] {service} | User: {username} | Pass: {decrypted_pwd}")
                    except Exception as e:
                        print(f"[{p_id}] {service} | User: {username} | Pass: [DECRYPTION FAILED]")
                        
        elif choice == '3':
            rows = db.get_all_passwords()
            if not rows:
                print("No passwords to edit.")
                continue
                
            p_id_input = input("Enter the ID number of the password to edit: ").strip()
            if not p_id_input.isdigit():
                print("Invalid ID.")
                continue
                
            p_id = int(p_id_input)
            
            service = input("Enter the new service name: ").strip()
            username = input("Enter the new username/email: ").strip()
            new_pwd = getpass.getpass("Enter the new password: ")
            
            enc_pwd = enc.encrypt_password(session_key, new_pwd)
            db.update_password(p_id, service, username, enc_pwd)
            print("SUCCESS: Password updated.")
            
        elif choice == '4':
            rows = db.get_all_passwords()
            if not rows:
                print("No passwords to delete.")
                continue
                
            p_id_input = input("Enter the ID number of the password to delete: ").strip()
            if not p_id_input.isdigit():
                print("Invalid ID.")
                continue
                
            db.delete_password(int(p_id_input))
            print("SUCCESS: Password deleted.")
            
        elif choice == '5':
            print("\n--- Change Master Password ---")
            print("WARNING: This will re-encrypt your entire vault.")
            old_pwd = getpass.getpass("Enter CURRENT Master Password: ")
            
            if not auth.verify_master_password(old_pwd):
                print("Incorrect current password. Aborting.")
                continue
                
            new_pwd = getpass.getpass("Enter NEW Master Password: ")
            confirm = getpass.getpass("Confirm NEW Master Password: ")
            
            if new_pwd != confirm:
                print("Passwords do not match. Aborting.")
                continue
                
            print("Processing... Please do not close the application.")
            
            # Step A: Generate the new encryption key
            new_session_key = enc.derive_key_from_password(new_pwd)
            
            # Step B: Pull ALL passwords and re-encrypt them
            rows = db.get_all_passwords()
            success = True
            for r in rows:
                p_id, service, username, old_encrypted_hash, _ = r
                try:
                    # Decrypt with OLD key
                    decrypted_pwd = enc.decrypt_password(session_key, old_encrypted_hash)
                    # Encrypt with NEW key
                    new_encrypted_hash = enc.encrypt_password(new_session_key, decrypted_pwd)
                    # Update DB
                    db.update_password(p_id, service, username, new_encrypted_hash)
                except Exception as e:
                    print(f"ERROR re-encrypting entry {p_id}. Aborting process!")
                    success = False
                    break
                    
            if success:
                # Step C: Save new master password hash
                auth.hash_and_save_master_password(new_pwd)
                # Step D: Update live session key
                session_key = new_session_key
                print("SUCCESS: Master password changed and all vault entries re-encrypted.")
                
        elif choice == '6':
            print("Exiting Password Manager. Stay safe!")
            break
            
        else:
            print("Invalid selection. Please enter a number from 1 to 6.")

# A Python convention meaning: "Only run the main() function if this core file is executed directly." 
if __name__ == "__main__":
    main()
