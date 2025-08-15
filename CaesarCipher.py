def caesar_cipher_encrypt(text, shift):
    shift %= 26
    result = []
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            result.append(char)
    return ''.join(result)

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def main():
    print("\n=== Caesar Cipher Tool ===")
    while True:
        choice = input("Do you want to (E)ncrypt or (D)ecrypt? (E/D): ").strip().upper()
        if choice not in ['E', 'D']:
            print("Invalid choice. Please enter 'E' to encrypt or 'D' to decrypt.")
            continue

        message = input("Enter your message: ")

        while True:
            try:
                shift = int(input("Enter the shift value (1-25): "))
                if 1 <= shift <= 25:
                    break
                else:
                    print("Please enter a number between 1 and 25.")
            except ValueError:
                print("Invalid input. Please enter an integer between 1 and 25.")

        if choice == 'E':
            encrypted_message = caesar_cipher_encrypt(message, shift)
            print(f"Encrypted Message: {encrypted_message}")
        else:
            decrypted_message = caesar_cipher_decrypt(message, shift)
            print(f"Decrypted Message: {decrypted_message}")

        another = input("Do you want to perform another operation? (Y/N): ").strip().upper()
        if another != 'Y':
            print("Goodbye!")
            break

if __name__ == "__main__":
    main()
