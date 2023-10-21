import random
import string
import hashlib
#import os
#import bcrypt

def extract_info_from_wordlist(wl_file):
    """
    This function extracts the information from a wordlist into a list
    """
    # We open the file
    path = str(wl_file)
    # Explicitly specify 'latin-1' encoding
    open_file = open(path, 'r', encoding='latin-1')
    lines = open_file.readlines()
    open_file.close()
    # We select the text of each line as a list element
    lines = [line.strip() for line in lines]
    print(lines[0:3])  # Use slicing to print the first 3 lines
    return lines



def wordlist(wordlist:list):
    """
    We create a sublist of words with 4-6 characters that began with an upper case letter
    We create a sublist of words with 5 characters that began with a number 
    We create a sublist of words with 3-6 characters that contain at least one symbol
    We create a sublist of words with 6 characters that only contain letters
    We create a sublist of words with 4 characters
    wordlist: list of words
    """
    # we create an empty list for hash passwords
    data_list1 = []
    data_list2 = []
    data_list3 = []
    data_list4 = []
    data_list5 = []
    # we create an empty list for clear passwords
    clear_list1 = []
    clear_list2 = []
    clear_list3 = []
    clear_list4 = []
    clear_list5 = []
    
    # Variable de control para verificar si todos los conjuntos de datos tienen 100 contraseñas
    todos_completos = False
    #we generate 5 datatsets of 100 passwords each
    while not todos_completos and wordlist:
        word = wordlist.pop(0)  # Tomar la primera palabra de la lista
        if len(word) > 3 and len(word) < 7 and word[0].isupper() and len(data_list1) < 100:
            #guardamos la contraseña en claro para después reutilizarla con otro hash
            clear_list1.append(word)
            #calculamos el hash de la contraseña
            hash_object = hashlib.sha256()
            hash_object.update(word.encode('utf-8'))
            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            data_list1.append(hashed_password)

        if len(word) == 5 and word[0].isdigit() and len(data_list2) < 100:
            #guardamos la contraseña en claro para después reutilizarla con otro hash
            clear_list2.append(word)
            #calculamos el hash de la contraseña
            hash_object = hashlib.sha256()
            hash_object.update(word.encode('utf-8'))
            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            data_list2.append(hashed_password)

        if len(word)>2 and len(word)<7 and any(char in string.punctuation for char in word) and len(data_list3) < 100:
            #guardamos la contraseña en claro para después reutilizarla con otro hash
            clear_list3.append(word)
            #calculamos el hash de la contraseña
            hash_object = hashlib.sha256()
            hash_object.update(word.encode('utf-8'))
            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            data_list3.append(hashed_password)

        if len(word) == 6 and word.isalpha() and len(data_list4) < 100:
            #guardamos la contraseña en claro para después reutilizarla con otro hash
            clear_list4.append(word)
            #calculamos el hash de la contraseña
            hash_object = hashlib.sha256()
            hash_object.update(word.encode('utf-8'))
            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            data_list4.append(hashed_password)

        if len(word) == 4 and len(data_list5) < 100:
            #guardamos la contraseña en claro para después reutilizarla con otro hash
            clear_list5.append(word)
            #calculamos el hash de la contraseña
            hash_object = hashlib.sha256()
            hash_object.update(word.encode('utf-8'))
            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            data_list5.append(hashed_password)

        # Verificar si todos los conjuntos de datos tienen 100 contraseñas
        if len(data_list1) == 100 and len(data_list2) == 100 and len(data_list3) == 100 and len(data_list4) == 100 and len(data_list5) == 100:
            todos_completos = True

    # Save each dataset to a TXT file
    filename1 = "dataset_wl_1" + ".txt"
    save_dataset(data_list1, filename1)
    filename1 = "dataset_wl_1_sin_hash" + ".txt"
    save_dataset(clear_list1, filename1)

    filename2 = "dataset_wl_2" + ".txt"
    save_dataset(data_list2, filename2)
    filename2 = "dataset_wl_2_sin_hash" + ".txt"
    save_dataset(clear_list2, filename2)

    filename3 = "dataset_wl_3" + ".txt"
    save_dataset(data_list3, filename3)
    filename3 = "dataset_wl_3_sin_hash" + ".txt"
    save_dataset(clear_list3, filename3)

    filename4 = "dataset_wl_4" + ".txt"
    save_dataset(data_list4, filename4)
    filename4 = "dataset_wl_4_sin_hash" + ".txt"
    save_dataset(clear_list4, filename4)

    filename5 = "dataset_wl_5" + ".txt"
    save_dataset(data_list5, filename5)
    filename5 = "dataset_wl_5_sin_hash" + ".txt"
    save_dataset(clear_list5, filename5)     



def save_dataset(dataset, filename):
  """Saves a dataset of passwords to a TXT file."""
  with open(filename, "w") as f:
    for password in dataset:
      f.write(password + "\n")


def generate_dataset_low():
    """Generates a dataset of 100 random passwords."""
    """Generates a random password with 3 to 7 lowercase characters"""
    
    # Datasets to store the passwords
    datasets_low = []
    dataset_sin_hash = []
    for i in range(3, 8):
        dataset = []
        dataset2 = []
        num_letters = i
        for i in range(100):
            low_letters = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for j in range(num_letters))
            dataset2.append(low_letters)
            # Crea un objeto hashlib para SHA-256
            hash_object = hashlib.sha256()

            # Hashea la contraseña
            hash_object.update(low_letters.encode('utf-8'))

            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            dataset.append(hashed_password)

        dataset_sin_hash.append(dataset2)    
        datasets_low.append(dataset)

    # Save each dataset to a TXT file
    for i, dataset in enumerate(datasets_low):
        filename = "dataset_low_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)
    for i, dataset in enumerate(dataset_sin_hash):
        filename = "dataset_low_sin_hash_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)

    return datasets_low, dataset_sin_hash

def generate_dataset_up():
    """Generates a dataset of 100 random passwords."""
    """Generates random password with 3 to 7 upercase characters"""
    
    # datasets to store the passwords
    datasets_up = []
    dataset_sin_hash = []
    for i in range(3, 8):
        dataset = []
        dataset2 = []
        num_letters = i
        for i in range(100):
            up_letters = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for j in range(num_letters))
            dataset2.append(up_letters)
            # Crea un objeto hashlib para SHA-256
            hash_object = hashlib.sha256()

            # Hashea la contraseña
            hash_object.update(up_letters.encode('utf-8'))

            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()

            dataset.append(hashed_password)
        dataset_sin_hash.append(dataset2)
        datasets_up.append(dataset)

    # Save each dataset to a TXT file
    for i, dataset in enumerate(datasets_up):
        filename = "dataset_up_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)
    for i, dataset in enumerate(dataset_sin_hash):
        filename = "dataset_up_sin_hash_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)

    return datasets_up, dataset_sin_hash

def generate_dataset_digit():
    """Generates a dataset of 100 random passwords."""
    """Generates random password with 3 to 7 digits"""

    # datasets to store the passwords
    datasets_digit = []
    dataset_sin_hash = []
    for i in range(3, 8):
        dataset = []
        dataset2 = []
        num_digits = i
        for i in range(100):
            digits = ''.join(random.choice(string.digits) for _ in range(num_digits))
            dataset2.append(digits)
            # Crea un objeto hashlib para SHA-256
            hash_object = hashlib.sha256()

            # Hashea la contraseña
            hash_object.update(digits.encode('utf-8'))

            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
            dataset.append(hashed_password)
        dataset_sin_hash.append(dataset2)
        datasets_digit.append(dataset)

    # Save each dataset to a TXT file
    for i, dataset in enumerate(datasets_digit):
        filename = "dataset_digit_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)
    for i, dataset in enumerate(dataset_sin_hash):
        filename = "dataset_digit_sin_hash_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)

    return datasets_digit, dataset_sin_hash

def generate_dataset_alphanumeric():
    """Generates a dataset of 100 random passwords."""
    """Generates random password with 3 to 7 alphanumeric characters"""

    # datasets to store the passwords
    datasets_alphanumeric = []
    dataset_sin_hash = []
    for i in range(3, 8):
        dataset = []
        dataset2 = []
        num_chars = i
        for i in range(100):
            chars = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(num_chars))
            dataset2.append(chars)
            # Crea un objeto hashlib para SHA-256
            hash_object = hashlib.sha256()

            # Hashea la contraseña
            hash_object.update(chars.encode('utf-8'))

            # Obtiene el hash en formato hexadecimal
            hashed_password = hash_object.hexdigest()
           
            dataset.append(hashed_password)
        dataset_sin_hash.append(dataset2)
        datasets_alphanumeric.append(dataset)

    # Save each dataset to a TXT file
    for i, dataset in enumerate(datasets_alphanumeric):
        filename = "dataset_alphanumeric_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)
    for i, dataset in enumerate(dataset_sin_hash):
        filename = "dataset_alphanumeric_sin_hash_" + str(i+1) + ".txt"
        save_dataset(dataset, filename)

    return datasets_alphanumeric, dataset_sin_hash


# We call the functions to generate the datasets
generate_dataset_low()
generate_dataset_up()
generate_dataset_digit()
generate_dataset_alphanumeric()

word_list = extract_info_from_wordlist('rockyou.txt')
wordlist(word_list)


