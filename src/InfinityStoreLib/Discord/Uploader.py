import requests
import hashlib
import os
import io
import pyAesCrypt
import yaml
import random
import json
from faker import Faker


def writef(name, data):
    try:
        file_path = os.path.join(os.getcwd(), name)
        print(file_path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        print(file_path)
        with open(file_path, 'wb') as file:
            file.write(data)
    except:
        print("error writing file")

def writed(name, data):
    try:
        file_path = os.path.join(os.getcwd(), name)
        print(file_path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        print(file_path)
        with open(file_path, 'w') as file:
            json.dump(data, file)
    except:
        print("error writing file")

### Upload ###

# Radnom key
def gen_key(key):
    if key: return key
    return str(os.urandom(69))

# File Hash
def gen_data_hash(data):
    data_hash = hashlib.sha512(data)
    return data_hash.hexdigest()

# Verschlüsseln
def enc(data, keys):
    bufferSize = 64 * 1024
    fIn = io.BytesIO(data)
    fCiph = io.BytesIO()
    try:
        pyAesCrypt.encryptStream(fIn, fCiph, keys, bufferSize)
        fCiph.seek(0)
        enc_data = fCiph.read()
        return enc_data
    except Exception as e:
        print("error encrypting data")
        return e

# In daten Blöcke zerstückeln
def gen_chunks(enc_data):
    chunks = []
    chunk_rnd = 2*1048576
    try:
        while enc_data:
            chunk_size = 5 * 1048576
            chunk_size = chunk_size + random.randint(0, chunk_rnd)
            chunks.append(enc_data[:chunk_size])
            #print(enc_data[:chunk_size])
            enc_data = enc_data[chunk_size:]
        return chunks
    except Exception as e:
        return e


# Daten Upload ready machen
def format_data(data_inbin, key):
    data_key = gen_key(key)
    data_hash = gen_data_hash(data_inbin)
    enc_data = enc(data_inbin, data_key)
    data_chunks = gen_chunks(enc_data)
    return data_chunks , data_hash, data_key

# Alle channels aus den settings lesen
def get_cannel():
    with open('cannels.yaml', 'r') as f:
        cannels = yaml.safe_load(f)
        f.close()
    return cannels["cannels"]

# Daten [] in channels [] hochladen
def upload(data, cannels=None):
    attachment_url = []
    fake = Faker()
    if not cannels: cannels = get_cannel()
    start_cannel = int(random.randint(1, len(cannels)))
    #print(start_cannel)
    try:
        for i in data:
            send = {fake.name(): i}
            response = requests.post(cannels[start_cannel-1] + "?wait=true", files=send)
            attachment_url.append(response.json()['attachments'][0]['url'])
            if len(cannels) > start_cannel: start_cannel +=1
            else: start_cannel = 0
    except Exception as e:
        return e
    return attachment_url


# bin daten lesen
def get_data(location):
    ld = b""
    try:
        with open(location, "rb+") as f:
            ld += f.read()
        return ld
    except:
        print("error reading the file")

# Daten entschlüsseln
def decrypt_data(data, key):
    bufferSize = 64 * 1024
    fCipher = io.BytesIO(data)
    fDec = io.BytesIO()
    try:
        pyAesCrypt.decryptStream(fCipher, fDec, key, bufferSize)
        fDec.seek(0)
        data = fDec.read()
       # print(data)
        return data
    except:
        print("error decrypting data")

# bin daten herunterladen urls []
def download_file(urls, data_key):
    data = b''
    for i in urls:
        data += requests.get(i+ "?wait=true").content
    dec = decrypt_data(data, data_key)
    return dec

# Download infos einlesen
def download_info(name):
    try:
        with open(os.path.join(os.getcwd(), "InfinityStorage\\"+name), "r") as f:
            urls, data_key = json.loads(f.read())

    except Exception as e:
        print(e)
    return urls, data_key

def up(data, cannels=None, key=None):
    #print(data)
    data_chunks, data_hash, data_key = format_data(data, key)
    urls = upload(data_chunks, cannels)
    save = [urls, data_key]
    writed("InfinityStorage\\"+data_hash, save)
    return data_hash

# obj hochladen
def upload_data(data, cannels=None, key=None):
    data = json.dumps(data)
    data = data.encode()
    data_hash = up(data, cannels, key)
    return data_hash

# Interface um eine location hochzuladen
def upload_location(location, cannels=None, key=None):
    data = get_data(location) #read bin
    data_hash = up(data, cannels, key)
    return data_hash


# Datei herunter laden und speichern
def download_location(name ,location):
    urls, data_key = download_info(name)
    data = download_file(urls, data_key)
    if name == hashlib.sha512(data).hexdigest():
        print("wirte")
        #print(data)
        with open(location, 'wb+') as file:
            file.write(data)
    else:
        print("hash mismatch")

# datei herunterladen und obj zurückgeben
def download_data(name):
    urls, data_key = download_info(name)
    data = download_file(urls, data_key)
    if name == hashlib.sha512(data).hexdigest():
        data = json.loads(data)
        return data
    else:
        print("error downloading data")


