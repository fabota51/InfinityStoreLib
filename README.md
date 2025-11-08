
# 📦 InfinityStoreLib — Discord File Storage Library

A simple Python library that lets you **upload and download files or Python objects using Discord webhooks as cloud storage**.
Data is securely **encrypted with AES**, chunked, and distributed across multiple Discord channels.

---

## 🚀 Features

* ✅ Upload and download files using Discord webhooks
* ✅ Store and retrieve Python objects (via `json.dumps`)
* ✅ Automatic AES encryption/decryption
* ✅ Generates a unique SHA-512 hash as a file identifier
* ✅ Multi-channel uploads for larger data
* ✅ Simple, easy-to-use interface

---

## Installation

```bash
pip install .\infinitystorelib-0.0.1-py3-none-any.whl
```

### Dependencies

* `requests`
* `pyAesCrypt`
* `yaml`
* `faker`
* `json`
* `hashlib`

---

## 📖 Usage Guide

### 🔹 1. Import and Setup

```python
from InfinityStoreLib.Discord.Uploader import *
channels = ["https://discord.com/api/webhooks/1382..."]
```

---

### 🔹 2. Upload a File

Uploads a local file to Discord and returns a unique **hash** (used to download it later).

```python
hash = upload_location("test.py", channels)
print("Uploaded file hash:", hash)
```

---

### 🔹 3. Download a File

Downloads the file using its hash and saves it to your specified location.

```python
download_location(hash, "C:/Users/PC/Desktop/test_downloaded.py")
```

---

### 🔹 4. Upload a Python Object

Stores a Python object (e.g., list, dict, etc.) as encrypted JSON.

```python
data = ["test1", "test2", "test3"]
hash = upload_data(data, channels)
print("Data hash:", hash)
```

---

### 🔹 5. Download a Python Object

Downloads and restores the original Python object.

```python
restored_data = download_data(hash)
print("First element:", restored_data[0])
```

---

## How It Works

| Step | Process        | Description                                                            |
| ---- | -------------- |------------------------------------------------------------------------|
| 1    | **Encryption** | Data is encrypted with AES using a random key                          |
| 2    | **Chunking**   | Data is split into 5–7 MB blocks                                       |
| 3    | **Upload**     | Each chunk is uploaded to Discord via webhook                          |
| 4    | **Index File** | The URLs + encryption key are saved locally, named after the data hash |
| 5    | **Download**   | Downloads all chunks, decrypts, and reconstructs the data              |

---

##  Function Reference

### `upload_location(filepath, channels, key=None)`

Uploads a file to Discord.
**Returns:** file hash (used for download)

---

### `download_location(hash, save_path)`

Downloads a file using its hash and saves it locally.

---

### `upload_data(obj, channels, key=None)`

Uploads any JSON-serializable object.
**Returns:** hash of stored data

---

### `download_data(hash)`

Downloads and reconstructs a stored Python object.

---

## ⚙️ Example Workflow

```python
from InfinityStoreLib.Discord.Uploader import *

channels = ["https://discord.com/api/webhooks/1382..."]

# Upload a Python file
hash = upload_location("script.py", channels)

# Download the same file
download_location(hash, "downloads/script_copy.py")

# Upload a Python object
obj = {"user": "Alice", "score": 120}
hash = upload_data(obj, channels)

# Retrieve the object
retrieved = download_data(hash)
print(retrieved)
```


## 🧾 YAML Configuration (optional)

If you don’t want to hardcode your webhooks, you can use a `cannels.yaml` file:

```yaml
cannels:
  - "https://discord.com/api/webhooks/1382..."
  - "https://discord.com/api/webhooks/1383..."
```



## Architecture Overview

```text
                  ┌──────────────────────────┐
                  │      Your File / Obj     │
                  └───────────┬──────────────┘
                              │
                              ▼
                      [ AES Encryption ]
                              │
                              ▼
                         [ Chunking ]
                              │
                              ▼
                ┌──────────────────────────────┐
                │  Discord Webhooks (Channels) │
                └─────────────┬────────────────┘
                              │
                              ▼
                     [ Local Index File ]
                              │
                              ▼
                    [ Download & Decrypt ]
```

---

## License

**MIT License** © 2025
Created by *Fabota51*

---



