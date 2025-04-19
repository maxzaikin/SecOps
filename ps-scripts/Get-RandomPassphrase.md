# 🎲 Get‑RandomPassphrase

Generate a cryptographically‑secure random passphrase and return its SHA‑512 hash in hexadecimal format.

---

## ✨ Features

- 🔐 **Secure**: Uses `RandomNumberGenerator` for true randomness  
- 🧮 **Flexible**: Customize the length of random bytes  
- 🔎 **SHA‑512**: Outputs a 128‑character hex string  

---

## ⚙️ Parameters

| Name        | Type | Description                                         | Default |
|-------------|------|-----------------------------------------------------|---------|
| `ByteLength`| Int  | Number of random bytes to generate (in bytes)       | `32`    |

---

## 🚀 Usage Examples

```powershell
# Generate a 32‑byte random passphrase (default)
Get-RandomPassphrase
🔐: 51FAD825C9DEE5414XXXXXX8AD978BDC257A3C7BCB3EF2990BD7DACXXXXXCAC31186F8292CECCF73.....
