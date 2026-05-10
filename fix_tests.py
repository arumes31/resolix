import re

c = open('webgui/main_test.go', 'r', encoding='utf-8').read()
# Add syslog timestamp to test lines
c = re.sub(r'\[\]byte\("dnsmasq\[123\]:', r'[]byte("Jan 02 15:04:05 dnsmasq[123]:', c)
c = re.sub(r'\[\]byte\("dnsmasq\[1\]:', r'[]byte("Jan 02 15:04:05 dnsmasq[1]:', c)
c = re.sub(r'"query\[A\] d', r'"Jan 02 15:04:05 dnsmasq[1]: query[A] d', c)
c = re.sub(r'"query\[A\] batch-', r'"Jan 02 15:04:05 dnsmasq[1]: query[A] batch-', c)
c = re.sub(r'"query\[A\] domain-', r'"Jan 02 15:04:05 dnsmasq[1]: query[A] domain-', c)
c = re.sub(r'\[\]byte\("query\[A\] domain', r'[]byte("Jan 02 15:04:05 dnsmasq[1]: query[A] domain', c)

open('webgui/main_test.go', 'w', encoding='utf-8').write(c)

enc = open('webgui/internal/encryption/encryption.go', 'r', encoding='utf-8').read()
enc = enc.replace('func Encrypt', '// Encrypt encrypts plaintext using AES-GCM and PBKDF2.\\nfunc Encrypt')
enc = enc.replace('func Decrypt', '// Decrypt decrypts a base64 encoded ciphertext using AES-GCM and PBKDF2.\\nfunc Decrypt')
enc = enc.replace('	finalData := append(salt, ciphertext...)\\n	return base64.StdEncoding.EncodeToString(finalData), nil', '	salt = append(salt, ciphertext...)\\n	return base64.StdEncoding.EncodeToString(salt), nil')
open('webgui/internal/encryption/encryption.go', 'w', encoding='utf-8').write(enc)
