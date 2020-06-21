# secrets-vault

Secrets Vault enables you to encrypt files from your FS and store secrets/credentials securely on your file system. The files/secrets/credentials are encrypted with a key that is derived from a password provided by you (the user). Every secret is associated with its own password so you should provide the password that corresponds to the secret every time you read it (or choose a password every time you encrypt a file/create a secret). The password should be between 6 nad 64 characters and should contain at least one symbol of each group: digits, capital letters and small letters. 

Possible usage for now is encrypting FS files, storing securely large tokens(that can not be easily remembered by human) or securing many secrets just using a not so wide set of passwords to protect this secrets(though NOT so recommended).

You can build the project using `mvn clean install`. If you want scan for vulnarabilties to be performed just use the `owasp-dependency-check` profile (`mvn clean install -Powasp-dependency-check`).

### Encrypting a file

The flow in this scenario is as follows:

1. Specify 'encrypt' command.
2. Type a filename. (could not be blank) - this should be the name of the file you want to encrypt.
3. Type the master password that is used for protection.
4. An AES data encryption key is generated using the PBKDF2 generation function with HMAC-SHA256.
5. An encrypted version of the file you specified in 2. is created using AES encryption (with the generated in 4. key) in GCM mode. Note that the original file is not modified. Also a metadata file is created that contains the IV and the provided master password hash (SHA-256).

- Steps 1 to 3 should be made by the user

### Creating a secret (file)

The flow in this scenario is as follows:

1. Specify 'create' command.
2. Type a filename. (could not be blank) - if there is already a file with the given name - fail
3. Type the secret you want to be protected.
4. Type the master password that is used for protection.
5. An AES data encryption key is generated using the PBKDF2 generation function with HMAC-SHA256.
6. The secret you provided in 3. is encrypted using AES encryption (with the generated in 5. key) in GCM mode.
7. The encrypted value from 6. is written to a file related to the specifed in 2. name. Also a metadata file is created that contains the IV and the provided master password hash (SHA-256).

- Steps 1 to 4 should be made by the user

### Reading/Decrypting a secret

The flow in this scenario is as follows:

1. Specify 'read' command
2. Type a filename. (could not be blank) - if there is NO file with the given name - fail
3. Type the master password that is protecting this secret.
4. An AES decryption key is generated using the PBKDF2 generation function with HMAC-SHA256.
5. SHA-256 hash of the key from 4. is compared against the one that is saved in the corresponding file. If this check does NOT pass - fail. Otherwise:
6. Decrypt the secret using the key from 4. and print it in the console.

- Steps 1 to 3 should be made by the user

### Example
![Example Secrets Vault Usage](doc/secrets-vault-demo.PNG)
