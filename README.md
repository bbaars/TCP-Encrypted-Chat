# TCP-Encrypted-Chat

##Part 1
For part 1, you must support the following functionality:

The server should allow for multiple simultaneous clients (you will likely need to use select or threads for this).
The server should provide a way for the clients to get a list of all other connected clients (you may either identify clients by IP/port combinatoin or by a username).
The server should support both clients sending to individual other clients, and clients sending to all other online users simultaneiously.
The server should support administrative commands (sent from a client). At minimum, you should implement a command to kick off another user (this must be handled gracefully). It is up to you how these will be distinguised from text. You must require some sort of authentication for these commands (but it does not need to be something that is realistically secure).
The client should provide a frontend to access all funtionality the server supports. Therefore it must be able to request a list of the IDs of all other connected clients, send messages to other individual users, and send broadcast messages to all users.

## Part 2
For part 2, you must encrypt all messages being sent from client to server, and server back to client. Since all messages between two clients go through a server, the server will need to decrypt and then re-encrypt each message.

Please refer to the sample cryptotest.java and cryptotest.c files for help in how to encrypt and decrypt in your programs.

The C version needs a RSA public and private key in PEM format. These can be produced with the commands:

```
openssl genpkey -algorithm RSA -out RSApriv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in RSApriv.pem -out RSApub.pem
The Java version needs the keys in DER format. You can produce the correct keys with the above commands plus:
openssl rsa -inform PEM -outform DER -pubin -pubout -in RSApub.pem -out RSApub.der
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in RSApriv.pem -out RSApriv.der '
```

If you are using pthreads (or any other thread system), openssl's libcrypto needs some additional setup. Please take a look at the pthreads section of [Named Link] https://github.com/openssl/openssl/blob/OpenSSL_1_0_1-stable/crypto/threads/mttest.c. From there, copy the pthreads version of thread_setup, and any other functions and variables it depends on. Call thread_setup as early as possible in your program.

If you are using Java, you may not use cipherstreams.

When clients join the chat server, they need to securely establish a symmetric key pair with the server. For this purpose, the server should have a public/private key pair for use with RSA. To establish a symmetric key, the client should randomly generate one, and then send it to the server encrypted with the server's RSA public key. The server then should decrypt it using the RSA private key. All subsequent messages should be sent encrypted with this symmetric key.

A random initialization vector is used in encryption to ensure unique encriptions of identical messages. You must properly generate a new IV for each message.
