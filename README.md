# What is Seccoco?

Seccoco is an Android library which offers you to add encryption to your application with just a few lines of code. Seccoco is designed with simplicity in mind. Instead of giving you gazillions of different configurations it provides you sensible defaults and abstracts away the complexity of cryptography. Under the hood it uses state of the art crypto algorithms.

# How to use Seccoco?

## Initialize
 Create Seccoco directly in your Android Application class and make this object available to other parts of your application e.g. via dependency injection.

    Seccoco seccoco =  SeccocoFactory.create(this);

Internally Seccoco will at first launch of the application create a keypair and store the private key securily. It then creates a random passphrase and stores this encrypted with the public key. On subsequent starts of the application it will then access the private key and decrypt the passphrase.

## Symmetric crypto

You don't need to provide a passphrase or IV. Seccoco internally uses the auto generated passphrase with an IV for it.

    byte[] encrypted = seccoco.crypto().encrypt("Hello from Seccoco".getBytes());
    byte[] decrypted = seccoco.crypto().decrypt(encrypted);

##Hybrid crypto

###Encryption

####For yourself

You can encrypt the data so that it can only be decrypted from your specific Seccoco configuration:


    byte[] plainText =  "My very own secret data".getBytes();
    EncryptedMessage encryptedMessage = seccoco.crypto().encryptForSelf(plainText);


####For the trusted recipient

You can include one certificate which is then trusted by default. 
In order to do this, you need to put this certificate in PEM format in the asset folder and name it ```seccoco-trustedrecipient.pem```.

If this file is found, you can encrypt the data for this recipient:

    byte[] plainText = "Hi there, I trust you out of the box!".getBytes();
    EncryptedMessage encryptedMessage = seccoco.crypto().encryptForTrustedRecipient(plainText);
    
####For some other recipient

If you want to send an encrypted message to somebody else, all you need to have is the certificate in PEM format.

First you need to extract the ```Identity``` object from the PEM file. This object holds the certificate as well as the fingerprint of the certificate.

    Identity identity = seccoco.identities().extractFromPem(new FileReader(new File("recipient.pem")));

Then you can encrypt the data:

    byte[] plainText = "Hi there, thanks for sending me your certificate!".getBytes();
    EncryptedMessage encryptedMessage = seccoco.crypto().encrypt(plainText,identity);


In all cases the encrypted message will have your certificate attached and also a signature of the content, so that the recipient of this message can validate if you are the one who sent this message.


###Decryption

If you received an encrypted message you can decrypt it again without the need of additional parameters.
    
    byte[] decrypted = seccoco.crypto().decrypt(encryptedMessage);

Contact us for questions: [info@seccoco.com](mailto:info@seccoco.com)