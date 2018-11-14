Zachary Hull    10109756
ReadMe.txt

Files:
	Server.java
	ServerThread.java
	Client.java
	CryptoUtilities.java
	ReadMe.txt
	
To compile:
	javac Server.java
	javac ServerThread.java
	javac Client.java
	javac CryptoUtilities.java

I used a linux computer with two consoles using port number 4444.

The problem is solved in full.

Known bugs:
	-need to give the server the key seed and enter before entering the 
	 output file name for the client

Durring the file transfer the server will echo the message sent,
then state if the message digest is "OK". If the digest is OK then it will 
echo the sent message after it has been decrypted. This will repeat for the 
file name, size and then the contents. In the event that everything has been 
completed properly it will issue a success message, if not then it will issue
an error message. When the server is done with the current file it will kill
the current thread The messages are parsed by converting the byte array to a
hex string then back to a byte array.

Everything is protected and retains its integrity, all messages are encrypted 
using AES-128-CBC and integrity assured using HMAC-SHA-1. The has is appended 
to a message then the message is encrypted.

Confidentiality and Integrity is assured because every message is encrypted 
with its hash then sent and only after the server has tthe message is it
decrypted.