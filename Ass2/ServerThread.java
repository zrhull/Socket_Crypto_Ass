//Zachary Hull    10109756
//ServerThread.java

import java.net.*;
import java.io.*;
import javax.crypto.spec.*;
import java.util.Scanner;

/**
 * Thread to deal with clients who connect to Server.  Put what you want the
 * thread to do in it's run() method.
 */

public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
    private int idnum;  //The client's id number.
    private int debug;
    private String key_seed;
	Scanner reader = new Scanner(System.in);  // Reading from System.in
	
    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
   public ServerThread (Socket s, Server p, int id, int deb){
		parent = p;
		sock = s;
		idnum = id;
		debug = deb;
   }
	
    /**
     * Getter for id number.
     * @return ID Number
     */
   public int getID (){
		return idnum;
   }
	
    /**
     * Getter for the socket, this way the parent thread can
     * access the socket and close it, causing the thread to
     * stop blocking on IO operations and see that the server's
     * shutdown flag is true and terminate.
     * @return The Socket.
     */
    public Socket getSocket ()
    {
	return sock;
    }
	
    /**
     * This is what the thread does as it executes.  Listens on the socket
     * for incoming data and then echos it to the screen.  A client can also
     * ask to be disconnected with "exit" or to shutdown the server with "die".
     */
   public void run (){
		BufferedReader in = null;
		String incoming = null;
		byte [] file_name = null;
		String file_size = null;

		
		//Get the key seed from user
		System.out.println("Enter a key seed: ");
		String key_seed = reader.nextLine(); 
		
		
		try {
		    in = new BufferedReader (new InputStreamReader (sock.getInputStream()));

		}catch (UnknownHostException e) {
	   	System.out.println ("Unknown host error.");
	   	return;
		}
		
		catch (IOException e) {
	   	System.out.println ("Could not establish communication.");
	   	return;
		}
		
		/* Try to read from the socket */
		try {
	   	incoming = in.readLine ();

		}catch (IOException e) {
		   if (parent.getFlag()){
		   	System.out.println ("shutting down.");
		   	return;
			}
	    	return;
		}
	
		
	/* See if we've recieved something */
	while (incoming != null){
		/* If the client has sent "exit", instruct the server to
		 * remove this thread from the vector of active connections.
		 * Then close the socket and exit.
		 */
		if (incoming.compareTo("exit") == 0){
			parent.kill (this);
			try {
			    in.close ();
			    sock.close ();
			}
			catch (IOException e)
			    {/*nothing to do*/}
			return;
		}
			
		/* If the client has sent "die", instruct the server to
		 * signal all threads to shutdown, then exit.
		 */
		else if (incoming.compareTo("die") == 0){
			parent.killall ();
			return;
		}	
			
		/* Otherwise, just echo what was recieved. */
		if (debug == 1){
			System.out.println ("Client " + idnum + ": " + incoming);
		}
		
			try{    //get file name

				// read input file into a byte array
				byte[] msg = CryptoUtilities.hexStringToByteArray(incoming);

				// compute key:  1st 16 bytes of SHA-1 hash of seed
				SecretKeySpec key = CryptoUtilities.key_from_seed(key_seed.getBytes());

				// do AES decryption
				byte[] hashed_plaintext = CryptoUtilities.decrypt(msg,key);

				// verify HMAC-SHA-1 message digest and output plaintext if valid
				if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
					System.out.println("Message digest OK");

					// extract plaintext and output to file
					file_name = CryptoUtilities.extract_message(hashed_plaintext);
					
					String s = new String(file_name);
					
					if (debug == 1){
						System.out.println ("Client " + idnum + " File name: " + s);
					}
			
				}else
					System.out.println("ERROR:  invalid message digest!");
			
				}catch(Exception e){
					System.out.println(e);
				}
				
			try{    //get file size
				incoming = in.readLine ();
				if (debug == 1){
					System.out.println ("Client " + idnum + ": " + incoming);
				}

				// read input file into a byte array
				byte[] msg = CryptoUtilities.hexStringToByteArray(incoming);

				// compute key:  1st 16 bytes of SHA-1 hash of seed
				SecretKeySpec key = CryptoUtilities.key_from_seed(key_seed.getBytes());
				
				// do AES decryption
				byte[] hashed_plaintext = CryptoUtilities.decrypt(msg,key);

				// verify HMAC-SHA-1 message digest and output plaintext if valid
				if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
					System.out.println("Message digest OK");

					// extract plaintext and output to file
					byte[] plaintext = CryptoUtilities.extract_message(hashed_plaintext);
					
					String s = new String(plaintext);
					
					if (debug == 1){
						System.out.println ("Client " + idnum + " File size: " + s);
					}
				
				}else
					System.out.println("ERROR:  invalid message digest!");
			
				}catch(Exception e){
					System.out.println(e);
				}
				
				
				
				FileOutputStream out_file = null;
			try{   //get file contents
				incoming = in.readLine ();
				if (debug == 1){
					System.out.println ("Client " + idnum + ": " + incoming);
				}
				// open output file
				String st_of_file_name = new String(file_name);
				out_file = new FileOutputStream(st_of_file_name);

				// read input file into a byte array
				byte[] msg = CryptoUtilities.hexStringToByteArray(incoming);

				// compute key:  1st 16 bytes of SHA-1 hash of seed
				SecretKeySpec key = CryptoUtilities.key_from_seed(key_seed.getBytes());

				// do AES decryption
				byte[] hashed_plaintext = CryptoUtilities.decrypt(msg,key);

				// verify HMAC-SHA-1 message digest and output plaintext if valid
				if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
					System.out.println("Message digest OK");

					// extract plaintext and output to file
					byte[] plaintext = CryptoUtilities.extract_message(hashed_plaintext);
					
					String s = new String(plaintext);
					
					if (debug == 1){
						System.out.println ("Client " + idnum + " File contents: " + s);
						
					}
				
					out_file.write(plaintext);  //write file contents to new file
					out_file.close();
					System.out.println("File transfer success!");
				}else
					System.out.println("ERROR:  invalid message digest!");
			
				}catch(Exception e){
					System.out.println(e);
				}
		
			parent.kill (this);		//done decrypting file, end this thread
			try {
			    in.close ();
			    sock.close ();
			}
			catch (IOException e)
			    {/*nothing to do*/}
			return;
			}
	    }
    }
