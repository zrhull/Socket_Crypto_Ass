//Zachary Hull    10109756
//Client.java

import java.io.*;
import java.net.*;
import javax.crypto.spec.*;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

/**
 * Client program.  Connects to the server and sends text accross.
 */

public class Client {
    private Socket sock;  //Socket to communicate with.

    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     */
   public static void main (String [] args){

		if (args.length != 2) {
	   	System.out.println ("Usage: java Client hostname port#");
	   	System.out.println ("hostname is a string identifying your server");
	   	System.out.println ("port is a positive integer identifying the port to connect to the server");
	   	return;
		}

		try {
	   	Client c = new Client (args[0], Integer.parseInt(args[1]));
		
		}catch (NumberFormatException e) {
	   	System.out.println ("Usage: java Client hostname port#");
	   	System.out.println ("Second argument was not a port number");
	   	return;
		}	
    }
	
    /**
     * Constructor, in this case does everything.
     * @param ipaddress The hostname to connect to.
     * @param port The port to connect to.
     */
    public Client (String ipaddress, int port){
		/* Allows us to get input from the keyboard. */
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String userinput = "";
		PrintWriter out;
		String in_file_name;
		String out_file_name;
		String key_seed;
		int read_bytes = 0;

		/* Try to connect to the specified host on the specified port. */
		try {
			sock = new Socket (InetAddress.getByName(ipaddress), port);
		}
		catch (UnknownHostException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("First argument is not a valid hostname");
			return;
		}
		catch (IOException e) {
			System.out.println ("Could not connect to " + ipaddress + ".");
			return;
		}
		
		/* Status info */
		System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);
		
		try {
			out = new PrintWriter(sock.getOutputStream());
		}
		catch (IOException e) {
			System.out.println ("Could not create output stream.");
			return;
		}
	
		//file name encrypted/ sent			
		FileInputStream in_file = null;
		
		//Get input and output file names, and the key seed
		Scanner reader = new Scanner(System.in);
		System.out.println("Enter a key seed: ");
		key_seed = reader.nextLine();
		System.out.println("Enter Input file name: ");
		in_file_name = reader.nextLine();
		System.out.println("Enter Output file name: ");
		out_file_name = reader.nextLine();
		reader.close();
		
		try{
			try{  //send new file name
				TimeUnit.SECONDS.sleep(1);

				// compute key:  1st 16 bytes of SHA-1 hash of seed
				SecretKeySpec key = CryptoUtilities.key_from_seed(key_seed.getBytes());

				// append HMAC-SHA-1 message digest
				byte[] hashed_msg = CryptoUtilities.append_hash(out_file_name.getBytes(),key);

				// do AES encryption
				byte[] aes_ciphertext = CryptoUtilities.encrypt(hashed_msg,key);
				
				/* Echo it to the screen. */
				out.println(CryptoUtilities.toHexString(aes_ciphertext));
				
				if ((out.checkError()) || (userinput.compareTo("exit") == 0) || (userinput.compareTo("die") == 0)) {
				System.out.println ("Client exiting.");
				stdIn.close ();
				out.close ();
				sock.close();	
				return;
				}
	    			
			}catch(Exception e){
				System.out.println(e);
			}finally{
				if (in_file != null){
					in_file.close();
				}
			}
  
			
			try{
	//file size
				TimeUnit.SECONDS.sleep(1);
				// open input and output files
				in_file = new FileInputStream(in_file_name);

				// read input file into a byte array
				byte[] msg = new byte[in_file.available()];
				read_bytes = in_file.read(msg);

				// compute key:  1st 16 bytes of SHA-1 hash of seed
				SecretKeySpec key = CryptoUtilities.key_from_seed(key_seed.getBytes());

				// append HMAC-SHA-1 message digest
				byte[] hashed_msg = CryptoUtilities.append_hash(Integer.toString(read_bytes).getBytes(),key);

				// do AES encryption
				byte[] aes_ciphertext = CryptoUtilities.encrypt(hashed_msg,key);
					
				/* Echo it to the screen. */
				
				out.println(CryptoUtilities.toHexString(aes_ciphertext));
				
				if ((out.checkError()) || (userinput.compareTo("exit") == 0) || (userinput.compareTo("die") == 0)) {
				System.out.println ("Client exiting.");
				stdIn.close ();
				out.close ();
				sock.close();	
				return;
				}
			
	//file contents encrypted/ sent
				TimeUnit.SECONDS.sleep(1);
				// append HMAC-SHA-1 message digest
				hashed_msg = CryptoUtilities.append_hash(msg,key);

				// do AES encryption
				aes_ciphertext = CryptoUtilities.encrypt(hashed_msg,key);
				
				/* Echo it to the screen. */
				out.println(CryptoUtilities.toHexString(aes_ciphertext));
	    			
			}catch(Exception e){
				System.out.println(e);
			}finally{
				if (in_file != null){
					in_file.close();
				}
			}
			
			  /* Tricky bit.  Since Java does short circuiting of logical 
			* expressions, we need to checkerror to be first so it is always 
			* executes.  Check error flushes the outputstream, which we need
			* to do every time after the user types something, otherwise, 
			* Java will wait for the send buffer to fill up before actually 
			* sending anything.  See PrintWriter.flush().  If checkerror
			* has reported an error, that means the last packet was not 
			* delivered and the server has disconnected, probably because 
			* another client has told it to shutdown.  Then we check to see
			* if the user has exitted or asked the server to shutdown.  In 
			* any of these cases we close our streams and exit.
			*/  
			if ((out.checkError()) || (userinput.compareTo("exit") == 0) || (userinput.compareTo("die") == 0)) {
				System.out.println ("Client exiting.");
				stdIn.close ();
				out.close ();
				sock.close();	
				return;
				}
		} catch (IOException e) {
			System.out.println ("Could not read from input.");
			return;
		}
	}
}



