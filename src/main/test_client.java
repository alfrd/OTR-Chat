package main;

import java.net.*;
import java.io.*;
import java.math.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

class Client {
	
	public static void main(String[] args) {
		new Client().run();
	}

	void run() {
		String serverName = "eitn41.eit.lth.se";
		int port = 1337;
		Random rnd = new Random();
		// the p shall be the one given in the manual
		String pString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
						"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
						"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
						"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
						"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
						"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
						"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
						"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
		BigInteger p = new BigInteger(pString, 16);
		BigInteger g = new BigInteger("2");

		try {
			Socket client = new Socket(serverName, port);
			PrintWriter out = new PrintWriter(client.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
			
			// receive g**x1 and convert to a number
			String g_x1_str = in.readLine();
			System.out.println("g**x1: " + g_x1_str);
			BigInteger g_x1 = new BigInteger(g_x1_str, 16);

			// generate g**x2, x2 shall be a random number
			Random rand = new Random();
			BigInteger x2 = new BigInteger(1535, rand);
			
			// calculate g**x2 mod p
			BigInteger g_x2 = g.modPow(x2, p);
			
			// convert to hex-string and send.
			out.println(g_x2.toString(16));
			
			// read the ack/nak. This should yield a nak due to x2 being 0. x2 is no longer 0 so we get ack
			System.out.println("\nsent g_x2: " + in.readLine());
			
			// calculates shared secret
			BigInteger keyDH = g_x1.modPow(x2, p);
			String passphrase = "eitn41 <3";
			String number = "123123";
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			
			byte[] secret = removeZeros(keyDH.toByteArray());
			byte[] phrase = removeZeros(passphrase.getBytes("UTF-8"));
			byte[] concat = new byte[secret.length + phrase.length];
			printByteArray(secret);
			printByteArray(phrase);
			System.arraycopy(secret, 0, concat, 0, secret.length);
			System.arraycopy(phrase, 0, concat, secret.length, phrase.length);
			md.reset();
			
			md.update(concat);
			
			byte[] yByteArray = md.digest();
			
			BigInteger y = new BigInteger(1, yByteArray);
			printByteArray(concat);
			System.out.println("Y: ");
			printByteArray(yByteArray);

			// initiate SMP
			
			// reads alice's response
			String g1a2str = in.readLine();
			BigInteger g1a2 = new BigInteger(g1a2str, 16);
			
			// print alice's response
			System.out.println("got g1a2: " + g1a2.toString());
			
			// calculate g1b2
			BigInteger b2 = new BigInteger(1536, rand);
			BigInteger g1b2 = g.modPow(b2, p);
			
			// send g1b2 to alice
			out.println(g1b2.toString(16));
			
			// read response
			System.out.println("Sent g1b2, got back: " + in.readLine());
			
			// get ga1a3
			String g1a3str = in.readLine();
			BigInteger g1a3 = new BigInteger(g1a3str, 16);
			
			// print alice's response
			System.out.println("got g1a3: " + g1a3.toString());
						
			// calculate and send g1b3
			BigInteger b3 = new BigInteger(1536, rand);
			BigInteger g1b3 = g.modPow(b3, p);
			
			// send g1b3 to alice
			out.println(g1b3.toString(16));
			
			// read response
			System.out.println("Sent g1b3, got back: " + in.readLine());
			
			// get Pa
			String pastr = in.readLine();
			BigInteger pa = new BigInteger(pastr, 16);
			
			// print alice's response
			System.out.println("got Pa: " + pa.toString());
			
			// calculate g2
			BigInteger g2 = g1a2.modPow(b2, p);
			
			// calculate Pb
			BigInteger r = new BigInteger(1536, rand);
			BigInteger g3 = g1a3.modPow(b3, p);
			BigInteger pb = g3.modPow(r, p);
			
			// send pb to alice
			out.println(pb.toString(16));
			
			// get pb ack/nak
			System.out.println("Sent Pb, got back: " + in.readLine());
			
			// get Qa
			String qastr = in.readLine();
			BigInteger qa = new BigInteger(qastr, 16);
			
			// print alice's response 
			System.out.println("got Qa: " + qa.toString());
			
			// calculate Qb
			BigInteger g1r = g.modPow(r, p);
			BigInteger g2y = g2.modPow(y, p);
			BigInteger qb = g1r.multiply(g2y);
			qb = qb.mod(p);
			
			// send Qb to alice
			out.println(qb.toString(16));
			
			// get Qb ack/nak
			System.out.println("Sent Qb, got back: " + in.readLine());
			
			// get qaqbinva3
			String qaqbinva3str = in.readLine();
			BigInteger qbabinva3 = new BigInteger(qaqbinva3str, 16);
			
			// calculate qaqbinvb3
			BigInteger qaqb = qa.multiply(qb.modInverse(p));
			BigInteger qaqbinvb3 = qaqb.modPow(b3, p);
			
			// send qaqbinvb3
			out.println(qaqbinvb3.toString(16));
			
			// get qbabinvb3 ack/nak
			System.out.println("Sent QaQbinvb3, got back: " + in.readLine());
			
			// get authentication
			System.out.println("Authentication: " + in.readLine());
			
			// encrypt message
			
			BigInteger message = new BigInteger("1337", 16);
			BigInteger encryptedMessage = message.xor(keyDH);
			
			// send message to alice
			out.println(encryptedMessage.toString(16));
			
			// get response
			System.out.println("Sent: " + in.readLine());
			
			client.close();
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	
	}
	
	private void printByteArray(byte[] array) {
		for (int i = 0; i < array.length; i++) {
			System.out.print(array[i] + " ");
		}
		System.out.print(" " + array.length + " bytes ");
		System.out.println("");
	}
	
	private byte[] removeZeros(byte[] array) {
		int i = 0;
		while(array[i] == (byte) 0) {
			i++;
		}
		byte[] cleanArray = new byte[array.length - i];
		int j = 0;
		while(i < array.length) {
			cleanArray[j] = array[i];
			i++;
			j++;
		}
		return cleanArray;
	}
}
