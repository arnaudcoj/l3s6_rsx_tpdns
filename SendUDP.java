/**
 *  TP1 Réseaux - UDP et Multicast
 *  Exercice 1
 *  Matthieu Caron
 *  Arnaud Cojez
 */

import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.lang.String;

/**
 * Class used to send a message
 */
public class SendUDP {
    
    public static void main (String[] args) throws Exception {
	DatagramSocket socket;
	DatagramPacket packetS;
	DatagramPacket packetR = new DatagramPacket(new byte[512], 512);
	InetAddress dst = InetAddress.getByName("172.18.12.9");
	int port = 53;
	byte[] msgS = {(byte) 0x08, (byte) 0xbb, (byte) 0x01, (byte) 0x00,
		       (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
		       (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		       (byte) 0x03, (byte) 0x77, (byte) 0x77, (byte) 0x77,
		       (byte) 0x04, (byte) 0x6c, (byte) 0x69, (byte) 0x66,
		       (byte) 0x6c, (byte) 0x02, (byte) 0x66, (byte) 0x72,
		       (byte) 0x00,
		       (byte) 0x00, (byte) 0x01,
		       (byte) 0x00, (byte) 0x01};

	packetS = new DatagramPacket(msgS, msgS.length, dst, port);
	socket = new DatagramSocket();

	socket.send(packetS);
	socket.receive(packetR);
	byte msgR[] = packetR.getData();
	System.out.println("paquet reçu hexa");
	for(int i = 0; i < packetR.getLength(); i++) {
	    System.out.print("," + Integer.toHexString(msgR[i] & 0xff));
	    if( (i+1) % 16 == 0)
		System.out.println("");
	}
	System.out.println("\n\npaquet reçu déc");
	for(int i = 0; i < packetR.getLength(); i++) {
	    System.out.print("," + getShortValue(msgR, i));
	    if( (i+1) % 16 == 0)
		System.out.println("");
	}
	System.out.println("");
	//2e partie decryptage
	/*
	System.out.println(getHexStr(msgR[0]) + ',' + getHexStr(msgR[1]) + " : IDENTIFIANT"); // IDENTIFIANT
	System.out.println(Integer.toBinaryString(msgR[2]) + ',' + Integer.toBinaryString(msgR[3]));
	*/

	//NOM
	int taillechaine = getEndOfString(msgR, 12);

	for(int i = 12; i < taillechaine; i++)
	    System.out.print((char) msgR[i]);

	System.out.println("");

	socket.close(); 
    }

    public static int getShortValue(byte[] t, int i) {
	return (t[i] & 0xff)*256 + (t[i+1] & 0xff);
    }

    public static String getHexStr(int i) {
	String res = Integer.toHexString(i & 0xff);
	if(res.length() == 1)
	    return '0' + res;
	else
	    return res;
    }

    public static int getEndOfString(byte[] t, int i) {
	while (t[i] != 0) {
	    int c = t[i] & 0xff;
	    if (c >= 192)
		return i+2;
	    else
		i += c+1;
	}
	return i+1;
    }
    
}
