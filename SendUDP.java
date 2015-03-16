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
	int i;
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
	for(i = 0; i < packetR.getLength(); i++) {
	    System.out.print("," + getHexStr(msgR[i] & 0xff));
	    if( (i+1) % 16 == 0)
		System.out.println("");
	}
	System.out.println("\n\npaquet reçu déc");
	for(i = 0; i < packetR.getLength(); i++) {
	    System.out.print("," + getShortValue(msgR, i));
	    if( (i+1) % 16 == 0)
		System.out.println("");
	}
	System.out.println("\n/////DECRYPTAGE/////");
	//2e partie decryptage
	i = 0;
	System.out.println(getHexStr(msgR[i++]) + ',' + getHexStr(msgR[i++]) + " : IDENTIFIANT");
	System.out.println(getParamStr(getShortValue(msgR, i))); // PARAMETRES
	i += 2;
	System.out.println(getShortValue(msgR, i) + " : QUESTION");
	i += 2;
	System.out.println(getShortValue(msgR, i) + " : REPONSE");
	i += 2;
	System.out.println(getShortValue(msgR, i) + " : AUTORITE");
	i += 2;
	System.out.println(getShortValue(msgR, i) + " : INFOS COMPLEMENTAIRES");
	i += 2;

	//NOM
	int taillechaine = getEndOfString(msgR);
	for(; i < taillechaine; i++)
	    System.out.print((char) msgR[i]);
	System.out.println(" : URL");
	
	System.out.println(getHexStr(msgR[i++]) + ',' + getHexStr(msgR[i++]) + " : TYPE (HOST ADDRESS)");
	System.out.println(getHexStr(msgR[i++]) + ',' + getHexStr(msgR[i++]) + " : CLASS (INTERNET)");

	System.out.println("");

	socket.close(); 
    }

    public static String getParamStr(int i) {
	char[] b = intToBinary(i, 16).toCharArray();
	String s = "";
	s += b[0] + " : QR\n";
	s += b[1] + "," + b[2] + "," + b[3] + "," + b[4] + " : OPCODE\n";
	s += b[5] + " : AA\n";
	s += b[6] + " : TC\n";
	s += b[7] + " : RD\n";
	s += b[8] + " : RA\n";
	s += b[9] + " : UNUSED\n";
	s += b[10] + " : AD\n";
	s += b[11] + " : CD\n";
	s += b[12] + "," + b[13] + "," + b[14] + "," + b[15] + " : RCODE\n";
	return s;
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

    public static int getEndOfString(byte[] t) {
	int i = 12;
	while (t[i] != 0) {
	    int c = t[i] & 0xff;
	    if (c >= 192)
		return i+2;
	    else
		i += c+1;
	}
	return i+1;
    }
    
    public static String intToBinary(int i, int totBit) {
	String s = "";
	int r = i;
	while(totBit-- != 0) {
	    s = (r % 2) + s;
	    r /= 2;
	}
	return s;
    }
}
