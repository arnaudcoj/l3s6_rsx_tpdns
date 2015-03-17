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
public class TpDNS {
    
    public static void main (String[] args) throws Exception {
	DatagramSocket socket;
	DatagramPacket packetS;
	DatagramPacket packetR = new DatagramPacket(new byte[512], 512);
	InetAddress dst = InetAddress.getByName("172.18.12.9");
	int port = 53;
	int i, length;
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
	byte[] msgR = packetR.getData();
	length = packetR.getLength();
	System.out.println("paquet reçu hexa");
	for(i = 0; i < packetR.getLength(); i++) {
	    System.out.print("," + getHexStr(msgR[i] & 0xff));
	    if( (i+1) % 16 == 0)
		System.out.println("");
	}
	System.out.println("\n/////DECRYPTAGE/////");
	//2e partie decryptage
	
	decryptPacket(msgR, length);

	socket.close(); 
    }

    public static void decryptPacket(byte[] msg, int length) {
	int i = 0;
	int j;
	int offset, nbchar, ip;
	System.out.println(getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]) + " : IDENTIFIANT");
	System.out.println(getParamStr(getShortValue(msg, i))); // PARAMETRES
	i += 2;
	System.out.println(getShortValue(msg, i) + " : QUESTION");
	i += 2;
	System.out.println(getShortValue(msg, i) + " : REPONSE");
	i += 2;
	System.out.println(getShortValue(msg, i) + " : AUTORITE");
	i += 2;
	System.out.println(getShortValue(msg, i) + " : INFOS COMPLEMENTAIRES");
	i += 2;

	//NOM
	int taillechaine = getEndOfString(msg, 12);
	for(; i < taillechaine; i++)
	    System.out.print((char) msg[i]);
	System.out.println(" : URL");
	
	System.out.println(getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]) + " : TYPE (HOST ADDRESS)");
	System.out.println(getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]) + " : CLASS (INTERNET)");

	//Reponse
	System.out.println("REPONSE");
	i = getChampStr(msg, i); // Affiche réponse 1
	i = getChampStr(msg, i); // Affiche réponse 2 (avec IP)
	ip = i - 4;
	while(i < length) // on commence à partir de i
	    i = getChampStr(msg, i); // on récupère l'indice où on s'est arreté après avoir lu un champ pour recommencer à partir de cet indice
	
	System.out.print("L'adresse IP est : ");
	for(int k = 0; k < 3; k++)
	    System.out.print((msg[ip+k] & 0xFF) + ".");

	System.out.println(msg[ip+3] & 0xFF);
    }

    public static int getChampStr(byte[] msg, int offset) {
	String s = "";
	int i = offset;
	int length;
	int type;
	//OFFSET
	System.out.println(getHexStr(msg[i++]) + ',' + getHexStr(msg[i]) + " : OFFSET de " + msg[i]);
	//NOM
	for(int j = msg[i++]; msg[j] != 0; j++)
	    System.out.print((char) msg[j]);
	System.out.println(" : NOM");
	//TYPE
	type = getShortValue(msg, i);
	System.out.println(getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]) + " : TYPE");
	//CLASS
	System.out.println(getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]) + " : CLASS");
	//TTL
	System.out.println(getIntValue(msg, i) + " TTL");
	i += 4;

	//RDLENGTH
	length = getShortValue(msg, i);
	System.out.println(length + " : LENGTH");
	i += 2;
	
	//RDDATA
	for(int j = 0; j < length; j++)
	    if(type == 1)
		System.out.print((msg[i+j] & 0xFF) + ".");
	    else
		System.out.print((char) msg[i+j]); // on affiche length char
	i += length; // on ajoute à i les octets parcourus
	
	System.out.println("\n");
    return i;
    }

    public static String getParamStr(int i) {
	char[] b = intToBinary(i, 16).toCharArray();
	int j;
	String s = "";
	s += b[0] + " : QR\n";
	for(j = 1; j < 5; j++)
	    s += b[j];
	s += " : OPCODE\n";
	s += b[5] + " : AA\n";
	s += b[6] + " : TC\n";
	s += b[7] + " : RD\n";
	s += b[8] + " : RA\n";
	s += b[9] + " : UNUSED\n";
	s += b[10] + " : AD\n";
	s += b[11] + " : CD\n";
	for(j = 12; j < 16; j++)
	    s += b[j];
	s += " : RCODE\n";
	return s;
    }

    public static int getShortValue(byte[] t, int i) {
	return (t[i] & 0xff)*256 + (t[i+1] & 0xff);
    }

    public static int getIntValue(byte[] t, int i) {
	return (t[i] & 0xff)*16777216 + (t[i+1] & 0xff)*65536 + (t[i+2] & 0xff)*256 + (t[i+3] & 0xff);
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
