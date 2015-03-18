/**
 * TP3 - REQUETES DNS
 *  Matthieu Caron
 *  Arnaud Cojez
 */

import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.lang.String;

/**
 * Classe utilisée pour envoyer des requêtes DNS, puis analyser/imprimer et leurs résultats.
 */
public class TpDNS {
    
    public static void main (String[] args) throws Exception {
	String label;
	if(args.length >= 1)
	    label = args[0];
	else
	    label = "www.lifl.fr";
	// Q4 (IMPRESSION ET ANALYSE DU PAQUET + AFFICHAGE DE L'IP)
		analysePacket(label);
	
	// Q5 (RENVOI DE L'ADRESSE IP SOUS FORME D'INT
	System.out.println("\nAdresse IP sous forme d'int : " + getIP(label));
    }

    /**
     * Envoie une requête DNS à propos d'une URL et imprime le contenu du paquet reçu ainsi que l'adresse IP correspondante
     * (Question 4)
     * @param label l'URL dont on veut connaître les informations
     */ 
    public static void analysePacket(String label) throws Exception {
	// ENVOI DE LA REQUETE
	DatagramSocket socket;
	DatagramPacket packetS;
	DatagramPacket packetR = new DatagramPacket(new byte[512], 512);
	//InetAddress dst = InetAddress.getByName("8.8.8.8"); PAS FAC
	InetAddress dst = InetAddress.getByName("172.18.12.9");
	int port = 53;
	int i, length, ip;
	byte[] msgS = createRequest(label);
	byte[] msgR;
	packetS = new DatagramPacket(msgS, msgS.length, dst, port);
	socket = new DatagramSocket();
	socket.send(packetS);
	socket.receive(packetR);

	// IMPRESSION ET DECRYPTAGE DU PAQUET
	printPacket(packetR);

	// FERMETURE DU SOCKET
	socket.close();
    }
    
    //Q5
    /**
     * Envoie une requête DNS à propos d'une URL et retourne son adresse IP (codée sous forme d'entier)
     * (Question 5)
     * @param label l'URL dont on veut connaître les informations
     * @return l'adresse IP correspondant à l'URL, sous forme d'entier
     */
    public static int getIP(String label) throws Exception {
	// ENVOI ET RECEPTION DU PAQUET
	DatagramSocket socket;
	DatagramPacket packetS;
	DatagramPacket packetR = new DatagramPacket(new byte[512], 512);
	//	InetAddress dst = InetAddress.getByName("8.8.8.8"); PAS FAC
	InetAddress dst = InetAddress.getByName("172.18.12.9");
	int port = 53;
	int i, length, ip;
	byte[] msgS = createRequest(label);
	byte[] msgR;
	packetS = new DatagramPacket(msgS, msgS.length, dst, port);
	socket = new DatagramSocket();
	socket.send(packetS);
	socket.receive(packetR);
	msgR = packetR.getData();

	// TRAITEMENT DU PAQUET
	i = getEndOfString(msgR, 12) + 6; // on va jusqu'au premier champ
	while(getShortValue(msgR, i) != 1)
	    i += getShortValue(msgR, i+8) + 12; // on va au premier champ de type 1 (contenant une adresse IP)

	// CODAGE DES 4 OCTETS DE L'IP DANS UN SEUL INT (qui est codé sur 4 octets)
	ip = (msgR[i+10] & 0xff)*16777216 + (msgR[i+11] & 0xff)*65536 + (msgR[i+12] & 0xff)*256 + (msgR[i+13] & 0xff);

	// AFFICHAGE EVENTUEL DE L'IP SOUS FORME LISIBLE POUR VERIFICATION
	//System.out.println( "getIP : Adresse obtenue : " + (msgR[i+10] & 0xff) + "." + (msgR[i+11] & 0xff) + "." + (msgR[i+12] & 0xff) + "." + (msgR[i+13] & 0xff));

	// FERMETURE DU SOCKET
	socket.close();
	
	return ip;
    }

    /**
     * Crée une requête DNS à partir d'une URL
     * @param label l'URL dont on veut avoir les informations
     * @return une requête permettant d'obtenir des informations sur l'URL label
     */
    public static byte[] createRequest(String label) {
	int length = 18 + label.length();
	int i;
	byte[] r = new byte[length];
	// DECOUPAGE DE LA CHAINE EN SOUS CHAINES
	String[] labelSplit = label.split("\\."); // "\\." = regexp pour le point "."

	// REMPLISSAGE DU SQUELETTE DE REQUETE
	r[0] = (byte) 0x08;
	r[1] = (byte) 0xbb;
	r[2] = r[5] = r[length -1] = r[length - 3] = (byte) 0x01;
	r[3] = r[4] = r[length -2] = r[length - 4] = r[length - 5] = (byte) 0;
	for(i = 6; i < 12; i++)
	    r[i] = (byte) 0;

	// AJOUT DU LABEL 
	for(String str : labelSplit) {
	    r[i++] = (byte) (str.length() & 0xff); //AJOUT DE LA LONGUEUR A LA PLACE DU POINT
	    for(char c : str.toCharArray())
		r[i++] = (byte) c; //AJOUT DES CARACTERES
	}
	return r;
    }

    /**
     * Imprime et décrypte le contenu d'un paquet
     * Cette fonction utilise printParamStr et printChampStr
     * (Pour la question 4)
     * @param packet le paquet qu'on veut imprimer
     */
    public static void printPacket(DatagramPacket packet) {
	byte[] msg = packet.getData();
	int length = packet.getLength();
	int i = 0;
	int j, offset, nbchar, ip, finChaine, nbRep, nbAut, nbAdd;

	System.out.println("\n/////DECRYPTAGE/////");
	
	System.out.println("IDENTIFIANT : " + getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]));

	printParamStr(getShortValue(msg, i)); // IMPRESSION PARAMETRES
	i += 2;

	System.out.println("QUESTION : " + getShortValue(msg, i));
	i += 2;

	nbRep = getShortValue(msg, i);
	System.out.println("REPONSE : " + nbRep);
	i += 2;

	nbAut = getShortValue(msg, i);
	System.out.println("AUTORITE : " + nbAut);
	i += 2;

	nbAdd = getShortValue(msg, i);
	System.out.println("INFOS COMPLEMENTAIRES : " + nbAdd);
	i += 2;

	// IMPRESSION NOM
	finChaine = getEndOfString(msg, 12);
	System.out.print("URL : ");
	for(; i < finChaine; i++)
	    System.out.print((char) msg[i]);

	System.out.println("\nTYPE (HOST ADDRESS) : " + getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]));
	System.out.println("CLASS (INTERNET) : " + getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]));

	// IMPRESSION REPONSES, AUTORITE, INFOS COMPLEMENTAIRES
	System.out.println("\n//REPONSES//");

	System.out.println("\n" + nbRep + " Réponses");
	for(j = 0; j < nbRep; j++) // on commence à partir de i
	    i = printChampStr(msg, i);

	System.out.println("\n" + nbAut + " Autorités");
	for(j = 0; j < nbAut; j++) // on commence à partir de i
	    i = printChampStr(msg, i);
	
	System.out.println("\n" + nbAdd + " Informations Additionelles");
	for(j = 0; j < nbAdd; j++) // on commence à partir de i
	    i = printChampStr(msg, i);

	// on récupère l'indice où on s'est arreté après avoir lu un champ pour recommencer à partir de cet indice

	// IMPRESSION ADRESSE IP
	i = getEndOfString(msg, 12) + 6; // on va jusqu'au premier champ
	while(getShortValue(msg, i) != 1)
	    i += getShortValue(msg, i+8) + 12; // on va au premier champ de type 1 (contenant une adresse IP)

	System.out.println( "L'adresse IP est : " + (msg[i+10] & 0xff) + "." + (msg[i+11] & 0xff) + "." + (msg[i+12] & 0xff) + "." + (msg[i+13] & 0xff));
    }

    /**
     * Imprime un champ de réponse d'un paquet
     * (Pour la question 4)
     * @param msg le tableau d'octets correspondant au paquet reçu
     * @param offset l'indice de début du champ
     * @return l'indice de début du prochain champ
     */
    public static int printChampStr(byte[] msg, int offset) {
	String s = "";
	int i = offset;
	int length, type;
	//OFFSET
	System.out.println("OFFSET : " + getHexStr(msg[i++]) + ',' + getHexStr(msg[i]) + " = " + (msg[i] & 0xff));
	//NOM
	System.out.print("NOM : ");
	for(int j = msg[i++] & 0xff; msg[j] != 0; j++)
	    System.out.print((char) msg[j]);
	//TYPE
	type = getShortValue(msg, i);
	System.out.println("\nTYPE : " + getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]));
	//CLASS
	System.out.println("CLASS : " + getHexStr(msg[i++]) + ',' + getHexStr(msg[i++]));
	//TTL
	System.out.println("TTL : " + getIntValue(msg, i));
	i += 4;

	//RDLENGTH
	length = getShortValue(msg, i);
	System.out.println("LENGTH : " + length);
	i += 2;
	
	//RDDATA
	for(int j = 0; j < length; j++)
	    if(type == 1) // AFFICHAGE ADRESSE IP
		System.out.print((msg[i+j] & 0xFF) + ".");
	    else // AUTRE AFFICHAGE 
		System.out.print((char) msg[i+j]); // on affiche length char
	i += length; // on ajoute à i les octets parcourus
	
	System.out.println("\n");
	return i;
    }

    /**
     * Imprime le champ de paramètres d'un paquet
     * (Pour la question 4)
     * @param i les paramètres sous forme d'entier
     */
    public static void printParamStr(int i) {
	char[] b = intToBinary(i, 16).toCharArray();
	int j;
	System.out.print("    QR : " + b[0]);
	for(j = 1; j < 5; j++)
	    System.out.print(b[j]);
	System.out.println("\n    OPCODE : ");
	System.out.println("    AA : " + b[5]);
	System.out.println("    TC :" + b[6]);
	System.out.println("    RD : " + b[7]);
	System.out.println("    RA : " + b[8]);
	System.out.println("    UNUSED : " + b[9]);
	System.out.println("    AD :" + b[10]);
	System.out.println("    CD :" + b[11]);
	System.out.print("    RCODE :");
	for(j = 12; j < 16; j++)
	    System.out.print(b[j]);
	System.out.println("");
    }

    /**
     * Permet de récupérer une valeur "short" (codée sur 2 octets) à partir dans un tableau de bytes à partir d'un offset i.
     * t[i] étant l'octet de poids fort
     * @param t le tableau de bytes
     * @param i l'offset
     * @return les 2 octets suivant i, réunis en un int
     */
    public static int getShortValue(byte[] t, int i) {
	return (t[i] & 0xff)*256 + (t[i+1] & 0xff);
    }

    /**
     * Permet de récupérer un entier (codé sur 4 octets) à partir dans un tableau de bytes à partir d'un offset i.
     * t[i] étant l'octet de poids fort
     * @param t le tableau de bytes
     * @param i l'offset
     * @return les 4 octets suivant i, réunis en un int
     */
    public static int getIntValue(byte[] t, int i) {
	return (t[i] & 0xff)*16777216 + (t[i+1] & 0xff)*65536 + (t[i+2] & 0xff)*256 + (t[i+3] & 0xff);
    }

    /**
     * Permet de connaitre où s'arrête la première chaine de caractère d'un paquet
     * @param t un paquet
     * @param i un entier
     * @return l'indice de fin de la chaine
     */
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

    /**
     * Permet de récupérer une chaine représentant la valeur Hexadécimale de l'octet de poids faible d'un entier
     * @param i un entier
     * @return la représentation hexadécimale de l'octet de poids faible de i
     */
    public static String getHexStr(int i) {
	String res = Integer.toHexString(i & 0xff);
	if(res.length() == 1)
	    return '0' + res;
	else
	    return res;
    }

    /**
     * Convertit un entier en une chaine de caractères binaires de taille totBit
     * les bits de poids fort seront tronqués si totBit est inférieure à la taille en bits de l'entier
     * @param i l'entier
     * @param totBit la taille désirée de la chaîne
     * @return la chaine binaire correspondant à i
     */
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
