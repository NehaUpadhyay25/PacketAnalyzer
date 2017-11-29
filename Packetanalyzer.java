import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Project - 4
 * This file is the PacketAnalyzer file. 
 * 
 * This file takes in the path of the packet in as command
 * line argument and converts it into byte array of bytes present
 * in the file.
 * 
 * This file then converts the byte array in string of hexadecimal 
 * values.
 * 
 * The string of hexadecimal values is later passed in the method
 * to print the Ethernet header and then it is passed in the IP
 * header method to print the IP headers.
 * 
 * By looking at the protocol in the IP header it then prints the
 * headers for the protocol ICMP , TCP or UDP depending on the 
 * protocol value of the IP header.
 * 
 * @author Neha Upadhyay
 *
 */

public class Packetanalyzer {
	
	/**
	 * This method is implemented to print the Ethernet header fields from the corresponding packet
	 * @param contentPacket Hexadecimal format of the packet
	 */
	public void printEthernet(String contentPacket)
	{
		System.out.println("ETHER:  ----- Ether Header ----- ");
		System.out.println("ETHER: ");
		System.out.println("ETHER: Packet Size = " +(contentPacket.length() / 2) +" bytes ");
		System.out.println("ETHER: Destination = " +contentPacket.substring(0, 2) + ":" +contentPacket.substring(2, 4)  + ":" +contentPacket.substring(4, 6) + ":" +contentPacket.substring(6, 8) + ":" +contentPacket.substring(8, 10) + ":" +contentPacket.substring(10, 12));
		System.out.println("ETHER: Source = " +contentPacket.substring(12, 14) + ":" +contentPacket.substring(14, 16)  + ":" +contentPacket.substring(16, 18) + ":" +contentPacket.substring(18, 20) + ":" +contentPacket.substring(20, 22) + ":" +contentPacket.substring(22, 24));
		System.out.println("ETHER: EtherType = " +contentPacket.substring(24, 28));
		System.out.println("ETHER: ");
	}
	
	/**
	 * This method is implemented to print the IP header fields from the corresponding packet
	 * @param 	contentPacket 	Hexadecimal format of the packet
	 * @return 	protocol		Protocol of the packet - TCP, ICMP or UDP
	 */
	public int printIp(String contentPacket)
	{
		System.out.println("IP:  ----- IP Header ----- ");
		System.out.println("IP: ");
		System.out.println("IP: Version = " +contentPacket.substring(28, 29));
		int headerLength = Integer.parseInt(contentPacket.substring(29,30),16);
		System.out.println("IP: Header Length = " +(4 * headerLength) + " bytes");
		System.out.println("IP: Type of Service = 0x" +contentPacket.substring(30,32));
		int service = Integer.parseInt(contentPacket.substring(30,32) , 16);
		byte newService = (byte) service;
		System.out.println("IP: xxx. .... = 0 (precedence)");
		System.out.println("IP: ..." + newService +".... = normal delay");
		System.out.println("IP: ...." + newService +"... = normal throughput");
		System.out.println("IP: ....." + newService +"... = normal reliability");
		
		System.out.println("IP: Total Length = " +Integer.parseInt(contentPacket.substring(32,36),16) + " bytes");
		System.out.println("IP: Identification = " +Integer.parseInt(contentPacket.substring(36,40),16));
		
		System.out.println("IP: Flags = " +contentPacket.substring(40,44));
		
		// This is used to check for the IP header Flag fields. To check whether to fragment or not
		//and to check is it the last fragment of the header field.
		int serviceFlag = Integer.parseInt(contentPacket.substring(40,42),16);
		
		String serviceFlag2 = ""+Integer.toBinaryString(serviceFlag);
		
		String checkFragment = serviceFlag2.substring(0,1);
		
		if(checkFragment.equals("1")) {
			System.out.println("IP: .1.. .... = do not fragment ");
		}
		else {
			System.out.println("IP: .0.. .... = fragment ");
		}
		
		char[] checkFragment2 = serviceFlag2.toCharArray();
		
		if(checkFragment2[0] == '1') {
			System.out.println("IP: .1.. .... = not last fragment ");
		}
		else {
			System.out.println("IP: ..0. .... = last fragment ");
		}
		System.out.println("IP: Fragment offset : "+Integer.parseInt(contentPacket.substring(42,44),16)+ " bytes");
		System.out.println("IP: Time to live = " +Integer.parseInt(contentPacket.substring(44,46),16) + " seconds/hops");
		
		String protocol1 = contentPacket.substring(46,48);
		
		//This is used to determine which of the three protocol the IP header corresponds to.
		if(protocol1.equals("01")) {
			System.out.println("IP: Protocol = " +Integer.parseInt(contentPacket.substring(46,48),16)+ " (ICMP)");
		}
		else if(protocol1.equals("06")) {
			System.out.println("IP: Protocol = " +Integer.parseInt(contentPacket.substring(46,48),16)+" (TCP)");
		}
		else {
			System.out.println("IP: Protocol = " +Integer.parseInt(contentPacket.substring(46,48),16)+ " (UDP)");
		}
		System.out.println("IP: Header Checksum = " +contentPacket.substring(48,52));
		
		
		//This is used to print the Source Address
		String source = contentPacket.substring(52,60) ;
		int add1 = Integer.parseInt(source.substring(0, 2),16);
		int add2 = Integer.parseInt(source.substring(2, 4),16);
		int add3 = Integer.parseInt(source.substring(4, 6),16);
		int add4 = Integer.parseInt(source.substring(6, 8),16);
		String newSource = add1+"."+add2+"."+add3+"."+add4;	
		InetAddress sourceAddress;
		try {
			sourceAddress = InetAddress.getByName(newSource);
			String sourceName = sourceAddress.getHostName();
			System.out.println("IP: Source Address = " +newSource +", "+sourceName);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//This is used to print the Destination Address
		String dest = contentPacket.substring(60,68) ;
		int addr1 = Integer.parseInt(dest.substring(0, 2),16);
		int addr2 = Integer.parseInt(dest.substring(2, 4),16);
		int addr3 = Integer.parseInt(dest.substring(4, 6),16);
		int addr4 = Integer.parseInt(dest.substring(6, 8),16);
		String newDest = addr1+"."+addr2+"."+addr3+"."+addr4;	
		InetAddress destAddress;
		
		try {
			destAddress = InetAddress.getByName(newDest);
			String destName = destAddress.getHostName();
			System.out.println("IP: Destination Address = " +newDest +", "+destName);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("IP: No Options ");
		System.out.println("IP: ");
				
		int protocol = Integer.parseInt(contentPacket.substring(46,48),16);
		return protocol;
	}
	
	/**
	 * This method is implemented to print the ICMP header fields from the 
	 * corresponding packet. It takes the substring of the string and if the 
	 * value of the Protocol field in the IP Protocol is 1.
	 * @param contentPacket Hexadecimal format of the packet
	 */
	public void printIcmp(String contentPacket)
	{
		System.out.println("ICMP:  ----- ICMP Header ----- ");
		System.out.println("ICMP: ");
		System.out.println("ICMP:  Type " +Integer.parseInt(contentPacket.substring(68, 70)));
		System.out.println("ICMP:  Code " +Integer.parseInt(contentPacket.substring(70, 72)));
		System.out.println("ICMP:  Checksum " +contentPacket.substring(72, 76));
		System.out.println("ICMP: ");
	}
	
	/**
	 * This method is implemented to print the TCP header fields from the 
	 * corresponding packet. It takes the substring of the string and if the 
	 * value of the Protocol field in the IP Protocol is 6.
	 * @param contentPacket Hexadecimal format of the packet
	 */
	public void printTcp(String contentPacket)
	{
		System.out.println("TCP:  ----- TCP Header ----- ");
		System.out.println("TCP: ");
		System.out.println("TCP: Source Port Number :" +Integer.parseInt(contentPacket.substring(68, 72),16));
		System.out.println("TCP: Destination Port Number :" +Integer.parseInt(contentPacket.substring(72, 76),16));
		System.out.println("TCP: Sequence Number :" +Long.parseLong(contentPacket.substring(76, 84),16));
		System.out.println("TCP: Acknowledgement Number :" +Long.parseLong(contentPacket.substring(84, 92),16));
		System.out.println("TCP: Data Offset :" +Integer.parseInt(contentPacket.substring(92, 93),16)*4+ " bytes");
		System.out.println("TCP: Flag : 0x" +contentPacket.substring(94, 96));
		
		int serviceFlag3 = Integer.parseInt(contentPacket.substring(94,96),16);
		String flag2 = Integer.toBinaryString(serviceFlag3);
		
		int length_flag2 = flag2.length();
		int diff_length = 6-length_flag2;
		String prepend_zeros = "";
		if(diff_length == 0) {
			System.out.println();
		}
		else {
			for(int i = 0; i<diff_length; i++)
				prepend_zeros += "" + 0;
			flag2 = prepend_zeros + flag2;
		}
				
		System.out.println("TCP: .."+flag2.substring(0, 1)+ "..... = No urgent pointer");
		System.out.println("TCP: .."+flag2.substring(1, 2)+ ".... = Acknowledgement ");
		System.out.println("TCP: .."+flag2.substring(2, 3)+ "... = Push ");
		System.out.println("TCP: .."+flag2.substring(3, 4)+ ".. = No reset ");
		System.out.println("TCP: .."+flag2.substring(4, 5)+ ". = No Syn ");
		System.out.println("TCP: .."+flag2.substring(5, 6)+ " = No Fin ");
		
		System.out.println("TCP: Window : " +Integer.parseInt(contentPacket.substring(96, 100),16));
		System.out.println("TCP: Checksum :0x" +contentPacket.substring(100, 104));
		System.out.println("TCP: Urgent Pointer :" +Integer.parseInt(contentPacket.substring(104, 108),16));
		System.out.println("TCP: ");
		System.out.println("TCP: Data: (First 64 bytes) ");
		System.out.println("TCP: Data " +contentPacket.substring(108, 112) + " " + contentPacket.substring(112,116) + " " + contentPacket.substring(116, 120) + " " + contentPacket.substring(120, 124));
		System.out.println("TCP: Data " +contentPacket.substring(124, 128) + " " +contentPacket.substring(128, 132) + " " + contentPacket.substring(132, 136) + " " + contentPacket.substring(136, 140));
		System.out.println("TCP: Data " +contentPacket.substring(140, 144) + " " +contentPacket.substring(144, 148) + " " + contentPacket.substring(148, 152) + " " + contentPacket.substring(152, 156));
		System.out.println("TCP: Data " +contentPacket.substring(156, 160) + " " +contentPacket.substring(160, 164) + " " + contentPacket.substring(164, 168) + " " + contentPacket.substring(168, 172));
	}
	
	/**
	 * This method is implemented to print the UDP header fields from the 
	 * corresponding packet. It takes the substring of the string and if the 
	 * value of the Protocol field in the IP Protocol is 17.
	 * @param contentPacket
	 */
	public void printUdp(String contentPacket)
	{
		System.out.println("UDP:  ----- UDP Header ----- ");
		System.out.println("UDP: ");
		System.out.println("UDP:  Source Port Number " +Integer.parseInt(contentPacket.substring(68, 72),16) );
		System.out.println("UDP:  Destination Port Number " +Integer.parseInt(contentPacket.substring(72, 76),16) );
		System.out.println("UDP:  Length " +Integer.parseInt(contentPacket.substring(76, 80),16));
		System.out.println("UDP:  Checksum " +contentPacket.substring(80, 84));
		System.out.println("UDP: ");
		System.out.println("UDP: Data: (First 64 Bytes)");
		System.out.println("UDP: Data " +contentPacket.substring(84, 88) + " " +contentPacket.substring(88, 92) + " " + contentPacket.substring(92, 96) + " " + contentPacket.substring(96, 100));
		System.out.println("UDP: Data " +contentPacket.substring(100, 104) + " " +contentPacket.substring(104, 108) + " " + contentPacket.substring(108, 112) + " " + contentPacket.substring(112, 116));
		System.out.println("UDP: Data " +contentPacket.substring(116, 120) + " " +contentPacket.substring(120, 124) + " " + contentPacket.substring(124, 128) + " " + contentPacket.substring(128, 132));
		System.out.println("UDP: Data " +contentPacket.substring(132, 136) + " " +contentPacket.substring(136, 140) + " " + contentPacket.substring(140, 144) + " " + contentPacket.substring(144, 148));
	}
	
	/**
	 * This is the main method which takes the file in as command line argument
	 * and calls the methods.
	 * @param 	args	command line argument
	 */
	public static void main(String args[])
	{
		String file = args[0];
		Packetanalyzer analyze = new Packetanalyzer();
		try
		{
			File fileName = new File(file);
			byte[] byteFile = new byte[(int) fileName.length()];
			FileInputStream fileStream = new FileInputStream(fileName);
			fileStream.read(byteFile);
			fileStream.close();
			
			String contentPacket = javax.xml.bind.DatatypeConverter.printHexBinary(byteFile);
			analyze.printEthernet(contentPacket);
			int protocol = analyze.printIp(contentPacket);
			
			if(protocol == 1)
			{
				analyze.printIcmp(contentPacket);
			}
			
			else if(protocol == 6)
			{
				analyze.printTcp(contentPacket);
			}
			
			else if(protocol == 17)
			{
				analyze.printUdp(contentPacket);	
			}
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
}
