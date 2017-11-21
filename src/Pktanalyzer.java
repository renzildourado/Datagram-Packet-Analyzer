import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Foundation of Computer Networks 
 * Project 1
 
 * This program takes a .bin packet file and prints the 
 * headers namely TCP, UDP, IP, ICMP.
 * 
 * @author Renzil Dourado (rd9012)
 */

//dskfvdsfgv


public class Pktanalyzer {

    /**
     * @param args the command line arguments
     */
    static int protocolNumber;
    public static void main(String[] args) throws IOException{


        File packet = new File(args[0]);    				//Takes file path
        String hex = binToHex(packet);                      //Converts the .bin packet into a hex dump
        hex = Ethernet(hex);                                //Prints the Ethernet header
        hex = IP(hex);                                      //Prints the IP header
        switch(protocolNumber)                              //Prints the respective header based
        {                                                   //on protocol number
            case 1:
                ICMP(hex);
                break;
            case 6:
                TCP(hex);
                break;
            case 17:
                UDP(hex);
                break;
        }

    }
    
    
    /**
     * This method prints the Ethernet header of the packet
     * @param hex hex dump of the file
     * @return remaining hex dump of the file after clipping off the Ethernet header
     */
    public static String Ethernet(String hex)
    {
        System.out.println("ETHER:\t -------Ether Header-------");
        System.out.println("ETHER:\t ");
        System.out.println("ETHER:\t Packet Size = "+hex.length()/2 +" bytes");
        System.out.println("ETHER:\t Destination = "+getMac(hex.substring(0, 12)));
        System.out.println("ETHER:\t Source      = "+getMac(hex.substring(12, 24)));
        System.out.print("ETHER:\t EtherType   = "+hex.substring(24, 28));
        if(hex.substring(24, 28).equals("0800"))
            System.out.println("(IPv4)");
        else
            System.out.println("Code not written for anything except IPv4 packets");
        System.out.println("ETHER:\t ");
        return(hex.substring(28));

    }

    /**
     * This method prints the IP header
     * @param hex the hex dump of the file returned by Ethernet method
     * @return hex dump of the file excluding the IP header
     */
    public static String IP(String hex)
    {
        System.out.println("IP:\t -------IP Header-------");
        System.out.println("IP:\t ");
        System.out.println("IP:\t Version = "+hex.charAt(0));
        System.out.println("IP:\t Header Length = "+Character.getNumericValue(hex.charAt(1))*4+" bytes");
        String flag = hexToBin(hex.substring(2, 4));                    //Converting the hex dump to binary for flags
        String precedence = flag.substring(0,3);
        String threeflags = flag.substring(3, 6);
        System.out.println("IP:\t Type of Service       = 0x"+hex.substring(2,4));
        System.out.print("IP:\t \t     "+precedence+". .... = (precedence)");
        switch(precedence)
        {
            case "000":
                System.out.println("Routine");
                break;
            case "001":
                System.out.print("Priority");
                break;
            case "010":
                System.out.print("Immediate");
                break;
            case "011":
                System.out.print("Flash");
                break;
            case "100":
                System.out.print("Flash Override");
                break;
            case "101":
                System.out.print("CRITIC/EPC");
                break;
            case "110":
                System.out.print("Internetwork Control");
                break;
            case "111":
                System.out.print("Network Control");
                break;

        }

        if(threeflags.charAt(0)=='1')
            System.out.println("IP:\t \t     ...1 .... = Low Delay");
        else
            System.out.println("IP:\t \t     ...0 .... = Normal Delay");

        if(threeflags.charAt(1)=='1')
            System.out.println("IP:\t \t     .... 1... = High Throughput");
        else
            System.out.println("IP:\t \t     .... 0... = Normal Throughput");

        if(threeflags.charAt(2)=='1')
            System.out.println("IP:\t \t     .... .1.. = High Reliability");
        else
            System.out.println("IP:\t \t     .... .0.. = Normal Reliability");

        System.out.println("IP:\t Total length          = "+Integer.parseInt(hex.substring(4, 8), 16)+" bytes");
        System.out.println("IP:\t Identification        = "+Integer.parseInt(hex.substring(8, 12), 16));
        String bits = hexToBin(hex.substring(12, 14))+hexToBin(hex.substring(14, 16));

        System.out.println("IP:\t Flags      = 0x"+hex.substring(12, 13));
        System.out.print("IP:     ."+bits.charAt(1)+".. ....   = ");
        if(bits.charAt(1)=='1')
            System.out.println("do not fragment");
        else
            System.out.println("may fragment");

        System.out.print("IP:     .."+bits.charAt(2)+". ....   = ");
        if(bits.charAt(2)=='1')
            System.out.println("more fragments");
        else
            System.out.println("last fragment");

        System.out.println("IP:\t Fragment Offset     = "+Integer.parseInt(bits.substring(3),2)*8+" bytes");
        System.out.println("IP:\t Time to live        = "+Integer.parseInt(hex.substring(16, 18), 16)+" seconds/hops");
        protocolNumber=Integer.parseInt(hex.substring(18, 20), 16);
        System.out.print("IP:\t Protocol            = "+protocolNumber);
        switch(protocolNumber)                                      //Switch statement to print the type of protocol
        {
            case 1:
                System.out.println("(ICMP)");
                break;
            case 6:
                System.out.println("(TCP)");
                break;
            case 17:
                System.out.println("(UDP)");
                break;
        }
        System.out.println("IP:\t Header Checksum     = "+hex.substring(20, 24));
        System.out.println("IP:\t Source address      = "+getIP(hex.substring(24, 32))+","+DNS(getIP(hex.substring(24, 32))));
        System.out.println("IP:\t Destination address = "+getIP(hex.substring(32, 40))+","+DNS(getIP(hex.substring(32, 40))));

        System.out.println("IP:\t");
        return(hex.substring(40));

    }
 
     /**
     * This method prints the TCP header
     * @param hex the hex dump of the file returned by IP method
     */
    public static void TCP(String hex)
    {
        System.out.println("TCP:\t -------TCP Header-------");
        System.out.println("TCP\t");
        System.out.println("TCP:\t Source port              = "+Integer.parseInt(hex.substring(0, 4), 16));
        System.out.println("TCP:\t Destination port         = "+Integer.parseInt(hex.substring(4, 8), 16));
        System.out.println("TCP:\t Sequence Number          = "+new BigInteger(hex.substring(8, 16), 16));
        System.out.println("TCP:\t Acknowledgement Number   = "+new BigInteger(hex.substring(16, 24), 16));
        System.out.println("TCP:\t Data offset              = "+(Integer.parseInt(hex.substring(24, 25), 16))*4+" bytes");
        String flags = hexToBin(hex.substring(25, 26)).substring(4)+hexToBin(hex.substring(26, 28));
        System.out.println("TCP: Flags                 = 0x"+hex.substring(25,28));
        System.out.println("TCP:     "+flags.charAt(0)+flags.charAt(1)+flags.charAt(2)+". .... ....   =  Reserved for future use");
        if(flags.charAt(3)=='0')
            System.out.println("TCP:     ..."+flags.charAt(3)+" .... ....   =  Nonce not set");
        else
            System.out.println("TCP:     ..."+flags.charAt(3)+" .... ....   =  Nonce set");

        if(flags.charAt(4)=='0')
            System.out.println("TCP:     .... "+flags.charAt(4)+"... ....   =  Congestion Window Reduced not set");
        else
            System.out.println("TCP:     .... "+flags.charAt(4)+"... ....   =  Congestion Window Reduced set");

        if(flags.charAt(5)=='0')
            System.out.println("TCP:     .... ."+flags.charAt(5)+".. ....   =  ECN-echo not set");
        else
            System.out.println("TCP:     .... ."+flags.charAt(5)+".. ....   =  ECN-echo set");

        if(flags.charAt(6)=='0')
            System.out.println("TCP:     .... .."+flags.charAt(6)+". ....   =  No Urgent Pointer");
        else
            System.out.println("TCP:     .... .."+flags.charAt(6)+". ....   =  Urgent Pointer");

        if(flags.charAt(7)=='0')
            System.out.println("TCP:     .... ..."+flags.charAt(7)+" ....   =  No Acknowledgement");
        else
            System.out.println("TCP:     .... ..."+flags.charAt(7)+" ....   =  Acknowledgement");


        if(flags.charAt(8)=='0')
            System.out.println("TCP:     .... .... "+flags.charAt(8)+"...   =  No Push");
        else
            System.out.println("TCP:     .... .... "+flags.charAt(8)+"...   =  Push");

        if(flags.charAt(9)=='0')
            System.out.println("TCP:     .... .... ."+flags.charAt(9)+"..   =  No Reset");
        else
            System.out.println("TCP:     .... .... ."+flags.charAt(9)+"..   =  Reset");

        if(flags.charAt(10)=='0')
            System.out.println("TCP:     .... .... .."+flags.charAt(10)+".   =  No Sync");
        else
            System.out.println("TCP:     .... .... .."+flags.charAt(10)+".   =  Sync");

        if(flags.charAt(11)=='0')
            System.out.println("TCP:     .... .... ..."+flags.charAt(11)+"   =  No Fin");
        else
            System.out.println("TCP:     .... .... ..."+flags.charAt(11)+"   =  Fin");

        System.out.println("TCP:\t Window           = "+Integer.parseInt(hex.substring(28,32), 16));
        System.out.println("TCP:\t Checksum         = "+hex.substring(32,36));
        System.out.println("TCP:\t Urgent Pointer   = "+Integer.parseInt(hex.substring(36,40), 16));
        System.out.println("TCP:\t Data: (first 64 bytes) ");
        System.out.print("TCP:\t");
        printData(hex.substring(40));
        
    }


    /**
     * This method prints the UDP header
     * @param hex the hex dump returned by the IP method
     */
    public static void UDP(String hex)
    {
        System.out.println("UDP:\t -------UDP Header-------");
        System.out.println("UDP\t");
        System.out.println("UDP:\t Source port              = "+Integer.parseInt(hex.substring(0, 4), 16));
        System.out.println("UDP:\t Destination port         = "+Integer.parseInt(hex.substring(4, 8), 16));
        System.out.println("UDP:\t Length                   = "+Integer.parseInt(hex.substring(8, 12), 16));
        System.out.println("UDP:\t Checksum                 = "+hex.substring(12, 16));
        System.out.println("UDP:\t Data: (first 64 bytes) ");
        System.out.print("UDP:\t");
        printData(hex.substring(16));

    }

    /**
     * This method prints the ICMP header 
     * @param hex hex dump returned by the IP method 
     */
    public static void ICMP(String hex)
    {
        System.out.println("ICMP:\t -------ICMP Header-------");
        System.out.println("ICMP\t");
        System.out.println("ICMP:\t Type              = "+Integer.parseInt(hex.substring(0, 2), 16));
        System.out.println("ICMP:\t Code              = "+Integer.parseInt(hex.substring(2, 4), 16));
        System.out.println("ICMP:\t Checksum          = "+hex.substring(4, 8));

    }
    
    
    /**
     * This method accepts the .bin file as input and returns a 
     * string which is a hex dump of the .bin file
     * @param packet the .bin file
     * @return hex dump
     * @throws FileNotFoundException
     * @throws IOException 
     */
    public static String binToHex(File packet) throws FileNotFoundException, IOException
    {
        InputStream input = new FileInputStream(packet);
        int binary;
        String hex = "";

        while ((binary = input.read())!= -1)
        {
            hex += String.format("%02X", binary);           //converting the file to hex
        }
        return hex;
    }
    
    /**
     * This method prints the data part for the TCP or UDP header
     * @param hex hex dump returned by the TCP/UDP method
     */
    public static void printData(String hex)
    {
        int count = 0;
        String oneLine = "";
        String formatting = "";
        if(protocolNumber == 6)
            formatting = "TCP:\t";
        if(protocolNumber == 17)
            formatting = "UDP:\t";
        for(int i=0; i<hex.length();i++)
        {
            count++;
            System.out.print(hex.charAt(i));
            if(count%4 ==0)
                System.out.print(" ");              //for a space between two hex characters
            oneLine += hex.charAt(i);
            if(count%32==0||i==hex.length()-1)      //end of line
            {
                System.out.print(" \" ");
                for(int j=0; j<oneLine.length(); j+=2)
                {
                    if(Integer.parseInt(oneLine.substring(j, j+2), 16)>=33 && Integer.parseInt(oneLine.substring(j, j+2), 16)<=127) //readable range of ASCII values
                    {
                        System.out.print(Character.toString((char)Integer.parseInt(oneLine.substring(j, j+2), 16)));        //prints the data in readable format
                    }
                    else
                        System.out.print(".");
                }
                System.out.print(" \" ");
                System.out.println();
                System.out.print(formatting);
                oneLine = "";
            }

            if(count==128)          //to maintain only 64 bytes of data
                break;

        }
    }

    
    /**
     * This method performs a lookup for the domain name of the specified IP
     * address
     * @param ip string containing the IP address to be looked up
     * @return IP address
     */
    public static String DNS(String ip)
    {
        InetAddress address = null;
        int error = 0;
        try
        {
            address = InetAddress.getByName(ip);
        }
        catch (UnknownHostException ex)
        {
            error = 1;
        }
        if(error==0)
        {
            if(address.getHostName().equals(ip))
                return ("Unknown Host");
            else
                return(address.getHostName());
        }
        else
            return ("Unknown Host");
    }

    /**
     * This method converts the given hex dump to binary
     * @param hex hex dump string to be converted to binary
     * @return binary string
     */
    public static String hexToBin(String hex)
    {
        int number = Integer.parseInt(hex, 16);
        String binary = Integer.toBinaryString(number);
        while(binary.length()!=8)
            binary = "0"+binary;        //makes sure binary bits are groups of 8 bits i.e a byte
        return binary;
    }

    /**
     * This method returns the MAC address with the colons in between
     * @param hex string of MAC address
     * @return the MAC address with colons in between
     */
    public static String getMac(String hex)
    {
        String mac = "";
        for(int i=0; i<hex.length();i+=2)
        {
            mac += hex.substring(i, i+2);
            if(i+2!=hex.length())
                mac += ":";
        }

        return mac;
    }

    /**
     * This method returns the IP address which has dots in between and is in
     * decimal format
     * @param hex hex code of the IP address
     * @return decimal IP address
     */
    public static String getIP(String hex)
    {
        String IP = "";
        for(int i=0; i<hex.length(); i+=2)
        {
            IP += Integer.parseInt(hex.substring(i, i+2), 16);
            if(i+2!=hex.length())
                IP += ".";
        }

        return IP;
    }

}
