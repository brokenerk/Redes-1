package captura;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;


public class Captura {

   private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }

	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

		}//for

		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		System.out
		    .printf("\nChoosing '%s' on your behalf:\n",
		        (device.getDescription() != null) ? device.getDescription()
		            : device.getName());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

		int snaplen = 64 * 1024;           // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000;           // 10 seconds in millis
                Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}//if

                       /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression =""; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
                /****************/


		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the
		 * libpcap loop.
		 **********************************************************************/
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {

				System.out.printf("\n\n\nPaquete recibido el %s caplen=%-4d len=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                /******Desencapsulado********/
                                

                                System.out.println("\nTrama:");
                                for(int i=0;i<packet.size();i++){
                                	System.out.printf("%02X ",packet.getUByte(i));
                                	if(i%16==15)
                                    	System.out.println("");
                                }
                                
                                System.out.println("\n\nEncabezado: \n"+ packet.toHexdump());

                                System.out.println("MAC destino:");
                                for(int i=0;i<6;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");

                                System.out.println("MAC origen:");
                                for(int i=6;i<12;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");

                                System.out.println("Tipo (hexadecimal):");
                                for(int i=12;i<14;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                            
                                int tipo = (packet.getUByte(12)==0)?packet.getUByte(13):(packet.getUByte(12)*256)+packet.getUByte(13);
                                System.out.printf("Tipo (decimal) = %d",tipo);
                                System.out.println("");

                                //------------------CHECKSUM CAPA DE RED-----------------------------

                                if(tipo==2048)
                                { // Verifica que el protocolo de la capa de red sea IP: 2048 - decimal

                                //Calculamos el numero de bytes que corresponden a los datos de la trama
                                int n=packet.getUByte(14)&0x0F, bytesr=0; //Se apartan las posiciones 0-3 del arreglo de transporte para los bytes extras


                                //Creamos un arreglo para los bytes de datos
                                byte[] encabezado = new byte[n*4];
                                
                                //Ingresamos los bytes de datos al arreglo
                                for (int i=14; i<14+(n*4); i++)
                                {
                                	encabezado[bytesr]=(byte)packet.getUByte(i);
					bytesr++;
                                }

                                //Enviamos los bytes de datos para realizar el checksum de la trama
                                long chkr = Checksum.calculateChecksum(encabezado);
      				System.out.printf("Protocolo IP. Checksum de la Capa de Red: %02X\n",chkr);
                                
                                  //-------------CHECKSUM TRANSPORTE-----------
                                
                                int ltrans=(packet.size()-26)+4;//Longitud que tendra el pseudoencabezado: IPOrigen + IPDestino + 00 + Protocolo + LongitudPDUTransporte + PDUTransporte
                                int longitud=((packet.getUByte(16)==0)?packet.getUByte(17):(packet.getUByte(16)*256)+packet.getUByte(17))-(n*4); //Longitud de la trama menos longitud del arreglo del checksum de red IP (Ests es la LongitudPDUTransporte mencionada arriba)
                                int bytest=0; //Se apartan las posiciones 0-3 del arreglo de transporte para: 00 + Protocolo + LongitudPDUTransporte
                                byte[] pseudoenc = new byte[ltrans]; //Pseudoencabezado
                                
                                
                                //Ingresamos los campos: IPOrigen + IPDestino + PDUTransporte
                                for (int i=26; i<34; i++)
                                { 
                                	pseudoenc[bytest]=(byte)packet.getUByte(i);
					bytest++;
                                }

                                bytest=0;
                                
                                //Posicion 8: 0x00
                                pseudoenc[8]=0x00;
                                
                                //Posicion 10 y 11: Longitud PDUTransporte
                                int byte_long1=(longitud>>8)&0xFF, byte_long2=longitud&0x00FF; //Se divide la longitud del PDU (hexadecimal) en 2 bytes
                                
                                pseudoenc[10]=(byte)byte_long1;
                                pseudoenc[11]=(byte)byte_long2;
                                

      				if((byte)packet.getUByte(23)==0x11) //Revisa si es UDP: Byte 23: 11
      				{
                                    //Posicion 9: Protocolo
                                    pseudoenc[9]=0x11; // UDP: 11
                                    System.out.print("Protocolo UPD. ");
                                    bytest=12;
                                
                                    //Ingresamos los campos: PDUTransporte
                                    for (int i=34; i<packet.size(); i++)
                                    { 
                                	pseudoenc[bytest]=(byte)packet.getUByte(i);
					bytest++;
                                    }
                                
                                    /*for (int i=0; i<pseudoenc.length;i++){
                                        System.out.printf("\n%02X",pseudoenc[i]);
                                    }
                                    Imprime bytes del pseudoencabezado*/
                                    
                                    //Enviamos los bytes de datos para realizar el checksum de la capa de transporte
                                    long chkt = Checksum.calculateChecksum(pseudoenc);
                                    System.out.printf("Checksum de la Capa de Transporte: %02X\n",chkt);
                                    }
      				else if ((byte)packet.getUByte(23)==0x06) //Revisa si es TCP: Byte 23: 06
      				{
                                    //Posicion 9: Protocolo
                                    pseudoenc[9]=0x06; // TCP: 06
                                    System.out.print("Protocolo TCP. ");
                                    bytest=12;
                                
                                    //Ingresamos los campos: PDUTransporte
                                    for (int i=34; i<packet.size(); i++)
                                    { 
                                	pseudoenc[bytest]=(byte)packet.getUByte(i);
					bytest++;
                                    }
                                
                                    /*for (int i=0; i<pseudoenc.length;i++){
                                        System.out.printf("\n%02X",pseudoenc[i]);
                                    }
                                    Imprime bytes del pseudoencabezado*/

                                    //Enviamos los bytes de datos para realizar el checksum de la capa de transporte
                                    long chkt = Checksum.calculateChecksum(pseudoenc);
                                    System.out.printf("Checksum de la Capa de Transporte: %02X\n",chkt);
      				}

                            }
			}
		};




		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to sepecify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		pcap.loop(10, jpacketHandler, "");

		/***************************************************************************
		 * Last thing to do is close the pcap handle
		 **************************************************************************/
		pcap.close();
                }catch(IOException e){e.printStackTrace();}
	}
}
