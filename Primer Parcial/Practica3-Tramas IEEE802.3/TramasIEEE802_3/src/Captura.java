/*
IMPLEMENTACION DE LA INTERPRETACIÓN DE TRAMAS IEEE802.3
AUTOR(ES): 	Nicolás Sayago Abigail
                Ramos Díaz Enrique 
VERSIÓN: 1.0
DESCRIPCIÓN: Captura tramas IEEE802.3 desde un archivo pcap y después las clasifica.

*/
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
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

public class Captura
{
	private static String asString(final byte[] mac)
	{
		final StringBuilder buf = new StringBuilder();
		for(byte b : mac)
		{
			if(buf.length() != 0)
				buf.append(':');
			if(b >= 0 && b < 16)
				buf.append('0');
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		} // Fin FOR
		return buf.toString();
	}
	public static void main(String[] args)
	{
		Pcap pcap = null;
		try
		{
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			List<PcapIf> alldevs = new ArrayList<PcapIf>();
			StringBuilder errbuf = new StringBuilder();
			//System.out.println("[1]--> Cargar traza de captura desde archivo");
			//System.out.print("\n Elige una de las opciones:");
			//int opcion = Integer.parseInt(br.readLine());
			//if(opcion == 1) {
				// Lee el archivo
				String fname = "paquetes3.pcap";
				pcap = Pcap.openOffline(fname, errbuf);
				if(pcap == null)
				{
					System.err.printf("Error" + errbuf.toString());
					return;
				}
			//1}

			/*****************************************************
			* Creamos un packet handler cuando recibamos paquetes
			* desde la libpcap loop
			******************************************************/
			PcapPacketHandler<String> jpacketHandler; // Fin PcapPacketHandler
                    jpacketHandler = new PcapPacketHandler<String>()
                    {
                        public void nextPacket(PcapPacket packet, String user)
                        {
                            System.out.printf("\n\n\n Paquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
                                    new Date(packet.getCaptureHeader().timestampInMillis()),
                                    packet.getCaptureHeader().caplen(),
                                    packet.getCaptureHeader().wirelen(),
                                    user
                            );
                            ///////////////////////////////////////////////////
                            ///////////////// DESENCAPSULADO /////////////////
                            /////////////////////////////////////////////////
                            
                            for(int i = 0; i<packet.size(); i++)
                            {
                                System.out.printf("%02X ", packet.getUByte(i));
                                if(i%16 == 15)
                                    System.out.println("");
                            } // Fin FOR
                            
                            int longitud = (packet.getUByte(12)*256) + packet.getUByte(13);
                            System.out.printf("\nLongitud: %d (%04X)", longitud, longitud);
                            /*
                            System.out.printf("PRUEBA");
                            int B12 = packet.getUByte(12);
                            int B12R = packet.getUByte(12)*256;
                            int B13 = packet.getUByte(13);
                           System.out.printf("\nB12: %d (%02X)" , B12, B12);
                           System.out.printf("\nB12R: %d (%02X)", B12R, B12R);
                           System.out.printf("\nB13: %d (%02X)", B13, B13);
                            */
                            
                            // Seleccionamos el tipo de trama
                            if(longitud<1500)
                            {
                                System.out.println("---> Trama IEEE802.3");
                                System.out.printf("|-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(0),packet.getUByte(1),packet.getUByte(2),packet.getUByte(3),packet.getUByte(4),packet.getUByte(5));
                                System.out.printf("\n|-->MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(6),packet.getUByte(7),packet.getUByte(8),packet.getUByte(9),packet.getUByte(10),packet.getUByte(11));
                                
                                int dsap = packet.getUByte(14)& 0x00000001;
                                String i_g = (dsap==1)?"Grupal":(dsap==0)?"Individual":"Otro";
                                System.out.printf("\n|-->DSAP: %02X   %s",packet.getUByte(14), i_g);
                                //System.out.println(packet.getUByte(15)& 0x00000001);
                                
                                int ssap = packet.getUByte(15)& 0x00000001;
                                String c_r = (ssap==1)?"Respuesta":(ssap==0)?"Comando":"Otro";
                                System.out.printf("\n|-->SSAP: %02X   %s",packet.getUByte(15), c_r);
                                
                                
                                
                                //////////////////////////////////////////////////////////////
                                ///////////// Clasificacion de Tramas IEEE802.3 /////////////
                                ////////////////////////////////////////////////////////////
                                // Elige el byte 16 para seleccionar que tipo de trama es
                                
                                int c = packet.getUByte(16);
                                int c1, c2;
                                byte control1, control2;
                                control1 = (byte)(c>>4);
                                control2 = (byte)(c& 0x0f);
                                
                                if(longitud>3) // CAMPO DE CONTROL mide 2 Bytes
                                {
                                     System.out.printf("\n|-->Control: %02X %02X",packet.getUByte(16), packet.getUByte(17));
                                    // Como el campo de control mide 2 bytes, los separamos
                                    int b1, b2;
                                    
                                    if((c & 0x01) == 1) // Puede ser una trama S o U
                                    {
                                        if((c & 0x02) == 0) // Es una trama S
                                        {
                                           
                                            System.out.println("\nEs una trama de SUPERVISION extendido");
                                            b1 = packet.getUByte(16)>>2;
                                            b2 = packet.getUByte(17)>>1;
                                            SupervisionExtendido(b1,b2);
                                        }
                                        else // Es una trama U
                                        {
                                            System.out.println("\nEs una trama UNNUMBER");
                                          
                                            c1=control1>>1;
                                            c2=control2>>2;
                                            Unnumber(c2, c1);
                                        }
                                    }
                                    else // Es una trama I
                                    {
                                        System.out.println("\nEs una trama de INFORMACION extendido");
                                        b1 = packet.getUByte(16)>>1;
                                        b2 = packet.getUByte(17)>>1;
                                        InformacionExtendido(b1,b2);
                                    }
                                } // Fin Longitud
                                
                                else // Suponemos que el campo de control mide 1 Byte
                                {
                                    System.out.printf("\n|-->Control: %02X",packet.getUByte(16));
                                    if((c & 0x01) == 1) // Puede ser una trama S o U
                                    {
                                        if((c & 0x02) == 0) // Es una trama s
                                        {
                                            System.out.println("\nEs una trama de SUPERVISION");
                                            c1=control1>>1;
                                            c2=control2>>2;
                                            Supervision(c2, c1);//Se envia el byte invertido
                                        }
                                        else // Es una trama u
                                        {
                                            System.out.println("\nEs una trama UNNUMBER");
                                            c1=control1>>1;
                                            c2=control2>>2;
                                            
                                            Unnumber(c2, c1);//Se envia el byte invertido
                                        }
                                    }
                                    else // Es una trama I
                                    {
                                        System.out.println("\nEs una trama de INFORMACION");
                                        c1=control1>>1;
                                        c2=control2>>1;
                                        Informacion(c2, c1);//Se envia el byte invertido
                                    }
                                } // Fin Else campo control 1 Byte
                                
                            }
                            else if(longitud>=1500)
                                System.out.println("---> Trama ETHERNET");
                        } // Fin NextPacket
                        
                        public void Informacion(int Ns, int Nr)
                        {
                            System.out.printf("\nN(S): %d (%04X)", Ns, Ns);
                            System.out.printf("\nN(R): %d (%04X)", Nr, Nr);
                        } // Fin Informacion
                        
                        public void InformacionExtendido(int Ns, int Nr)
                        {
                            System.out.printf("\nN(S): %d  (%04X)", Ns, Ns);
                            System.out.printf("\nN(R): %d  (%04X)", Nr, Nr);
                        }
                        public void Supervision(int c1, int Nr)
                        {
                            SupervisionInterpretacion(c1); 
                            System.out.printf("\nN(R): %d  (%04X)", Nr, Nr);
                        } //Fin Supervision
                        
                        public void SupervisionExtendido(int B1, int Nr)
                        {
                            SupervisionInterpretacion(B1);
                            System.out.printf("\nN(R): %d (%04X)", Nr, Nr);
                        }
                        
                        public void SupervisionInterpretacion(int CO)
                        {
                            // Interpretacion de CODIGO
                            if((CO & 0x01 ) == 0) // Puede ser RR o REJ
                            {
                                if((CO & 0x02) == 0) // Es RR
                                    System.out.printf("\nCODIGO: 00 Listo para recibir (RR)");
                                else
                                    System.out.printf("\nCODIGO: 01 Rechazado (REJ)");
                            }
                            else // Puede ser  RNR o SRES
                            {
                                if((CO & 0x02 ) == 0) // Es RNR
                                    System.out.printf("\nCODIGO: 10 No Listo para recibir (RR)");
                                else
                                    System.out.printf("\nCODIGO: 11 Rechazo selectivo (REJ)");
                            }
                        }
                        public void Unnumber(int C1, int C2)
                        {

                            System.out.printf("\nCODIGO: %d  (%04X)", C1, C1);
                            System.out.printf("\nCODIGO: %d  (%04X)", C2, C2);
                            // Interpretacion de CODIGO
                            if(((C1 & 0xF0) == 0) && ((C1 & 0x0F) == 0)) // Puede ser 00
                            {
                                if((C2 & 0x01) == 0) //Puede ser SNRM, UI, DISC 00 0...
                                {
                                    if((C2 & 0x02) == 0) // 00 00...
                                    {
                                        if((C2 & 0x04) == 0) // 00 00 0
                                            System.out.printf("\nCODIGO: 00 000   Informacion sin Numerar (UI)\n");
                                        else // 00 00 1
                                            System.out.printf("\nCODIGO: 00 001    Activacion Modo Respuesta Normal (SNRM)\n");
                                    }
                                    else // 00 010
                                        System.out.printf("\nCODIGO: 00 010    Desconexion (DISC)\n");
                                }
                                else // Puede ser 00 1
                                {
                                    if((C2 & 0x02) == 0) // 00 10...
                                        System.out.printf("\nCODIGO: 00 100    Sondeo sin numerar (UP)\n");
                                    
                                    else // 00 11
                                        System.out.printf("\nCODIGO: 00 110    Reconocmiento sin numerar (UA)\n");
                                }
                            }
                            else // Puede ser  11...
                            {
                                
                                if((C2&0x01) == 0) // 11 0
                                {
                                    if((C2&0x02) == 0) // 11 00
                                    {
                                        if((C2&0x04) == 0) // 11 00 0
                                            System.out.printf("\nCODIGO: 11 000    Activacion modo de respuesta Asincrona (SARM)\n");
                                        else // 11 00 1
                                            System.out.printf("\nCODIGO: 11 001    Reinicio (RSET)\n");
                                    }
                                    else // 11 01
                                    {
                                        if((C2&0x04) == 0) // 11 01 0
                                            System.out.printf("\nCODIGO: 11 010    Activacion modo de respuesta extendido (SARME)\n");
                                        else // 11 01 1
                                            System.out.printf("\nCODIGO: 11 011    Activacion modo de respuesta extendido (SNRME)\n");
                                    }
                                }
                                else  // 11 1
                                {
                                    if((C2&0x02) == 0) // 11 10
                                    {
                                        if ((C2&0x04) == 0) // 11 10 0
                                            System.out.printf("\nCODIGO: 11 100    Activación Modo de Respuesta Balanceado (SABM)\n");
                                        else // 11 10 1
                                            System.out.printf("\nCODIGO: 11 101    Intercambio de ID (XID)\n");
                                    }
                                    else  // 11 11 0
                                        System.out.printf("\nCODIGO: 11 110    Activación Modo de Respuesta Balanceado (SABME)\n");
                                }
                            }
                        }   
                    };

			pcap.loop(-1, jpacketHandler, " ");

			pcap.close();
		} // Fin TRY
		catch(Exception e)
		{
			e.printStackTrace();
		}

	} // Fin Main

} // Fin Class TramaIEEE

