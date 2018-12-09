/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocoloenvia.envia;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;  
import java.util.ArrayList;  
import java.util.Arrays;  
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;  
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;



public class Envia {  
    public static StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    public static PcapIf dispositivo;
    public static Pcap pcap;
    public static byte[] MACo, MACd;
    public static Thread hiloPrincipal;
    
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
    
    private static String getNombreArchivo(byte[] nombre){//Obtiene el nombre del archivo en texto
        String n = "";
        for(int i = 0; i <nombre.length; i++){
            n += (char)nombre[i];
        }
        return n;
    }
    
    public static byte[] getNombrePacket(byte[] trama){//Obtener nombre del archivo del paquete recibido en bytes
        int k=0;
        int l = (trama[20]==0)?trama[21]:(trama[20]*256)+trama[21];
        byte [] nombre = new byte[trama[l]];
        for(int c=22;c<(trama[l]+22);c++)
        {
            nombre[k]=trama[c];
            k++;
        }
        return nombre;
    }
    
    
    public static byte[] getArchivoPacket(byte[] trama){//Obtener el archivo del paquete recibido en bytes
        int k=0;
        int inicio = (trama[20]==0)?trama[21]:(trama[20]*256)+trama[21];
        int l = (trama[18]==0)?trama[19]:(trama[18]*256)+trama[19];
        byte [] archivo = new byte[trama[l]];
        for(int c=(22+inicio);c<(trama[l]+inicio+22);c++)
        {
            archivo[k]=trama[c];
            k++;
        }
        return archivo;
    }
    
    public static int getLong(byte[] informacion){//Obtiene la longitud del archivo o nombre a enviar
        return informacion.length;
    }
    
    public static byte[] getBytes(String info){//Obtiene el arreglo de bytes del archivo o nombre a enviar
        return info.getBytes();
    }
    
    public static void llenarTrama(byte[] trama, byte[] MACdestino, byte[] MACorigen, byte[] narch, byte[] buf, int tamname, int tamarch){
        //Llena la trama a enviar
        for(int k=0;k<MACorigen.length;k++){
            trama[k] = MACdestino[k];
            trama[k+6]=MACorigen[k];
        }
        
        int byte_long1, byte_long2, long1_n, long2_n;
        long chk1, chk2;
        trama[12]= (byte) 0x11; //tipo sin asignar
        trama[13]= (byte) 0x00; //tipo sin asignar rfc 1340 
        
        trama[17]= (byte) 0xC1; //Protocolo 0xC1

        byte_long1=(tamarch>>8)&0xFF;
        byte_long2=(tamarch)&0x00FF;
        
        trama[18]= (byte) byte_long1;//Longitud del mensaje divida en 2 bytes
        trama[19]= (byte) byte_long2;
        
        long1_n=(tamname>>8)&0xFF;
        long2_n=(tamname)&0x00FF;
        
        trama[20]= (byte) long1_n;//Longitud del nombre divida en 2 bytes
        trama[21]= (byte) long2_n;

        chk1=(Checksum.calculateChecksum(buf)>>8)&0xFF;
        chk2=(Checksum.calculateChecksum(buf))&0x00FF;
        
        trama[22+tamname+tamarch]= (byte)chk1;//Checksum del mensaje divido en 2 bytes
        trama[23+tamname+tamarch]= (byte)chk2;
        
        for(int c=0;c<tamname;c++)
            trama[22+c]=narch[c];
        
        for(int c=0;c<tamarch;c++)
                trama[22+tamname+c]=buf[c];
        
        if(tamarch<=1500){
            trama[14]=(byte)0xA0;
            
        } //Si el mensaje es pequeño, sera de subtipo P=A0
        else{
            trama[14]=(byte)0xA1;
        } //Si el mensaje es grande, sera de subtipo G=A1
        
    }
    
    
    public static void DividirPacket(byte[] trama, byte[] archivo,int tamarchivo){
        if(tamarchivo%1500 !=0){
            int cociente = (int)tamarchivo/1500;
            int residuo = tamarchivo-(cociente*1500);
            int partes=cociente+1;
            
        }
    }
    

    
    public static PcapIf dispositivoRed(int interfaz){
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        String ip_interfaz="";
 
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			//return;
		}

		System.out.println("Dispositivos encontrados:");
		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                        Iterator<PcapAddr> it = device.getAddresses().iterator();
                        while(it.hasNext()){
                            PcapAddr dir = it.next();//dir, familia, mascara,bc
                            PcapSockAddr direccion =dir.getAddr();
                            byte[]d_ip = direccion.getData();
                            int familia=direccion.getFamily();
                            int[]ipv4 = new int[4];
                            if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                                ipv4[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                                ipv4[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                                ipv4[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                                ipv4[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                                
                                System.out.println("IP4->"+ipv4[0]+"."+ipv4[1]+"."+ipv4[2]+"."+ipv4[3]);
                            }else if(familia==org.jnetpcap.PcapSockAddr.AF_INET6){
                                System.out.print("IP6-> ");
                                for(int z=0;z<d_ip.length;z++)
                                    System.out.printf("%02X:",d_ip[z]);
                            }//if
                        }//while
                        System.out.printf("\n\n");
		}//for
                }catch(IOException io){
                  io.printStackTrace();
                }//catch
   try{
       BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
       //System.out.println("\nElije la interfaz de red:");
        PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device  
       /******************************************************/
        Iterator<PcapAddr> it1 = device.getAddresses().iterator();
        while(it1.hasNext()){
         PcapAddr dir = it1.next();//dir, familia, mascara,bc
         PcapSockAddr direccion1 =dir.getAddr();
         byte[]d_ip = direccion1.getData(); //esta sera la ip origen
         int familia=direccion1.getFamily();
         int[]ipv4_1 = new int[4];
         if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
            ipv4_1[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
            ipv4_1[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
            ipv4_1[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
            ipv4_1[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
            ip_interfaz = ipv4_1[0]+"."+ipv4_1[1]+"."+ipv4_1[2]+"."+ipv4_1[3];  
            System.out.println("Interfaz que se usara: "+ip_interfaz);
        }
        }

    return device;
        
   }catch(Exception e){
       e.printStackTrace();
       return null;
   }//catch
        
    }
    
    
    public static byte[] MAC(PcapIf device){
        /******************************************************/
        try{
       System.out.print("MAC ORIGEN: ");   
       byte[] MACorigen = device.getHardwareAddress();
       for(int j=0;j<MACorigen.length;j++){
           System.out.printf("%02X ",MACorigen[j]); 
       }
           System.out.println("");
            return MACorigen;
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }
    
    public static void filtro(){
          /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="ether proto 0x1100"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
    }
    
    public static void analizarPaquete(PcapPacket packet){
        
                                /******Desencapsulado********/
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
                                System.out.println("Tipo:");
                                for(int i=12;i<14;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
                                System.out.printf("\nTipo= %d",tipo);
                                if(tipo==4352){ //0x1100
                                   System.out.println("\n****************Este es mi mensaje que mande\n y los datos del mensaje son:");
                                   
                                   int lname=(packet.getUByte(20)==0)?packet.getUByte(21):(packet.getUByte(20)*256)+packet.getUByte(21);
                                   int j=0;
                                   byte[]n = new byte[lname];//Nombre
                                   for(int k=22;k<(lname+22);k++){
                                       System.out.printf("%02X ",packet.getUByte(k));
                                       n[j]=(byte)packet.getUByte(k);
                                       j++;
                                   }
                                        
                                   String namexd = getNombreArchivo(n);
                                   System.out.println("\n"+namexd);
                                   
                                   j=0;
                                   int larchivo=(packet.getUByte(18)==0)?packet.getUByte(19):(packet.getUByte(18)*256)+packet.getUByte(19);
                                   
                                   byte[]a = new byte[larchivo];//Nombre
                                   for(int k=(lname+22);k<(lname+22+larchivo);k++){
                                       System.out.printf("%02X ",packet.getUByte(k));
                                       a[j]=(byte)packet.getUByte(k);
                                       j++;
                                   }
                                        
                                   String datos = getNombreArchivo(a);
                                   System.out.println("\n"+datos);

                                for(int l=0;l<packet.size();l++){
                                System.out.printf("%02X ",packet.getUByte(l));
                                if(l%16==15)
                                    System.out.println("");
                                }
                                System.out.println("");

                                }
		
    }
    
    public static void recibirPaquetes(){
       PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>(){
                    @Override
                    public void nextPacket(PcapPacket packet, String user){
                                    System.out.printf("\n\nPaquete recibido el %s bytes capturados=%-4d tam original=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                        analizarPaquete(packet);
                    }
                };
       
            hiloPrincipal = new Thread(new Runnable(){
                    @Override
                    public void run(){
                        pcap.loop(Pcap.LOOP_INFINITE, jPacketHandler, "");
                    }
                });
            hiloPrincipal.start();
    }
    
    private static void  enviarTrama(byte [] trama){
        Thread hilo = new Thread(new Runnable(){
            @Override
            public void run(){
                pcap.sendPacket(trama);
            }
        });
        hilo.start();
    }
    
  public static void main(String[] args) {  
        /***************************************************************************
	       * First get a list of devices on this system
        **************************************************************************/
        dispositivo= dispositivoRed(0);//Seleccionamos interfaz de red
        if(pcap!=null){//IMPORTANTE. Si se omite lanza error
            pcap.close();
        }
        else{  
                try{
                   /***************************************** 
                    * Second we open a network interface 
                    *****************************************/  
                       pcap=Pcap.openLive(dispositivo.getName(), 64 * 1024, Pcap.MODE_PROMISCUOUS, 4 * 1000, errbuf);//Abrimos la conexion
                       
                   /******************************************************* 
                    * Third we create our crude packet we will transmit out 
                    * This creates a broadcast packet 
                    *******************************************************/ 
                       MACo=MAC(dispositivo);
                       MACd=MACo;//TEMPORAL!!!
                       String nombre1="hola.java";
                       String archivo1="Nunca mas.";

                       String nombre2="adios.java";
                       String archivo2="Nevermore.";

                       byte[] trama1 = new byte[getLong(getBytes(nombre1))+getLong(getBytes(archivo1))+24];
                       byte[] trama2 = new byte[getLong(getBytes(nombre2))+getLong(getBytes(archivo2))+24];

                       if(getLong(getBytes(nombre1))>50||getLong(getBytes(nombre2))>50)
                           System.out.println("Ha ocurrido un error. El tamaño máximo para el nombre del archivo es de 50 bytes.");
                       else{
                           llenarTrama(trama1, MACd, MACo, getBytes(nombre1), getBytes(archivo1), getLong(getBytes(nombre1)),getLong(getBytes(archivo1)));
                           llenarTrama(trama2, MACd, MACo, getBytes(nombre2), getBytes(archivo2), getLong(getBytes(nombre2)),getLong(getBytes(archivo2)));

                           filtro();

                           int sec=0, ack=0;

                   /******************************************************* 
                    * Fourth We send our packet off using open device 
                    *******************************************************/  
                           enviarTrama(trama1);//Enviar tramas
                           enviarTrama(trama2);
                           
                           recibirPaquetes();
                  }
            }catch(Exception e){
               e.printStackTrace();
           }//catch
        }
  }
}