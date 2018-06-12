/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package sniffer;
import java.lang.System;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import org.jnetpcap.packet.PcapPacket;
import static org.jnetpcap.packet.format.FormatUtils.asString;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;


public class Protocolos {
    public static int Num_ethernet=0, Num_ieee=0, Num_llci=0, Num_llcg=0, Num_arp=0, Num_rarp=0, Num_ip4=0, Num_tcp=0,Num_udp=0,Num_icmp=0, Num_ip6=0;

    public static void Informacion(int Ns, int Nr){
        Tramas.TxtArea.append(String.format("\nN(S): %d (%04X)", Ns, Ns));
        Tramas.TxtArea.append(String.format("\nN(R): %d (%04X)", Nr, Nr));
    } // Fin Informacion
                        
    public static void InformacionExtendido(int Ns, int Nr)
    {
        Tramas.TxtArea.append(String.format("\nN(S): %d  (%04X)", Ns, Ns));
        Tramas.TxtArea.append(String.format("\nN(R): %d  (%04X)", Nr, Nr));
    }
    public static void Supervision(int c1, int Nr)
    {
        SupervisionInterpretacion(c1); 
        Tramas.TxtArea.append(String.format("\nN(R): %d  (%04X)", Nr, Nr));
    } //Fin Supervision
    
    public static void SupervisionExtendido(int B1, int Nr)
    {
        SupervisionInterpretacion(B1);
        Tramas.TxtArea.append(String.format("\nN(R): %d (%04X)", Nr, Nr));
    }
    
    public static void SupervisionInterpretacion(int CO)
    {
        // Interpretacion de CODIGO
        if((CO & 0x01 ) == 0) // Puede ser RR o REJ
        {
            if((CO & 0x02) == 0) // Es RR
                Tramas.TxtArea.append(String.format("\nCODIGO: 00 Listo para recibir (RR)"));
            else
                Tramas.TxtArea.append(String.format("\nCODIGO: 01 Rechazado (REJ)"));
        }
        else // Puede ser  RNR o SRES
        {
            if((CO & 0x02 ) == 0) // Es RNR
                Tramas.TxtArea.append(String.format("\nCODIGO: 10 No Listo para recibir (RR)"));
            else
                Tramas.TxtArea.append(String.format("\nCODIGO: 11 Rechazo selectivo (REJ)"));
        }
    }
    public static void Unnumber(int C1, int C2)
    {

        Tramas.TxtArea.append(String.format("\nCODIGO: %d  (%04X)", C1, C1));
        Tramas.TxtArea.append(String.format("\nCODIGO: %d  (%04X)", C2, C2));
        // Interpretacion de CODIGO
        if(((C1 & 0xF0) == 0) && ((C1 & 0x0F) == 0)) // Puede ser 00
        {
            if((C2 & 0x01) == 0) //Puede ser SNRM, UI, DISC 00 0...
            {
                if((C2 & 0x02) == 0) // 00 00...
                {
                    if((C2 & 0x04) == 0) // 00 00 0
                        Tramas.TxtArea.append(String.format("\nCODIGO: 00 000   Informacion sin Numerar (UI)\n"));
                    else // 00 00 1
                        Tramas.TxtArea.append(String.format("\nCODIGO: 00 001    Activacion Modo Respuesta Normal (SNRM)\n"));
                }
                else // 00 010
                    Tramas.TxtArea.append(String.format("\nCODIGO: 00 010    Desconexion (DISC)\n"));
            }
            else // Puede ser 00 1
            {
                if((C2 & 0x02) == 0) // 00 10...
                    Tramas.TxtArea.append(String.format("\nCODIGO: 00 100    Sondeo sin numerar (UP)\n"));
                
                else // 00 11
                    Tramas.TxtArea.append(String.format("\nCODIGO: 00 110    Reconocmiento sin numerar (UA)\n"));
            }
        }
        else // Puede ser  11...
        {
            
            if((C2&0x01) == 0) // 11 0
            {
                if((C2&0x02) == 0) // 11 00
                {
                    if((C2&0x04) == 0) // 11 00 0
                        Tramas.TxtArea.append(String.format("\nCODIGO: 11 000    Activacion modo de respuesta Asincrona (SARM)\n"));
                    else // 11 00 1
                        Tramas.TxtArea.append(String.format("\nCODIGO: 11 001    Reinicio (RSET)\n"));
                }
                else // 11 01
                {
                    if((C2&0x04) == 0) // 11 01 0
                        Tramas.TxtArea.append(String.format("\nCODIGO: 11 010    Activacion modo de respuesta extendido (SARME)\n"));
                    else // 11 01 1
                        Tramas.TxtArea.append(String.format("\nCODIGO: 11 011    Activacion modo de respuesta extendido (SNRME)\n"));
                }
            }
            else  // 11 1
            {
                if((C2&0x02) == 0) // 11 10
                {
                    if ((C2&0x04) == 0) // 11 10 0
                        Tramas.TxtArea.append(String.format("\nCODIGO: 11 100    Activación Modo de Respuesta Balanceado (SABM)\n"));
                    else // 11 10 1
                        Tramas.TxtArea.append(String.format("\nCODIGO: 11 101    Intercambio de ID (XID)\n"));
                }
                else  // 11 11 0
                    Tramas.TxtArea.append(String.format("\nCODIGO: 11 110    Activación Modo de Respuesta Balanceado (SABME)\n"));
            }
        }
    }   
    public static void IEEE802(PcapPacket trama, int longitud){
        Num_ieee++;
        Tramas.TxtArea.append("---> T R A M A IEEE802.3\n");
       int dsap = trama.getUByte(14)& 0x00000001;
       if(dsap==1)
           Num_llcg++;
       else if(dsap==0)
           Num_llci++;
           
       String i_g = (dsap==1)?"Grupal":(dsap==0)?"Individual":"Otro";
        Tramas.TxtArea.append(String.format("\n|-->DSAP: %02X   %s",trama.getUByte(14), i_g));
        //System.out.println(packet.getUByte(15)& 0x00000001);
        
        int ssap = trama.getUByte(15)& 0x00000001;
        String c_r = (ssap==1)?"Respuesta":(ssap==0)?"Comando":"Otro";
        Tramas.TxtArea.append(String.format("\n|-->SSAP: %02X   %s",trama.getUByte(15), c_r));
        
        
        
        //////////////////////////////////////////////////////////////
        ///////////// Clasificacion de Tramas IEEE802.3 /////////////
        ////////////////////////////////////////////////////////////
        // Elige el byte 16 para seleccionar que tipo de trama es
        
        int c = trama.getUByte(16);
        int c1, c2;
        byte control1, control2;
        control1 = (byte)(c>>4);
        control2 = (byte)(c& 0x0f);
        
        if(longitud>3) // CAMPO DE CONTROL mide 2 Bytes
        {
             Tramas.TxtArea.append(String.format("\n|-->Control: %02X %02X",trama.getUByte(16), trama.getUByte(17)));
            // Como el campo de control mide 2 bytes, los separamos
            int b1, b2;
            
            if((c & 0x01) == 1) // Puede ser una trama S o U
            {
                if((c & 0x02) == 0) // Es una trama S
                {
                   
                    Tramas.TxtArea.append("\nEs una trama de SUPERVISION extendido\n");
                    b1 = trama.getUByte(16)>>2;
                    b2 = trama.getUByte(17)>>1;
                    SupervisionExtendido(b1,b2);
                }
                else // Es una trama U
                {
                    Tramas.TxtArea.append("\nEs una trama UNNUMBER\n");
                  
                    c1=control1>>1;
                    c2=control2>>2;
                    Unnumber(c2, c1);
                }
            }
            else // Es una trama I
            {
                Tramas.TxtArea.append("\nEs una trama de INFORMACION extendido\n");
                b1 = trama.getUByte(16)>>1;
                b2 = trama.getUByte(17)>>1;
                InformacionExtendido(b1,b2);
            }
        } // Fin Longitud
        
        else // Suponemos que el campo de control mide 1 Byte
        {
            Tramas.TxtArea.append(String.format("\n|-->Control: %02X",trama.getUByte(16)));
            if((c & 0x01) == 1) // Puede ser una trama S o U
            {
                if((c & 0x02) == 0) // Es una trama s
                {
                    Tramas.TxtArea.append("\nEs una trama de SUPERVISION\n");
                    c1=control1>>1;
                    c2=control2>>2;
                    Supervision(c2, c1);//Se envia el byte invertido
                }
                else // Es una trama u
                {
                    Tramas.TxtArea.append("\nEs una trama UNNUMBER\n");
                    c1=control1>>1;
                    c2=control2>>2;
                    
                    Unnumber(c2, c1);//Se envia el byte invertido
                }
            }
            else // Es una trama I
            {
                Tramas.TxtArea.append("\nEs una trama de INFORMACION\n");
                c1=control1>>1;
                c2=control2>>1;
                Informacion(c2, c1);//Se envia el byte invertido
            }
        }
        
    }
    /*
    public static void Ethernet(PcapPacket trama){
        Tramas.TxtArea.append("---> T R A M A  E T H E R N E T\n");
        
        //Calculamos el numero de bytes que corresponden a los datos de la trama
        int n=trama.getUByte(14)&0x0F, bytesr=0; //Se apartan las posiciones 0-3 del arreglo de transporte para los bytes extras


        //Creamos un arreglo para los bytes de datos
        byte[] encabezado = new byte[n*4];
                                
        //Ingresamos los bytes de datos al arreglo
        for (int i=14; i<14+(n*4); i++){
            encabezado[bytesr]=(byte)trama.getUByte(i);
            bytesr++;
        }

       //Enviamos los bytes de datos para realizar el checksum de la trama
        long chkr = Checksum.calculateChecksum(encabezado);
      	Tramas.TxtArea.append(String.format("Protocolo IP. Checksum de la Capa de Red: %02X\n",chkr));
                                
        //-------------CHECKSUM TRANSPORTE-----------
                                
        int ltrans=(trama.size()-26)+4;//Longitud que tendra el pseudoencabezado: IPOrigen + IPDestino + 00 + Protocolo + LongitudPDUTransporte + PDUTransporte
        int longitud=((trama.getUByte(16)==0)?trama.getUByte(17):(trama.getUByte(16)*256)+trama.getUByte(17))-(n*4); //Longitud de la trama menos longitud del arreglo del checksum de red IP (Ests es la LongitudPDUTransporte mencionada arriba)
        int bytest=0; //Se apartan las posiciones 0-3 del arreglo de transporte para: 00 + Protocolo + LongitudPDUTransporte
        byte[] pseudoenc = new byte[ltrans]; //Pseudoencabezado
                                
                                
        //Ingresamos los campos: IPOrigen + IPDestino + PDUTransporte
        for (int i=26; i<34; i++)
        { 
            pseudoenc[bytest]=(byte)trama.getUByte(i);
            bytest++;
        }
        //bytest=7;
        bytest=0;
                                
        //Posicion 8: 0x00
        pseudoenc[8]=0x00;
                                
        //Posicion 10 y 11: Longitud PDUTransporte
        int byte_long1=longitud&0xFF00, byte_long2=longitud&0x00FF; //Se divide la longitud del PDU (hexadecimal) en 2 bytes
                                
        pseudoenc[10]=(byte)byte_long1;
       pseudoenc[11]=(byte)byte_long2;
                                

      	if((byte)trama.getUByte(23)==0x11) //Revisa si es UDP: Byte 23: 11
      	{
                                    //Posicion 9: Protocolo
         pseudoenc[9]=0x11; // UDP: 11
        Tramas.TxtArea.append("Protocolo UPD. ");
        bytest=12;
                                
        //Ingresamos los campos: PDUTransporte
        for (int i=34; i<trama.size(); i++)
        { 
            pseudoenc[bytest]=(byte)trama.getUByte(i);
			bytest++;
        }
                              
                                    
        //Enviamos los bytes de datos para realizar el checksum de la capa de transporte
        long chkt = Checksum.calculateChecksum(pseudoenc);
        Tramas.TxtArea.append(String.format("Checksum de la Capa de Transporte: %02X\n",chkt));
        }
      	else if ((byte)trama.getUByte(23)==0x06) //Revisa si es TCP: Byte 23: 06
      	{
             //Posicion 9: Protocolo
            pseudoenc[9]=0x06; // TCP: 06
            Tramas.TxtArea.append("Protocolo TCP. ");
            bytest=12;
                                
            //Ingresamos los campos: PDUTransporte
            for (int i=34; i<trama.size(); i++){ 
                pseudoenc[bytest]=(byte)trama.getUByte(i);
				bytest++;
            }
            //Enviamos los bytes de datos para realizar el checksum de la capa de transporte
            long chkt = Checksum.calculateChecksum(pseudoenc);
            Tramas.TxtArea.append(String.format("Checksum de la Capa de Transporte: %02X\n",chkt));
      	}

    }*/
    
    //Tramas.TxtArea.append(String.format(
    //Tramas.TxtArea.append(
    
    public static void TipodeProtocolo(PcapPacket trama){
        
        
        ///Ip4
        //Ip6
        //ARP
        //TCP
        //Icmp
        //Udp
        
        
        
        Ethernet eth = new Ethernet();
           if(trama.hasHeader(eth)){//Ethernet
               Num_ethernet++;
               Tramas.TxtArea.append("-----Trama Ethernet-----\n");
                //JBuffer buffer= eth;
               int tipo=eth.type();
               //System.out.println("Tipo Decimal:"+tipo);
               Tramas.TxtArea.append(String.format("Tipo: %X\n",tipo));
               switch(tipo){
                   case (int)1://LLC Individual
                       Num_llci++;
                       Tramas.TxtArea.append("-----Trama LLC individual-----\n");
                       IEEE802dot2 llc =new IEEE802dot2();
                       if(trama.hasHeader(llc)){
                           int ssap=llc.ssap();
                           int dsap=llc.dsap();
                           int control=llc.control();
                           Tramas.TxtArea.append(String.format("SSAP:%s\n",ssap));
                           Tramas.TxtArea.append(String.format("DSAP:%s\n",dsap));
                           Tramas.TxtArea.append(String.format("Control:%x\n",control));
                       }
                       break;
                   case (int)2://LLC Grupo
                       Num_llcg++;
                        Tramas.TxtArea.append("-----Trama LLC de grupo-----\n");
                        IEEE802dot2  llcg=new IEEE802dot2();
                        if(trama.hasHeader(llcg)){
                            int ssap=llcg.ssap();
                            int dsap=llcg.dsap();
                            int control=llcg.control();
                            Tramas.TxtArea.append(String.format("SSAP:%s\n",ssap));
                            Tramas.TxtArea.append(String.format("DSAP:%s\n",dsap));
                            Tramas.TxtArea.append(String.format("Control:%x\n",control));
                        }
                        break;
                   case (int) 2054://ARP
                       
                        Tramas.TxtArea.append("-----Mensaje ARP-----\n");
                        Arp arp=new Arp();
                        if(trama.hasHeader(arp)){
                            int operacion=arp.operation();
                            int [] sp=new int[4];
                            int [] tp=new int[4];
                            sp[0] = ((arp.spa()[0])<0)?(arp.spa()[0])+256:arp.spa()[0];
                            sp[1] = ((arp.spa()[1])<0)?(arp.spa()[1])+256:arp.spa()[1];
                            sp[2] = ((arp.spa()[2])<0)?(arp.spa()[2])+256:arp.spa()[2];
                            sp[3] = ((arp.spa()[3])<0)?(arp.spa()[3])+256:arp.spa()[3];
                            tp[0] = ((arp.tpa()[0])<0)?(arp.tpa()[0])+256:arp.tpa()[0];
                            tp[1] = ((arp.tpa()[1])<0)?(arp.tpa()[1])+256:arp.tpa()[1];
                            tp[2] = ((arp.tpa()[2])<0)?(arp.tpa()[2])+256:arp.tpa()[2];
                            tp[3] = ((arp.tpa()[3])<0)?(arp.tpa()[3])+256:arp.tpa()[3];
                            if(operacion==1){
                                Num_arp++;
                                Tramas.TxtArea.append("Hardware Type: "+arp.hardwareType()+"\n");
                                Tramas.TxtArea.append("Hlen: "+arp.hlen()+"\n");
                                Tramas.TxtArea.append("Plen: "+arp.plen()+"\n");
                                Tramas.TxtArea.append("Protocol Type: "+arp.protocolType()+"\n");
                                
                                if(sp.equals(tp)){
                                   Tramas.TxtArea.append("ARP gratuito direccion " + sp[0]+"."+sp[1]+"."+sp[2]+"."+sp[3]+"\n"); 
                                }
                                else{
                                   Tramas.TxtArea.append("Consulta ARP Quien tiene la direccion " + tp[0]+"."+tp[1]+"."+tp[2]+"."+tp[3] + "??\n"); 
                                }
                            }
                            else if(operacion==2){
                                Num_arp++;
                                Tramas.TxtArea.append("Respuesta ARP " + sp[0]+"."+sp[1]+"."+sp[2]+"."+sp[3] + " es" + asString(arp.sha())+"\n");
                            }
                            else if(operacion==3){//RARP
                                Num_rarp++;
                                Tramas.TxtArea.append("Consulta RARP\n");
                            }
                            else if(operacion==4){
                                Num_rarp++;
                                Tramas.TxtArea.append("Respuesta RARP\n");
                            }
                        }
                        break;
                   case (int)2048://IPv4
                       Num_ip4++;
                       Tramas.TxtArea.append("-----IPv4-----\n");
                       Ip4 ip4= new Ip4();
                       //System.out.println("Version"+ip4.version());
                       if (trama.hasHeader(ip4)) {
                            Tramas.TxtArea.append("TTL: "+ip4.ttl()+"\n");
                            Tramas.TxtArea.append("Version : "+ip4.version()+"\n");
                            Tramas.TxtArea.append("TOS: "+ip4.tos()+"\n");
                            Tramas.TxtArea.append("tos_ECN: "+ip4.tos_ECN()+"\n");
                            Tramas.TxtArea.append("Chescksum: "+ip4.checksum()+"\n");
                            Tramas.TxtArea.append("Flags_MF: "+ip4.flags_MF()+"    Flags_DF: "+ip4.flags_DF()+"\n");
                            Tramas.TxtArea.append("Hlen: "+ip4.hlen()+"\n");
                            Tramas.TxtArea.append("ID: "+ip4.id()+"\n");
                            Tramas.TxtArea.append("Longitud: "+ip4.length()+"      Offset: "+ip4.offset()+"\n");
                            
                            
                            int s1 = ((ip4.source()[0])<0)?(ip4.source()[0])+256:ip4.source()[0];
                            int s2 = ((ip4.source()[1])<0)?(ip4.source()[1])+256:ip4.source()[1];
                            int s3 = ((ip4.source()[2])<0)?(ip4.source()[2])+256:ip4.source()[2];
                            int s4 = ((ip4.source()[3])<0)?(ip4.source()[3])+256:ip4.source()[3];
                            int d1 = ((ip4.destination()[0])<0)?(ip4.destination()[0])+256:ip4.destination()[0];
                            int d2 = ((ip4.destination()[1])<0)?(ip4.destination()[1])+256:ip4.destination()[1];
                            int d3 = ((ip4.destination()[2])<0)?(ip4.destination()[2])+256:ip4.destination()[2];
                            int d4 = ((ip4.destination()[3])<0)?(ip4.destination()[3])+256:ip4.destination()[3];
                            Tramas.TxtArea.append("IP destino: "+d1+"."+d2+"."+d3+"."+d4+"\n");
                            Tramas.TxtArea.append("IP origen: "+s1+"."+s2+"."+s3+"."+s4+"\n");
                            int protocolo = ip4.type();
                            Tramas.TxtArea.append("Protocolo: "+protocolo+"\nDescripcion: "+ip4.typeDescription()+"\n");
                            
                            
                            switch(protocolo){
                                    case 6://TCP
                                        Num_tcp++;
                                        Tcp tcp = new Tcp();
                                        if (trama.hasHeader(tcp)) {
                                            Tramas.TxtArea.append("-----TCP-----\n");
                                            Tramas.TxtArea.append("Puerto origen: "+tcp.source()+"\nPuerto destino: "+tcp.destination()+"\n");
                                            byte[] data = trama.getByteArray(0, trama.size());
                                            Tramas.TxtArea.append("Datos:\n");
                                            BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
                                            String linea="";
                                            try{
                                                while((linea= br.readLine())!=null){
                                                    Tramas.TxtArea.append(linea+"\n");
                                                }
                                                br.close();
                                                Tramas.TxtArea.append("\n\n\n");
                                                }
                                            catch(IOException e){
                                                e.printStackTrace();
                                            }
                                        }
                                        break;
                                    case 17://UDP
                                         Udp udp=new Udp();
                                         Num_udp++;
                                         if(trama.hasHeader(udp)){
                                             Tramas.TxtArea.append("-----UDP-----\n");
                                             Tramas.TxtArea.append("Puerto Origen: "+udp.source()+"\nPuerto destino: "+udp.destination()+"\n");
                                             byte [] data=trama.getByteArray(0,trama.size());
                                             Tramas.TxtArea.append("Datos:\n");
                                             BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
                                            String linea="";
                                            try{
                                                while((linea= br.readLine())!=null){
                                                    Tramas.TxtArea.append(linea+"\n");
                                                }
                                                br.close();
                                                Tramas.TxtArea.append("\n\n\n");
                                             }
                                            catch(IOException e){
                                                e.printStackTrace();
                                            }
                                         }
                                        break;
                                    case 1://ICMP
                                        Icmp icmp= new Icmp();
                                        Num_icmp++;
                                        Icmp.EchoRequest echo = new Icmp.EchoRequest();
                                        if(trama.hasHeader(icmp)){
                                            Tramas.TxtArea.append("-----ICMP------\n");
                                            int code=icmp.code();
                                            int Tipo=icmp.type();
                                            int id=echo.id();
                                            int sequence=echo.sequence();
                                            Tramas.TxtArea.append("Tipo: "+Tipo+"[ "+icmp.typeDescription()+" ]\n");
                                            Tramas.TxtArea.append("Codigo: "+code+"\n");
                                            Tramas.TxtArea.append("Id: "+id+"\n");
                                            Tramas.TxtArea.append("Secuencia: "+sequence+"\n");
                                            Tramas.TxtArea.append("Checksum: "+icmp.checksum()+"\n");
                                            byte [] data=trama.getByteArray(0,trama.size());
                                            Tramas.TxtArea.append("Datos:\n");
                                            BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
                                            String linea="";
                                            try{
                                                while((linea= br.readLine())!=null){
                                                    Tramas.TxtArea.append(linea+"\n");
                                                }
                                                br.close();
                                                Tramas.TxtArea.append("\n\n\n");
                                             }
                                            catch(IOException e){
                                                e.printStackTrace();
                                            }
                                  
                                        }    
                                       
                            }
                       }
                       break;
                    case (int)34525://IPv6
                        Num_ip6++;
                        Tramas.TxtArea.append("-----IPv6------\n");
                        
                        
                        //System.out.printf("Tipo%X\n",tipo);
                        Ip6 ip6=new Ip6();
                        
                        if(trama.hasHeader(ip6)){

                            Tramas.TxtArea.append("Version : "+ip6.version()+"\n");
                            Tramas.TxtArea.append("Longitud: "+ip6.length()+"\n");
                            int protocolo;
                            protocolo = ip6.next();
                            byte[]s=ip6.source();
                            byte[]d=ip6.destination();
                            /*
                            int s1=((ip6.source()[0])*256)+(ip6.source()[1]);
                            int s2=((ip6.source()[2])*256)+(ip6.source()[3]);
                            int s3=((ip6.source()[4])*256)+(ip6.source()[5]);
                            int s4=((ip6.source()[6])*256)+(ip6.source()[7]);
                            int s5=((ip6.source()[8])*256)+(ip6.source()[9]);
                            int s6=((ip6.source()[10])*256)+(ip6.source()[11]);
                            int s7=((ip6.source()[12])*256)+(ip6.source()[13]);
                            int s8=((ip6.source()[14])*256)+(ip6.source()[15]);
                            */
                            Tramas.TxtArea.append("Ip Origen");
                            for(int i=0;i<s.length;i++){
                                if((i%2)==0){
                                    Tramas.TxtArea.append(":");
                                }
                                Tramas.TxtArea.append(String.format("%02X",s[i]));
                            }
                            Tramas.TxtArea.append("\n");
                             Tramas.TxtArea.append("Ip Destino");
                            for(int i=0;i<s.length;i++){
                                if((i%2)==0){
                                    Tramas.TxtArea.append(":");
                                }
                                 Tramas.TxtArea.append(String.format("%02X",d[i]));
                            }
                            Tramas.TxtArea.append("\n");
                            Tramas.TxtArea.append("Protocolo: "+protocolo+"\n");
                            switch(protocolo){
                                case 6://TCP
                                    Num_tcp++;
                                    Tcp tcp = new Tcp();
                                        if (trama.hasHeader(tcp)) {
                                            Tramas.TxtArea.append("-----TCP-----\n");
                                            Tramas.TxtArea.append("Puerto origen: "+tcp.source()+"\nPuerto destino: "+tcp.destination()+"\n");
                                            byte[] data = trama.getByteArray(0, trama.size());
                                            Tramas.TxtArea.append("Datos:\n");
                                            BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
                                            String linea="";
                                            try{
                                                while((linea= br.readLine())!=null){
                                                    Tramas.TxtArea.append(linea+"\n");
                                                }
                                                br.close();
                                                Tramas.TxtArea.append("\n\n\n");
                                                }
                                            catch(IOException e){
                                                e.printStackTrace();
                                            }
                                        }
                                    break;
                                case 17://UDP
                                    Num_udp++;
                                    Udp udp=new Udp();
                                         if(trama.hasHeader(udp)){
                                             Tramas.TxtArea.append("-----UDP-----\n");
                                             Tramas.TxtArea.append("Puerto Origen: "+udp.source()+"\nPuerto destino: "+udp.destination()+"\n");
                                             byte [] data=trama.getByteArray(0,trama.size());
                                             Tramas.TxtArea.append("Datos:\n");
                                             BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
                                            String linea="";
                                            try{
                                                while((linea= br.readLine())!=null){
                                                    Tramas.TxtArea.append(linea+"\n");
                                                }
                                                br.close();
                                                Tramas.TxtArea.append("\n\n\n");
                                             }
                                            catch(IOException e){
                                                e.printStackTrace();
                                            }
                                         }
                                    break;
                                case 1://ICMP
                                    Tramas.TxtArea.append("-----ICMP------\n");
                                    Num_icmp++;
                                    Icmp icmp= new Icmp();
                                    //Icmp.EchoRequest echo = new Icmp.EchoRequest();
                                    if(trama.hasHeader(icmp)){
                                        int code=icmp.code();
                                        int Tipo=icmp.type();
                                        //int id=echo.id();
                                        //int sequence=echo.sequence();
                                        Tramas.TxtArea.append("Tipo:"+Tipo+"[ "+icmp.typeDescription()+" ]\n");
                                        Tramas.TxtArea.append("Codigo: "+code+"\n");
                                        //System.out.println("Id:"+id);
                                        //System.out.println("Secuencia:"+sequence);
                                    }
                                    break;
                            }
                        }
                    break;
                    
               }
               
           }
        
    }
    
    public static void enviaGrafico(){
        Estadisticas.graficar(Num_ethernet, Num_ieee, Num_llci, Num_llcg, Num_arp, Num_rarp, Num_ip4, Num_tcp,Num_udp,Num_icmp, Num_ip6);
        
    }

}
