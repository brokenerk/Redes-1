package protocolo;
import java.io.*;
import javax.swing.JFileChooser;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class VentanaProtocolo extends javax.swing.JFrame 
{
    public VentanaProtocolo() 
    {
        initComponents();
    }
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jCboDevices = new javax.swing.JComboBox<>();
        Btn_Devices = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        MACOrigen = new javax.swing.JTextField();
        MACDestino = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        RutaArchivoSelec = new javax.swing.JTextField();
        ElegirArc = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        EnviarArchivo = new javax.swing.JButton();
        ChkEmisor = new javax.swing.JCheckBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Protocolo");
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
            public void windowOpened(java.awt.event.WindowEvent evt) {
                formWindowOpened(evt);
            }
        });

        jCboDevices.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCboDevicesActionPerformed(evt);
            }
        });

        Btn_Devices.setText("Start");
        Btn_Devices.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                Btn_DevicesMouseClicked(evt);
            }
        });
        Btn_Devices.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Btn_DevicesActionPerformed(evt);
            }
        });

        jLabel1.setText("MAC ORIGEN");

        jLabel2.setText("MAC DESTINO");

        MACOrigen.setEditable(false);

        jLabel3.setText("ELEGIR ARCHIVO");

        RutaArchivoSelec.setEditable(false);

        ElegirArc.setText("...");
        ElegirArc.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                ElegirArcMouseClicked(evt);
            }
        });
        ElegirArc.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ElegirArcActionPerformed(evt);
            }
        });

        jLabel4.setText("Selecciona una interfaz de red");

        EnviarArchivo.setText("Enviar Archivo");
        EnviarArchivo.setEnabled(false);
        EnviarArchivo.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                EnviarArchivoMouseClicked(evt);
            }
        });
        EnviarArchivo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                EnviarArchivoActionPerformed(evt);
            }
        });

        ChkEmisor.setText("Emisor");
        ChkEmisor.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ChkEmisorActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel4)
                        .addGap(0, 466, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(203, 203, 203)
                        .addComponent(EnviarArchivo, javax.swing.GroupLayout.PREFERRED_SIZE, 135, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(172, 172, 172))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jCboDevices, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(Btn_Devices, javax.swing.GroupLayout.PREFERRED_SIZE, 59, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(26, 26, 26)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel3)
                                        .addGap(18, 18, 18)
                                        .addComponent(RutaArchivoSelec, javax.swing.GroupLayout.DEFAULT_SIZE, 405, Short.MAX_VALUE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(ElegirArc, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(jLabel2)
                                            .addComponent(jLabel1))
                                        .addGap(33, 33, 33)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(MACDestino, javax.swing.GroupLayout.PREFERRED_SIZE, 129, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 335, Short.MAX_VALUE))
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(MACOrigen, javax.swing.GroupLayout.PREFERRED_SIZE, 129, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(ChkEmisor)))))))
                        .addGap(19, 19, 19))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel4)
                .addGap(9, 9, 9)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCboDevices, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(Btn_Devices))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(MACOrigen, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ChkEmisor))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(MACDestino, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(RutaArchivoSelec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ElegirArc)
                    .addComponent(jLabel3))
                .addGap(18, 18, 18)
                .addComponent(EnviarArchivo)
                .addContainerGap(20, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    
    public static StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    public static PcapIf dispositivo;
    public static Pcap pcapA;
    public static byte[] MACo=new byte[6], MACd;
    public static Thread hiloPrincipal;
    public static String path, nombre_arc;
    public static List<PcapIf> alldevs=new ArrayList<>();
    public static List<Byte> a=new ArrayList<>();
    public static int partes, ntramas=1, contadorArchivo=0; 
    public static RandomAccessFile archivoOrigen, archivoDestino;
    
    public static byte[] stringToMAC(String s) {
    s = s.replace(":", "");
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
        return data;
    }
  
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////// MÉTODOS PARA ENVIAR ////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Elegir el archivo a enviar
    private void ElegirArcActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ElegirArcActionPerformed
        // TODO add your handling code here:
         // Código que el profe dio en clase XD
        try
        { // LECTURA DEL ARCHIVO
          /* Caja de dialogo: Te muestra los archivos de la maquina. 
            Tiene el boton aceptar y cancelar*/
          JFileChooser jf = new JFileChooser();
          //jf.setMultiSelectionEnabled(true);
          // Valor de la constante 
          int r = jf.showOpenDialog(null);
          if(r == JFileChooser.APPROVE_OPTION)
          {
            // Devuelve el archivo
            File f = jf.getSelectedFile();
            try{
                archivoOrigen = new RandomAccessFile(f, "r");
            }catch(IOException e){
                JOptionPane.showMessageDialog(null, "No se ha podido leer el archivo.", "Error",JOptionPane.ERROR_MESSAGE);
            
            }
            // Para mostrar las propiedades del archivo
            nombre_arc = f.getName();
            path = f.getAbsolutePath();
            // Mostramos el nombre del archivo
           
            long tam = f.length();
            // Obtenemos el número de tramas
            int cociente =(int)tam/1460;
            int residuo = (int)tam-(cociente*1460);
            partes = cociente+1;
            System.out.println("NUMERO DE TRAMAS:  "+partes);
            // Los datos primitivos almacen valores.
            // Lee datos desde cualquier tipo de datos primitivos
            DataInputStream dis = new DataInputStream(new FileInputStream(path));
            RutaArchivoSelec.setText(path);
            EnviarArchivo.setEnabled(true);
          }
        }
        catch(IOException io)
        {   //
            JOptionPane.showMessageDialog(null, "No se ha podido leer el archivo.", "Error",JOptionPane.ERROR_MESSAGE);
            
        }
    }//GEN-LAST:event_ElegirArcActionPerformed


    // Al dar click en el boton enviar...
    private void EnviarArchivoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_EnviarArchivoActionPerformed
        // TODO add your handling code here:
        try
        {
            
            MACd=stringToMAC(MACDestino.getText());
            
            if(getLong(nombre_arc.getBytes())>50)
                JOptionPane.showMessageDialog(null, "El nombre del archivo es muy largo");
            else
            {
                byte[] buf = new byte[(int)archivoOrigen.length()];
                // Lee el archivo origen
                archivoOrigen.readFully(buf);
                
                if((int)archivoOrigen.length()>1460)
                {
                    int b,indice=0;
                    int tamMaxArchivo;
                    for (int a=0; a<(partes-1); a++)
                    {
                        b=a;
                        tamMaxArchivo = 1460;
                        byte[] trama1 = new byte[getLong(nombre_arc.getBytes())+tamMaxArchivo+24];        
                        byte[] arc = new byte[1460];
                        indice = b*1460;
                        for(int i=0; i<tamMaxArchivo; i++)
                        {
                            arc[i] = buf[indice];
                            indice++;
                        }
                        llenarTrama(trama1, MACd, MACo, nombre_arc.getBytes(), arc, getLong(nombre_arc.getBytes()),tamMaxArchivo, partes);
                        System.out.printf("\nSE LLENO LA TRAMA    " + (int)(a+1) + "\n");
                        enviarTrama(trama1);
                        System.out.printf("SE ENVIO LA TRAMA    " + (int)(a+1) + "\n\n");
                        Thread.sleep(500);
                    }
                    
                    
                    tamMaxArchivo=(int)archivoOrigen.length()-((partes-1)*1460);
                    byte[] tramaN = new byte[getLong(nombre_arc.getBytes())+tamMaxArchivo+24];
                    byte[] arcN = new byte[1460];
                    b = (partes-1)*1460;
                        for(int i=0; i<tamMaxArchivo; i++)
                        {
                            arcN[i] = buf[indice];
                            indice++;
                        }
                    llenarTrama(tramaN, MACd, MACo, nombre_arc.getBytes(), arcN, getLong(nombre_arc.getBytes()),tamMaxArchivo, partes);
                    System.out.printf("\nSE LLENO LA TRAMA "+ partes + "\n");
                    enviarTrama(tramaN);        
                    System.out.printf("SE ENVIO LA TRAMA "+ partes + "\n");
                    JOptionPane.showMessageDialog(null, "Se ha enviado el archivo "+nombre_arc+" correctamente.");
              
                    //Thread.sleep(1500);
                }
                else
                {
                    byte[] trama1 = new byte[getLong(nombre_arc.getBytes())+(int)archivoOrigen.length()+24]; 
                    llenarTrama(trama1, MACd, MACo, nombre_arc.getBytes(), buf , getLong(nombre_arc.getBytes()), (int)archivoOrigen.length(), partes);
                    enviarTrama(trama1);
                    System.out.printf("\nSE ENVIO LA TRAMA\n");
                    JOptionPane.showMessageDialog(null, "Se ha enviado el archivo "+nombre_arc+" correctamente.");
                
                    //Thread.sleep(1500);
                }             
            }
        }
        catch(Exception e){
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "No se ha podido enviar el archivo "+nombre_arc, "Error",JOptionPane.ERROR_MESSAGE);
        
        }
    }//GEN-LAST:event_EnviarArchivoActionPerformed

    // El siguiente método llena la trama conforme el protocolo establecido 
    public static void llenarTrama(byte[] trama, byte[] MACdestino, byte[] MACorigen, byte[] narch, byte[] arch,  int tamname, int tamarch, int numTramasTotal) throws IOException{
        //Llena la trama ARCHIVO a enviar

        for(int k=0; k<tamarch; k++)
            System.out.printf("%02X ",arch[k]);  

        // COLOCA EN LAS POSICION 0-5 MAC DESTINO Y 6-11 MAC
        System.out.println("");
        for(int k=0;k<6;k++){
            trama[k] = MACdestino[k];
            //System.out.printf("%02X ", trama[k+6]);
            trama[k+6]=MACorigen[k];
            System.out.printf("%02X ", trama[k]);
        }
        
        int byte_long1, byte_long2, long1_n, long2_n;
        int totalTram1, totalTram2;
        long chk1, chk2;

        trama[12]= (byte) 0x16; //tipo sin asignar BYTE 12
        trama[13]= (byte) 0x01; //tipo sin asignar rfc 1340   BYTE 13
        
        
        
        totalTram1 = (numTramasTotal>>8)&0xFF;
        totalTram2 = (numTramasTotal)&0x00FF;
        
        trama[15] = (byte) totalTram1;  // Numero de total de tramas dividida en 2 bytes
        trama[16] = (byte) totalTram2;

        trama[17]= (byte) 0xC1; //Protocolo 0xC1

        byte_long1=(tamarch>>8)&0xFF;
        byte_long2=(tamarch)&0x00FF;
        
        trama[18]= (byte) byte_long1;//Longitud del mensaje divida en 2 bytes
        trama[19]= (byte) byte_long2;

        long1_n=(tamname>>8)&0xFF;
        long2_n=(tamname)&0x00FF;
            
        trama[20]= (byte) long1_n;//Longitud del nombre divida en 2 bytes
        trama[21]= (byte) long2_n;

        chk1=(Checksum.calculateChecksum(arch)>>8)&0xFF;
        chk2=(Checksum.calculateChecksum(arch))&0x00FF;
        
        trama[trama.length-2]= (byte)chk1;//Checksum del mensaje divido en 2 bytes
        trama[trama.length-1]= (byte)chk2;
        
        for(int c=0;c<tamname;c++)
            trama[22+c]=narch[c];
        
       for(int c=0;c<tamarch;c++)
            trama[22+tamname+c]=arch[c];
        
        if(tamarch<=1460){
            trama[14]=(byte)0xA0;
            
        } //Si el mensaje es pequeño, sera de subtipo P=A0
        else
            trama[14]=(byte)0xA1;
        //Si el mensaje es grande, sera de subtipo G=A1
        
    }

    //Obtiene la longitud del archivo o nombre a enviar
    public static int getLong(byte[] informacion){
        return informacion.length;
    }
    
    private static void  enviarTrama(byte [] trama){
        Thread hilo = new Thread(new Runnable(){
            @Override
            public void run(){
                pcapA.sendPacket(trama);
            }
        });
        hilo.start();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////// MÉTODOS PARA RECIBIR ///////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    

    //Obtener nombre del archivo del paquete recibido en bytes
    public static byte[] getNombrePacket(byte[] trama){
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
    //Obtener el archivo del paquete recibido en bytes
    public static byte[] getArchivoPacket(byte[] trama){
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

    public static void LimpiarRecibidos(int lname, int larchivo, int j, byte[] escribir, String namexd, byte[] n) throws IOException, InterruptedException{
        escribir=null;
        n=null;
        lname=0;
        larchivo=0;
        j=0;
        ntramas=0;
        contadorArchivo=0;
        partes=0;
        path="";
        namexd="";
        nombre_arc="";
        archivoOrigen.close();
        archivoDestino.close();
        a.clear();    
    }

    public static void analizarPaquete(PcapPacket packet){
        // No mover tipo y archivo destino
        /******Desencapsulado*******/
        
        //Verifica la MAC destino, para evitar capturar todos los paquetes, solo los dirigidos a esa MAC
        boolean mac=true;
        if(ChkEmisor.isSelected()){
            for(int k=0;k<6;k++){
                if(MACo[k]!=(byte)packet.getUByte(k)){
                    if((byte)packet.getUByte(k)==(byte)0xff)
                        mac=true; 
                    else
                        mac=false;
                }
            }
        }

        if(packet.getUByte(12) == 22 && packet.getUByte(13) == 1 && mac){ //0x1601
            
            System.out.printf("\n\nPaquete recibido el %s bytes capturados=%-4d tam original=%-4d\n",
                    new Date(packet.getCaptureHeader().timestampInMillis()),
                    packet.getCaptureHeader().caplen(),  // Length actually captured
                    packet.getCaptureHeader().wirelen() // Original length
                    );

            //IMPRIME EL TOTAL DE TRAMAS QUE CONFORMAN EL ARCHIVO
            int TramasTotal=(packet.getUByte(15)==0)?packet.getUByte(16):(packet.getUByte(15)*256)+packet.getUByte(16);
            System.out.println("NUMERO TOTAL DE TRAMAS: "+TramasTotal+"\n");

            // PONE NOMBRE DE LA TRAMA EN EL ARCHIVO
            
            int lname=(packet.getUByte(20)==0)?packet.getUByte(21):(packet.getUByte(20)*256)+packet.getUByte(21);
            byte []n=new byte[lname];
            int j=0;
            
            for(int k=(22);k<(lname+22);k++)
                {
                   n[j]=(byte)packet.getUByte(k);
                   j++;
                } 
            String namexd=getNombreArchivo(n);
            
            // PEGA EL ARCHIVO
           int larchivo=(packet.getUByte(18)==0)?packet.getUByte(19):(packet.getUByte(18)*256)+packet.getUByte(19);
           j=0;
            
            System.out.println("Trama: "+ntramas);
            if(ntramas<(TramasTotal+1)){
                
                //REVISAMOS ERRORES POR MEDIO DE CHECKSUM
                byte[] ck=new byte[larchivo];
                int cks=(packet.getUByte(packet.size()-2)==0)?packet.getUByte(packet.size()-1):(packet.getUByte(packet.size()-2)*256)+packet.getUByte(packet.size()-1);
                for(int k=(lname+22);k<(lname+22+larchivo);k++)
                {
                   ck[j]=(byte)packet.getUByte(k);
                   a.add(contadorArchivo,(byte)packet.getUByte(k));
                   System.out.printf("%02X ", a.get(j)); 
                   contadorArchivo++;
                   j++;
                } 
                System.out.println("\n"+a.size()+"\n\n");
                
                if(cks!=Checksum.calculateChecksum(ck))
                    System.out.println("\nChecksum.... AVISO: Bytes de los datos de la trama erroneos.");
                else
                    System.out.println("\nChecksum.... OK"); 
                 /*for(int l=0;l<packet.size();l++){
                                System.out.printf("%02X ",packet.getUByte(l));
                                if(l%16==15)
                                    System.out.println("");
                                }
                                System.out.println("");*/
                                
                if(ntramas==TramasTotal){
                    try{
                        //System.out.println("\nEscribiendo en disco....\n");
                        archivoDestino = new RandomAccessFile("C:\\received\\" + namexd, "rw");
                        try{
                            byte[]escribir=new byte[contadorArchivo];
                            
                            for(int k=0;k<contadorArchivo;k++)
                            {
                                escribir[k]=a.get(k);
                                
                            }
                            
                            /*for(int l=0;l<contadorArchivo;l++){
                            System.out.printf("%02X ",escribir[l]);
                            if(l%16==15)
                            System.out.println("");
                            }
                            System.out.println("");*/
                            //archivoDestino.write(escribir);//Escribe el archivo recibido en disco
                            //System.out.println("\nArchivo recibido escrito en disco");
                            //JOptionPane.showMessageDialog(null, "Se ha recibido el archivo "+namexd);
                            //LimpiarRecibidos(lname, larchivo, j, escribir, namexd, n);
                        }
                        catch(Exception e)
                        {
                            JOptionPane.showMessageDialog(null, "No se ha podido recibir el archivo "+namexd, "Error",JOptionPane.ERROR_MESSAGE);
                            
                            e.printStackTrace();
                        }
                    }
                catch(FileNotFoundException ex)
                {
                        Logger.getLogger(VentanaProtocolo.class.getName()).log(Level.SEVERE, null, ex);
                }
                }
            }

            ntramas++;
                
        } // Fin if
    } // Fín método analizarPaquete


    // VA CACHANDO TRAMAS XD
    public static void recibirPaquetes(){
        try{
                
                PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>(){
                    @Override
                    public void nextPacket(PcapPacket paquete, String txt){
                            analizarPaquete(paquete);
                            
                    }
                };
                hiloPrincipal = new Thread(new Runnable(){
                    @Override
                    public void run(){
                        pcapA.loop(Pcap.LOOP_INFINITE, jPacketHandler, "");
                    }
                });
                hiloPrincipal.start();
            }catch(Exception e){
                Logger.getLogger(VentanaProtocolo.class.getName()).log(Level.SEVERE, null, e);
            }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////// MÉTODOS PARA AMBOS ///////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////

    //Obtiene el nombre del archivo en texto
    private static String getNombreArchivo(byte[] nombre){
        String n = "";
        for(int i = 0; i <nombre.length; i++)
            n += (char)nombre[i];
        return n;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////// MÉTODOS DEL SISTEMA ///////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////
 
    public static void cargaDevices(){ 
       Pcap.findAllDevs(alldevs, errbuf);
        try{
            for(PcapIf inter : alldevs){
                String descripcion = inter.getDescription();
                if(descripcion == null) descripcion = "";
                String mac = asString(inter.getHardwareAddress());
                String ip4 = "";
                Iterator<PcapAddr> it = inter.getAddresses().iterator();
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
                        ip4="IP4: ["+ipv4[0]+"."+ipv4[1]+"."+ipv4[2]+"."+ipv4[3]+"]";
                    }
                }
                jCboDevices.addItem(descripcion + "  MAC: [" + mac + "] " + ip4);  
            }
                              

        }catch(IOException io){
            JOptionPane.showMessageDialog(null, "No se pudieron cargar las interfaces de red.", "Error",JOptionPane.ERROR_MESSAGE);
            io.printStackTrace();
        }//catch
    }


    
    // Botón que confirma cuando se selecciona una interfaz
    private void Btn_DevicesMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_Btn_DevicesMouseClicked
        // TODO add your handling code here:
    }//GEN-LAST:event_Btn_DevicesMouseClicked

    // Seleccionar el archivo que se desea enviar
    private void ElegirArcMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ElegirArcMouseClicked
       
    }//GEN-LAST:event_ElegirArcMouseClicked
    // Se cierra la ventana
    private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        if(pcapA != null){
            pcapA.close();
        }
    }//GEN-LAST:event_formWindowClosing

    /* Cuando se abre la ventana, lo primero que hace
       es buscar las interfaces existentes en la computadora 
    */
    private void formWindowOpened(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowOpened
        // TODO add your handling code here:
        cargaDevices();
        MACDestino.setEnabled(false);
        RutaArchivoSelec.setEnabled(false);
        ElegirArc.setEnabled(false);
    }//GEN-LAST:event_formWindowOpened
    
    // Envía el archivo seleccionado
    private void EnviarArchivoMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_EnviarArchivoMouseClicked
        // TODO add your handling code here:
    }//GEN-LAST:event_EnviarArchivoMouseClicked

    // abrir la interfaz
    private void Btn_DevicesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Btn_DevicesActionPerformed
        dispositivo=alldevs.get(jCboDevices.getSelectedIndex());
        //MACOrigen.setText(asString(dispositivo.getHardwareAddress()));         
        /***************************************************************************
	       * First get a list of devices on this system
        **************************************************************************/
        if(pcapA!=null ){//IMPORTANTE. Si se omite lanza error
            pcapA.close();
            pcapA=null;
            Btn_Devices.setText("Start");
            MACDestino.setText("");
            MACDestino.setEnabled(false);
            RutaArchivoSelec.setEnabled(false);
            ElegirArc.setEnabled(false);
        }
        else{  
            
            MACDestino.setEnabled(true);
            RutaArchivoSelec.setEnabled(true);
            ElegirArc.setEnabled(true);
            Btn_Devices.setText("Stop");
                try{
                   /***************************************** 
                    * Second we open a network interface 
                    *****************************************/  
                    MACo=dispositivo.getHardwareAddress();
                    MACOrigen.setText(asString(MACo));
                    pcapA = Pcap.openLive(dispositivo.getName(), 64 * 1460, 0, 1000, errbuf);
                    PcapBpfProgram filtro = new PcapBpfProgram();
                    pcapA.compile(filtro, "ether proto 0x1601", 0, 0);
                    pcapA.setFilter(filtro);
                    recibirPaquetes();
                }catch(Exception e){
                    JOptionPane.showMessageDialog(null, "Error interno al crear Pcap.", "Error",JOptionPane.ERROR_MESSAGE);
                    e.printStackTrace();
                }//catch
        }
    }//GEN-LAST:event_Btn_DevicesActionPerformed

    private void jCboDevicesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCboDevicesActionPerformed

    }//GEN-LAST:event_jCboDevicesActionPerformed

    private void ChkEmisorActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ChkEmisorActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_ChkEmisorActionPerformed
    
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(VentanaProtocolo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(VentanaProtocolo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(VentanaProtocolo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(VentanaProtocolo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new VentanaProtocolo().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Btn_Devices;
    private static javax.swing.JCheckBox ChkEmisor;
    private javax.swing.JButton ElegirArc;
    private javax.swing.JButton EnviarArchivo;
    private javax.swing.JTextField MACDestino;
    private javax.swing.JTextField MACOrigen;
    private javax.swing.JTextField RutaArchivoSelec;
    private static javax.swing.JComboBox<String> jCboDevices;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    // End of variables declaration//GEN-END:variables
}