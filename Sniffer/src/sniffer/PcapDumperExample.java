/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package sniffer;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;


public class PcapDumperExample {
  public static void exporta(Pcap pcap) {
    /***************************************************************************
     * Third we create a PcapDumper and associate it with the pcap capture
     ***************************************************************************/
    String ofile = "tramas.pcap";
    PcapDumper dumper = pcap.dumpOpen(ofile); // output file

    /***************************************************************************
     * Fouth we create a packet handler which receives packets and tells the 
     * dumper to write those packets to its output file
     **************************************************************************/
    PcapHandler <PcapDumper> dumpHandler = new PcapHandler<PcapDumper>() {

      public void nextPacket(PcapDumper dumper, long seconds, int useconds,
        int caplen, int len, ByteBuffer buffer) {

        dumper.dump(seconds, useconds, caplen, len, buffer);
      }
    };

    /***************************************************************************
     * Fifth we enter the loop and tell it to capture 10 packets. We pass
     * in the dumper created in step 3
     **************************************************************************/
    pcap.loop(10, dumpHandler, dumper);
		
    File file = new File(ofile);
    JOptionPane.showMessageDialog(null,"Se ha exportado la sesion actual de pcap en el archivo "+ofile+" de "+file.length()+" bytes");
            
		

    /***************************************************************************
     * Last thing to do is close the dumper and pcap handles
     **************************************************************************/
    dumper.close(); // Won't be able to delete without explicit close
    /*if (file.exists()) {
      file.delete(); // Cleanup
    }*/
		
    
  }
}