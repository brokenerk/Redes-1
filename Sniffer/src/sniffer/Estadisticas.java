/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package sniffer;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

public class Estadisticas{
    
    public static void graficar(int ethernet, int ieee, int llci, int llcg, int arp, int rarp, int ip4, int tcp, int udp, int icmp, int ip6){
        // create a dataset...
        DefaultCategoryDataset data = new DefaultCategoryDataset();
        data.setValue(ethernet, "Ethernet", "Capa Enlace de Datos");
        data.setValue(ieee, "IEEE802.3", "Capa Enlace de Datos");
        data.setValue(llci, "LLC Individual", "Capa Enlace de Datos");
        data.setValue(llcg, "LLC de Grupo", "Capa Enlace de Datos");
        
        data.setValue(arp, "ARP", "Capa de Red");
        data.setValue(rarp, "RARP", "Capa de Red");
        data.setValue(ip4, "IPv4", "Capa de Red");
        data.setValue(ip6, "IPv6", "Capa de Red");
        data.setValue(icmp, "ICMP", "Capa de Red");
        
        data.setValue(tcp, "TCP", "Capa de Transporte");
        data.setValue(udp, "UDP", "Capa de Transporte");
        // create a chart...
        JFreeChart chart = ChartFactory.createBarChart(
        "Protocolos Analizados",
         null, 
        null,
        data,
        PlotOrientation.VERTICAL, 
        true, 
        true, 
        false);
        // create and display a frame...
        ChartFrame frame = new ChartFrame("Estadisticas Tramas recibidas", chart);
        frame.pack();
        frame.setVisible(true);
    }
    
}