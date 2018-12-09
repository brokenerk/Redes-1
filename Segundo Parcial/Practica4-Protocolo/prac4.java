try{
	JFileChooser jf = new JFileChooser();
	//jf.setMultiSelectionEnabled(true);

	int r = jf.showOpenDialog(null);

	if(r == JFileChooser.APPROVE_OPTION){
		File f = jf.getSelectedFile();
		String nombre_arc = f.getName();
		String path = f.getAbsolutePath();
		long tam=f.length();
		DataInputStream dis = new DataInputStream(new FileInputStream(path));
		long enviados = 0;
		int n = 0, tmax = 1400;

		while(enviados < tam){
			byte[] b = new byte[tmax];
			n=dis.read(b);
		}
	}
}

//Arrays.copyOf( , );