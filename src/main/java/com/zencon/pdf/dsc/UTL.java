package com.zencon.pdf.dsc;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.print.*;
import com.spire.*;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Enumeration;

import javax.imageio.ImageIO;
import com.google.common.io.BaseEncoding;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.itextpdf.io.font.PdfEncodings;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.EncryptionConstants;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfDocumentInfo;

import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfReader;

import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.WriterProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.element.Image;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;



public class UTL  {
	
	public static String			DSC_PRNT_META;
	public static String			DSC_PRNT_USER;
	public static String			DSC_PRNT_INFO;
	public static String			DSC_PRNT_PCNT;

	public static String 			DSC_PKCS_TYPE;
	public static String 			DSC_PKCS_CARD;
	public static String 			DSC_PKCS_PSWD;
	public static String			DSC_PKCS_NAME;
	public static String 			DSC_PKCS_TEXT;
	
	public static String			DSC_DATE_TIME;
	
	public static String 			DSC_ROOT_FLDR;
	public static String 			DSC_INPT_FLDR;
	public static String 			DSC_INPT_FILE;	
	
	public static String	 		DSC_JLOG_FILE;
	public static String 			DSC_TEMP_FILE;
	
	public static String			DSC_SIGN_PAGE;
	public static String 			DSC_SIGN_NAME;
	public static String 			DSC_SIGN_DATE;
	public static String 			DSC_SIGN_FORM;
	public static String 			DSC_SIGN_FILE;
	public static String 			DSC_VIEW_FILE;
		
	public static String 			DSC_TEXT_SIGN;
	public static String			DSC_TEXT_CORD;
	
	public static String 			DSC_SIGN_LOGO;
	public static String 			DSC_SIGN_PICT;
	
	public static String			DSC_OUTP_LIST;
	public static String 			DSC_OUTP_TYPE;
	public static String			DSC_OUTP_CORD;
	public static String 			DSC_OUTP_FLDR;
	public static String 			DSC_OUTP_FILE;
	
	public static String			DSC_PAGE_HGHT;
	public static String			DSC_PAGE_WDTH;
	public static String			DSC_PAGE_ROTN;	
	public static String			DSC_PAGE_LIST;
	public static String			DSC_AUTH_NAME;
	
	public static String			DSC_CERT_LIST;
	public static String			DSC_CERT_CODE;
	public static String			DSC_CERT_PATH;
	public static String			DSC_CERT_PSWD;
	public static CryptoStandard 	DSC_CERT_CCMS;
	public static PrivateKey 		DSC_CERT_PKEY;
	public static X509Certificate 	DSC_CERT_X509;
	public static Certificate[]		DSC_CERT_CCHN;
	public static boolean			DSC_CERT_USGE;
	public static String 			DSC_CERT_NAME;
	public static String 			DSC_CERT_DATA;
	public static String 			DSC_CERT_ALGO;
	public static Boolean			DSC_PRNT_FILE;

	
	public static void loadConfig() throws IOException, JSONException {

		File 		file = new File("cfg/config.json");
		String 		text = FileUtils.readFileToString(file, "UTF-8");
	 	JSONObject 	json = new JSONObject(text);
		
	 	DSC_CERT_ALGO = DigestAlgorithms.SHA256;
		DSC_CERT_CCMS = CryptoStandard.CMS;
		DSC_JLOG_FILE = json.getString("DSC_JLOG_FILE");
		DSC_SIGN_LOGO = "img/dsc_inp.png";
		DSC_SIGN_PICT = "img/dsc_out.png";
		DSC_TEXT_SIGN = "Digitally signed by";
		DSC_SIGN_FORM =  "yyyy-MM-dd HH:mm:ss z";
		
		DSC_ROOT_FLDR = json.getString("DSC_ROOT_FLDR");
		DSC_OUTP_FLDR = json.getString("DSC_OUTP_FLDR");
		DSC_SIGN_PAGE = json.getString("DSC_SIGN_PAGE");
		
		DSC_PKCS_TYPE = json.getString("DSC_PKCS_TYPE");		
		DSC_PKCS_CARD = json.getString("DSC_PKCS_CARD");
		DSC_PKCS_PSWD = json.getString("DSC_PKCS_PSWD");
		DSC_PRNT_FILE = json.getBoolean("DSC_PRNT_FILE");

		DSC_PKCS_TEXT = json.getJSONObject("DSC_PKCS_LIST").toString();
		DSC_OUTP_LIST = json.getJSONObject("DSC_OUTP_LIST").toString();
		DSC_CERT_LIST = json.getJSONObject("DSC_CERT_LIST").toString();
		
		PropertyConfigurator.configure(DSC_JLOG_FILE);
	}
	public static void checkFile() {
		File 	file = new File(DSC_TEMP_FILE);
		if (!file.exists()) {
			System.out.println("Exiting in checkFile");
			System.exit(0);
		} 
	}
	public static void setOutType() throws JSONException {
		JSONObject item = new JSONObject(DSC_OUTP_LIST);
		if (item.has(DSC_OUTP_TYPE)) {
			DSC_OUTP_CORD = item.getJSONArray(DSC_OUTP_TYPE).toString();
		} else {
			DSC_OUTP_CORD = item.getJSONArray("DFLT").toString();
		}
		DSC_TEXT_CORD = item.getJSONArray("TEXT").toString();

	}
 	public static void setImage(String data) throws IOException, JSONException, InterruptedException, NoSuchAlgorithmException, CertificateException, KeyStoreException, ParseException {
 		JSONArray 			cord = new JSONArray(DSC_TEXT_CORD);
		JSONObject			item = new JSONObject();
 		final BufferedImage bimg = ImageIO.read(new File(DSC_SIGN_LOGO));
		DSC_SIGN_DATE   = "Date: " + DSC_DATE_TIME;
		String[] list= data.split(",");
		 for (String pair : list) {
			 try {
		      String split[] = pair.split("=");
		      item.put(split[0].trim(), split[1].trim());
			 } catch(Exception e) {
				 continue;
			 }     
		 }
		DSC_SIGN_NAME = item.getString("CN");
		System.out.println(DSC_SIGN_NAME);
		DSC_SIGN_NAME = DSC_SIGN_NAME.replace("DS","");
		DSC_SIGN_NAME = DSC_SIGN_NAME.replace("2","");
	    Graphics g 		= bimg.getGraphics();
	    Font font = new Font("Arial",Font.PLAIN,9); 
	    g.setFont(font);
	    ((Graphics2D) g).setComposite(AlphaComposite.Clear);
	    g.setColor(Color.BLACK);
	    g.drawString(DSC_TEXT_SIGN,                cord.getInt(0),cord.getInt(1));
	    g.drawString(DSC_SIGN_NAME,cord.getInt(0),cord.getInt(2));
//	    g.drawString(DSC_SIGN_NAME.substring(25),  cord.getInt(0),cord.getInt(3));
	    g.drawString(DSC_SIGN_DATE,cord.getInt(0), cord.getInt(3));
	    g.drawString("Auth By : " + DSC_AUTH_NAME, 	cord.getInt(0),cord.getInt(4));	    
	    g.dispose();
	    ImageIO.write(bimg, "png", new File(DSC_SIGN_PICT));
	}
	public static void setCoOrd() throws JSONException {
		int 		angle = Integer.parseInt(DSC_PAGE_ROTN);
		int 		width = Integer.parseInt(DSC_PAGE_WDTH);
		JSONArray   xcord  = new JSONArray(DSC_OUTP_CORD);
		JSONArray	clist = new JSONArray();
		int llx,lly,wdt,hgt;
    	if (angle == 90 ) {
        	llx = (int) ( width - xcord.getInt(2));
        	lly = xcord.getInt(1);
        	wdt = xcord.getInt(4);
        	hgt = xcord.getInt(3);
    	} else {
    		llx = xcord.getInt(1);
    		lly = xcord.getInt(2);
    		wdt = xcord.getInt(3);
    		hgt = xcord.getInt(4);
    	}
		clist.put(llx);
		clist.put(lly);
		clist.put(wdt);
		clist.put(hgt);
		DSC_OUTP_CORD = clist.toString();
	}
	public static void setDocMeta() throws IOException, JSONException {
		PdfReader	    read = new PdfReader(DSC_TEMP_FILE);
		PdfDocument 	pdoc = new PdfDocument(read);
		PdfDocumentInfo info = pdoc.getDocumentInfo();
		DSC_PAGE_ROTN = String.valueOf(pdoc.getPage(1).getRotation());
		DSC_PAGE_WDTH = String.valueOf((int)pdoc.getPage(1).getPageSize().getWidth());	
		DSC_PAGE_HGHT = String.valueOf((int) pdoc.getPage(1).getPageSize().getHeight());
		DSC_PRNT_PCNT = String.valueOf(pdoc.getNumberOfPages());
		DSC_PRNT_META = info.getTitle();
		pdoc.close();
	}
	public static void setDocInfo() throws JSONException, IOException {
		setDocMeta();
		setOutType();
		setPageList();
		setCoOrd();
	}
	public static void setPageList() throws JSONException {
		JSONArray list = new JSONArray();
		JSONArray   xcord  = new JSONArray(DSC_OUTP_CORD);
/*		if (DSC_SIGN_PAGE.equalsIgnoreCase("")) {
			list.put(1);
			DSC_PAGE_LIST = list.toString();
			return;
		} */
		int 	  pcnt = Integer.parseInt(DSC_PRNT_PCNT);
		int 	  ncpy = xcord.getInt(0);
		int		  item = 0;
		int 	  page = 0;
		if (ncpy>0) {
			if (ncpy > pcnt ) {
				ncpy = pcnt;
			} 
			page = pcnt / ncpy;
			for (int i=1;i<=ncpy;i++) {
				item = item + page;
				list.put(item);
			}
		} else {
			page = pcnt + ncpy;
			if (page > 0) {
				for (int i=1;i<=page;i++) {
					item = i;
					list.put(item);
				}
			} else {
				list.put(1);
			}
		}
		DSC_PAGE_LIST = list.toString();
	}

	public static void readToken() throws IOException, JSONException, KeyStoreException, NoSuchAlgorithmException, CertificateException {


	    KeyStore 			 kstore = null;
	    PasswordProtection   psprot = null;
	    Enumeration<String>  keylst = null;
	    String 				 keyitm = null;
	    JSONObject		     cclist = new JSONObject(DSC_CERT_LIST);
	    DSC_CERT_PATH   = cclist.getJSONObject(DSC_CERT_CODE).getString("DSC_CERT_PATH");
	    DSC_CERT_PSWD   = decodePWD(cclist.getJSONObject(DSC_CERT_CODE).getString("DSC_CERT_PSWD"));
	    InputStream ins = new FileInputStream(DSC_CERT_PATH);
	    Security.addProvider(new BouncyCastleProvider());
	  //  try {
	    	kstore = KeyStore.getInstance("PKCS12");
	        psprot = new PasswordProtection(DSC_CERT_PSWD.toCharArray());
	        kstore.load(ins ,  psprot.getPassword());
	        keylst = kstore.aliases();

	        while (keylst.hasMoreElements()) {
	            keyitm = keylst.nextElement();
	            try {
	            	DSC_CERT_CCHN = kstore.getCertificateChain(keyitm);
	                DSC_CERT_X509 = (X509Certificate) kstore.getCertificate(keyitm);
	                DSC_CERT_PKEY =  (PrivateKey) 	  kstore.getKey(keyitm, psprot.getPassword());
	                DSC_CERT_DATA = DSC_CERT_X509.getSubjectDN().toString();
	                DSC_CERT_USGE = DSC_CERT_X509.getKeyUsage()[0];
	                if (DSC_CERT_USGE == true) {
	                	break;
	                }
	            } catch (Exception e) {
	                continue;
	            }
	        }
	 //   } catch (Exception e) {
//	    	dispErr("Digital Signature not attached");
	   // 	System.out.println("Error at readtoken");
	    //	System.exit(0);
	   // }
	}
	public static void setNames() {
		File 	file = new File(DSC_TEMP_FILE);
		String 	name = FilenameUtils.removeExtension(file.getName());
		DSC_INPT_FILE = DSC_OUTP_FLDR+"/inp/"+name+"_inp.pdf";
		DSC_OUTP_FILE = DSC_OUTP_FLDR+"/inp/"+name+"_out.pdf";
		DSC_SIGN_FILE = DSC_OUTP_FLDR+"/out/"+name+"_signed.pdf";
		DSC_VIEW_FILE = DSC_OUTP_FLDR+"/out/"+name+"_signed_view.pdf";
		
	}

	public static void addSigns(String DSC_SIMG_OUTP) throws IOException, JSONException {
		JSONArray page = new JSONArray(DSC_PAGE_LIST);
		JSONArray cord = new JSONArray(DSC_OUTP_CORD);
		int 	  angl = Integer.parseInt(DSC_PAGE_ROTN);

		PdfCanvas 	pdfcanvas;
		Canvas		canvas;
	    
		String 	    	simage = DSC_SIMG_OUTP;
		PdfReader   	reader = new PdfReader(DSC_TEMP_FILE);
		PdfWriter   	writer = new PdfWriter(DSC_OUTP_FILE);
		PdfDocument 	pdfDoc = new PdfDocument(reader,writer);

        ImageData data = ImageDataFactory.create(simage);
        Image     simg = new Image(data);
        for (int i=0;i<page.length();i++) {
        	PdfPage xpage = pdfDoc.getPage(page.getInt(i));     
        	pdfcanvas = new PdfCanvas(xpage);
        	Rectangle rect = new Rectangle(cord.getInt(0),cord.getInt(1),cord.getInt(2),cord.getInt(3));
        	simg.setRotationAngle(Math.toRadians(angl)); 
        	simg.scaleToFit(cord.getInt(2), cord.getInt(3));
        	canvas = new Canvas(pdfcanvas,pdfDoc,rect);
           	canvas.add(simg);
        }
	    pdfDoc.close();
}

	 public static void signPDoc(String src, 
		 					 String dest,
		 					 Certificate[] chain,
		 					 PrivateKey pk, 
		 					 String digestAlgorithm, 
		 					 String provider,
		 					 PdfSigner.CryptoStandard subfilter,
		 					 String reason, 
		 					 String location)
						throws GeneralSecurityException, IOException, JSONException {
		 	JSONArray		 sgcord = new JSONArray(DSC_OUTP_CORD);
	        PdfReader 		 reader = new PdfReader(src);
	        PdfSigner 		 signer = new PdfSigner(reader, new FileOutputStream(dest), false);
	        PdfSignatureAppearance sap = signer.getSignatureAppearance();
	        PdfFont font = PdfFontFactory.createRegisteredFont("TimesRoman", PdfEncodings.WINANSI);
	        Rectangle rect = new Rectangle(	sgcord.getInt(0),sgcord.getInt(1),10,10);
	        JSONArray	page = new JSONArray(DSC_PAGE_LIST);
	        ImageData data = ImageDataFactory.create(DSC_SIGN_PICT);
	        sap.setReason(reason);
	        sap.setLayer2Font(font);
	        sap.setImage(data);
	        sap.setLayer2FontSize(8.0f);
	        sap.setLocation(location);
	        sap.setReuseAppearance(false);
	        sap.setPageRect(rect);
	        sap.setPageNumber(page.getInt(0));
	        signer.setFieldName("sig");	        

	        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
	        IExternalDigest digest = new BouncyCastleDigest();
	        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
		}

	public static String decodePWD(String pswd)  {
		String pass = null;
		pass = new String(BaseEncoding.base64().decode(pswd));
		return pass;
	}
	public static void dsblPrint( ) throws IOException {
		
        PdfReader pdfReader = new PdfReader(DSC_SIGN_FILE);
        WriterProperties writerProperties = new WriterProperties();
        writerProperties.setStandardEncryption(null, null, ~EncryptionConstants.ALLOW_PRINTING, EncryptionConstants.ENCRYPTION_AES_256);
        PdfWriter pdfWriter = new PdfWriter(new FileOutputStream(DSC_VIEW_FILE), writerProperties);
        PdfDocument pdfDocument = new PdfDocument(pdfReader, pdfWriter);
        pdfDocument.close();
		
	}
	public static void viewPDF() {
		if (Desktop.isDesktopSupported()) {
		    try {
		        File myFile = new File(DSC_SIGN_FILE);
		        Desktop.getDesktop().open(myFile);
		    } catch (IOException ex) {
		        // no application registered for PDFs
		    }
		}
	}
	public static void prntPDF() {
        //load the sample document
        com.spire.pdf.PdfDocument pdf = new com.spire.pdf.PdfDocument();
        pdf.loadFromFile(DSC_SIGN_FILE);

        PrinterJob loPrinterJob = PrinterJob.getPrinterJob();
        PageFormat loPageFormat  = loPrinterJob.defaultPage();
        Paper loPaper = loPageFormat.getPaper();

        //remove the default printing margins
        loPaper.setImageableArea(0,0,loPageFormat.getWidth(),loPageFormat.getHeight());

        //set the number of copies
        loPrinterJob.setCopies(2);

        loPageFormat.setPaper(loPaper);
        loPrinterJob.setPrintable(pdf,loPageFormat);
        try {
            loPrinterJob.print();
        } catch (PrinterException e) {
            e.printStackTrace();
        }
    } 
}

