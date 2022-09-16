package com.zencon.pdf.dsc;

import java.awt.print.PrinterException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import javax.print.PrintException;

import org.json.JSONException;

public class Main extends UTL {

	public static void main(String[] args) throws JSONException, InterruptedException, GeneralSecurityException, IOException, PrinterException, PrintException, ParseException   {
		System.setProperty("sun.java2d.cmm", "sun.java2d.cmm.kcms.KcmsServiceProvider");
		System.setProperty("java.awt.headless", "true");
		Date       date = Calendar.getInstance().getTime();  
        DateFormat text = new SimpleDateFormat("yyyyMMdd_HHmmss"); 
        DateFormat frmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); 
        switch ( args.length ) {
        case 1 : 
        	DSC_TEMP_FILE = args[0];
        	DSC_DATE_TIME = frmt.format(date);
        	DSC_OUTP_TYPE = "DFLT";
        	DSC_CERT_CODE = "DFLT";
        	DSC_AUTH_NAME = "";
        	break;
        case 2 : 
			DSC_TEMP_FILE = args[0];
			DSC_DATE_TIME = frmt.format(text.parse(args[1]));
			DSC_OUTP_TYPE = "DFLT";
			DSC_CERT_CODE = "DFLT";
			DSC_AUTH_NAME = "";
			break;
        case 3 : 
			DSC_TEMP_FILE = args[0];
			DSC_DATE_TIME = frmt.format(text.parse(args[1]));
			DSC_OUTP_TYPE = args[2];
			DSC_CERT_CODE = "DFLT";
			DSC_AUTH_NAME = "";
			break;
        case 4 : 
			DSC_TEMP_FILE = args[0];
			DSC_DATE_TIME = frmt.format(text.parse(args[1]));
			DSC_OUTP_TYPE = args[2];
			DSC_CERT_CODE = args[3];
			DSC_AUTH_NAME = "";
			break;
        case 5 : 
			DSC_TEMP_FILE = args[0];
			DSC_DATE_TIME = frmt.format(text.parse(args[1]));
			DSC_OUTP_TYPE = args[2];
			DSC_CERT_CODE = args[3];
			DSC_AUTH_NAME = args[4];
			break;
	}
		loadConfig();
		setDocInfo();
		setNames();
		readToken();
		setImage(DSC_CERT_DATA);
		addSigns(DSC_SIGN_PICT);
		signPDoc(DSC_OUTP_FILE, 
				 DSC_SIGN_FILE, 
				 DSC_CERT_CCHN, 
				 DSC_CERT_PKEY, 
				 DSC_CERT_ALGO,
				 DSC_CERT_NAME, 
				 DSC_CERT_CCMS, 
				 DSC_AUTH_NAME, 
				 ""); 
		//dsblPrint();
		if (DSC_PRNT_FILE) {
			prntPDF();
		}	else {
			viewPDF();
		}
		
		System.exit(0);
	}

}