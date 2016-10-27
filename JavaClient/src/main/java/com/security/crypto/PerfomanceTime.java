package com.security.crypto;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.SessionHandler;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

public class PerfomanceTime {

    private HSSFWorkbook workbook;
    private HSSFSheet sheet;
    private Map<Integer, Object[]> data;
    private int loopvalue;
    private FileInputStream file;
    private App.Command command;


    private static String Sample_Sheet = "JavaSheet";
    private static String Sample_Xcel = "CryptoDevicePerformance.xls";

    public PerfomanceTime(int loopvalue, App.Command command) {
        this.loopvalue = loopvalue;
        this.command = command;
        switch (this.command) {
            case PlainTextConnection:
                Intialize();
                break;
            case SslTlsV2:
                SSLUpdateSheet();
                break;
            default:
                System.out.println("Default Value.");
                break;
        }
    }

    public void Set_CryptoDevice_Experiment() {
        for (int i = 1; i < loopvalue; i++) {
            long ExecutionTime;

            String Receive = null;
            SessionHandler session = new SessionHandler(Properties.PlainTextConnection);
            ExecutionTime = session.StartDHKeyExchange();
            session.SendSecureMessage("hello Server 1");
            Receive = session.ReceiveSecureMessage();
            System.out.println(Receive);
            session.ConnectionClose();

            data.put(i, new Object[]{String.valueOf(i), ExecutionTime, "NUll"});
        }
    }

    public void Set_SSl_Experiment() {
        Cell cell = null;
        for (int i = 1; i < loopvalue; i++) {
            long ExecutionTime;
            cell = sheet.getRow(i).getCell(2);
            ExecutionTime = SSLPerformanceTime();
            cell.setCellValue(ExecutionTime);
        }
        try {
            file.close();

            FileOutputStream outFile = new FileOutputStream(new File(Sample_Xcel));
            workbook.write(outFile);
            outFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void WriteData() {
        SortedSet<Integer> keyset = new TreeSet<Integer>(data.keySet());
        int rownum = 0;
        for (Integer key : keyset) {
            Row row = sheet.createRow(rownum++);
            Object[] objArr = data.get(key);
            int cellnum = 0;
            for (Object obj : objArr) {
                Cell cell = row.createCell(cellnum++);
                if (obj instanceof Long)
                    cell.setCellValue((Long) obj);
                else if (obj instanceof String)
                    cell.setCellValue((String) obj);
                else if (obj instanceof Integer)
                    cell.setCellValue((Integer) obj);
                else if (obj instanceof Double)
                    cell.setCellValue((Double) obj);
                else if (obj instanceof Long)
                    cell.setCellValue((long) obj);
            }
        }
        StoreDate();
    }

    public void FindMax() {
        Cell cell = null;

        cell.setCellFormula("SUM(B2:B" + loopvalue + ")");
        String Max_Light_IoT_CryptoDevice = cell.getCellFormula();

        cell.setCellFormula("SUM(C1:C" + loopvalue + ")");
        String SSLTime = (cell.getCellFormula());

        System.out.println(SSLTime);

    }

    private long SSLPerformanceTime() {
        long elapseTime = System.currentTimeMillis();
        SessionHandler session = new SessionHandler(Properties.SslTlsV2);
        session.ConnectionClose();
        return (System.currentTimeMillis() - elapseTime);
    }

    private void Intialize() {
        workbook = new HSSFWorkbook();
        sheet = workbook.createSheet(Sample_Sheet);
        data = new HashMap<Integer, Object[]>();
        data.put(0, new Object[]{"Experiment No.", "Light_IoT_CryptoDeviceTime", "SSL_TIME"});
    }

    private void SSLUpdateSheet() {
        try {
            file = new FileInputStream(new File(Sample_Xcel));
            workbook = new HSSFWorkbook(file);
            sheet = workbook.getSheetAt(0);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void StoreDate() {
        try {
            FileOutputStream out = new FileOutputStream(new File(Sample_Xcel));
            workbook.write(out);
            out.close();
            System.out.println("Excel written successfully..");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
