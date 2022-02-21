package rss.app;

import java.io.File;
import java.io.IOException;


import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

public class FileByBlocks {
    private File file;

    FileByBlocks(String fileName) {
        this.file = new File(fileName);
        try (PDDocument doc = PDDocument.load(file)) {

            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(doc);

            System.out.println("Text size: " + text.length() + " characters:");
            System.out.println(text);
        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}