package br.com.darkscreen.SecureIO;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.io.IOException;

public class ReportGenerator {

    /**
     * Gera um relatório em PDF e o salva no caminho especificado.
     *
     * @param filePath     O caminho onde o arquivo PDF será salvo.
     * @param reportContent O conteúdo que será escrito no relatório.
     * @throws IllegalArgumentException se o caminho do arquivo ou o conteúdo do relatório forem nulos ou vazios.
     * @throws IOException              se ocorrer um erro ao salvar o documento.
     */
    public void generateReport(String filePath, String reportContent) {
        // Validações de entrada
        if (filePath == null || filePath.isEmpty()) {
            throw new IllegalArgumentException("Caminho do arquivo não pode ser nulo ou vazio.");
        }

        if (reportContent == null || reportContent.isEmpty()) {
            throw new IllegalArgumentException("Conteúdo do relatório não pode ser nulo ou vazio.");
        }

        // Tenta gerar o relatório
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                contentStream.setFont(PDType1Font.HELVETICA, 12);
                contentStream.beginText();
                contentStream.newLineAtOffset(100, 700); // Posição do texto
                contentStream.showText(reportContent);
                contentStream.endText();
            }

            document.save(filePath); // Salva o documento no caminho especificado
        } catch (IOException e) {
            // Trata a exceção de forma adequada
            throw new RuntimeException("Erro ao gerar o relatório em PDF: " + e.getMessage(), e);
        }
    }
}
