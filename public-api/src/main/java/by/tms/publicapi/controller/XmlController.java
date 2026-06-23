package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.io.StringWriter;

@RestController
@RequestMapping("/api/xml")
@Tag(name = "XML Processing", description = "XML processing with XXE and XSLT injection vulnerabilities")
public class XmlController {

    @PostMapping("/import")
    @Operation(summary = "Import XML data (XXE vulnerability)")
    public ResponseEntity<String> importXml(
            @Parameter(description = "XML data to parse")
            @RequestBody String xmlData) {

        try {
            // УЯЗВИМОСТЬ: XXE - XML External Entity Processing
            // Не отключаем внешние сущности, что позволяет читать файлы и делать SSRF
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // УЯЗВИМОСТЬ: Явно включаем опасные фичи
            factory.setFeature(
                    "http://xml.org/sax/features/external-general-entities", true
            );
            factory.setFeature(
                    "http://xml.org/sax/features/external-parameter-entities", true
            );
            factory.setFeature(
                    "http://apache.org/xml/features/nonvalidating/load-external-dtd", true
            );
            factory.setXIncludeAware(true);
            factory.setExpandEntityReferences(true);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(
                    new InputSource(new StringReader(xmlData))
            );

            // Конвертируем обратно для отображения содержимого
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));

            return ResponseEntity.ok("Parsed XML:\n" + writer);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "XML Parse Error: " + e.getMessage()
            );
        }
    }

    @PostMapping("/transform")
    @Operation(summary = "Transform XML with XSLT (XSLT Injection)")
    public ResponseEntity<String> transformXml(
            @Parameter(description = "XML content")
            @RequestParam String xml,
            @Parameter(description = "XSLT stylesheet (optional)")
            @RequestParam(required = false) String xslt) {

        try {
            TransformerFactory factory = TransformerFactory.newInstance();

            // УЯЗВИМОСТЬ: Небезопасная фабрика трансформеров
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);

            Source xmlSource = new StreamSource(
                    new StringReader(xml)
            );

            if (xslt != null && !xslt.isEmpty()) {
                // УЯЗВИМОСТЬ: XSLT Injection - можно выполнять произвольные трансформации
                // XSLT может содержать команды для чтения файлов и SSRF
                Source xsltSource = new StreamSource(
                        new StringReader(xslt)
                );

                Transformer transformer = factory.newTransformer(xsltSource);
                StringWriter writer = new StringWriter();
                transformer.transform(xmlSource, new StreamResult(writer));
                return ResponseEntity.ok("Transformed XML:\n" + writer);
            }

            return ResponseEntity.ok(xml);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Transform Error: " + e.getMessage()
            );
        }
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate XML against DTD (DTD Injection)")
    public ResponseEntity<String> validateXml(
            @Parameter(description = "XML to validate")
            @RequestParam String xml,
            @Parameter(description = "Custom DTD (optional)")
            @RequestParam(required = false) String dtd) {

        try {
            // УЯЗВИМОСТЬ: Позволяем использовать пользовательские DTD
            String xmlWithDtd;

            if (dtd != null && !dtd.isEmpty()) {
                // Вставляем пользовательский DTD
                if (xml.startsWith("<?xml")) {
                    int insertPoint = xml.indexOf("?>") + 2;
                    xmlWithDtd = xml.substring(0, insertPoint) +
                            "\n<!DOCTYPE root [\n" + dtd + "\n]>\n" +
                            xml.substring(insertPoint);
                } else {
                    xmlWithDtd = "<?xml version=\"1.0\"?>\n" +
                            "<!DOCTYPE root [\n" + dtd + "\n]>\n" +
                            xml;
                }
            } else {
                xmlWithDtd = xml;
            }

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setValidating(true);

            // УЯЗВИМОСТЬ: Включаем загрузку внешних DTD
            factory.setFeature(
                    "http://apache.org/xml/features/nonvalidating/load-external-dtd", true
            );

            DocumentBuilder builder = factory.newDocumentBuilder();

            // Добавляем обработчик ошибок для получения информации о валидации
            builder.setErrorHandler(new ErrorHandler() {
                @Override
                public void warning(SAXParseException exception) {
                }

                @Override
                public void error(SAXParseException exception)
                        throws SAXException {
                    throw exception;
                }

                @Override
                public void fatalError(SAXParseException exception)
                        throws SAXException {
                    throw exception;
                }
            });

            Document document = builder.parse(
                    new InputSource(new StringReader(xmlWithDtd))
            );

            return ResponseEntity.ok("XML is valid. Root element: " +
                    document.getDocumentElement().getNodeName());
        } catch (Exception e) {
            return ResponseEntity.ok("Validation result: " + e.getMessage());
        }
    }

    @PostMapping("/xpath")
    @Operation(summary = "Execute XPath query on XML (XPath Injection)")
    public ResponseEntity<String> executeXPath(
            @Parameter(description = "XML document")
            @RequestParam String xml,
            @Parameter(description = "XPath expression")
            @RequestParam String xpath) {

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(
                    new InputSource(new StringReader(xml))
            );

            // УЯЗВИМОСТЬ: XPath Injection
            // Позволяет обходить аутентификацию и извлекать данные
            XPath xPath = XPathFactory.newInstance().newXPath();
            String result = xPath.evaluate(xpath, document);

            return ResponseEntity.ok("XPath Result: " + result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "XPath Error: " + e.getMessage()
            );
        }
    }
}
