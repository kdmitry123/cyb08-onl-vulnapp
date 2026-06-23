package by.tms.internalapi.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/internal/files")
public class FileProcessingController {

    private static final String UPLOAD_DIR = "/tmp/uploads/";

    @PostMapping("/process")
    public ResponseEntity<String> processFile(@RequestBody String filePath) {
        // УЯЗВИМОСТЬ: Обработка произвольных файлов
        try {
            Path path = Paths.get(filePath);
            String content = Files.readString(path);

            // УЯЗВИМОСТЬ: Выполнение команд из содержимого файла
            if (content.startsWith("EXEC:")) {
                String command = content.substring(5);
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                );
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return ResponseEntity.ok(output.toString());
            }

            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @PostMapping("/execute-command")
    public ResponseEntity<String> executeCommand(@RequestParam String cmd) {
        // УЯЗВИМОСТЬ: Выполнение произвольных команд
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", cmd);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            return ResponseEntity.ok(output.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
}