package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/files")
@Tag(name = "File Management", description = "File operations with path traversal vulnerabilities")
public class FileController {

    private static final String UPLOAD_DIR = "/tmp/uploads/";

    @GetMapping("/read")
    @Operation(summary = "Read file from server (Path Traversal vulnerability)")
    public ResponseEntity<String> readFile(
            @Parameter(description = "Filename to read")
            @RequestParam String filename) {
        // УЯЗВИМОСТЬ: Path Traversal
        // Можно прочитать любой файл: ../../etc/passwd
        try {
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            String content = Files.readString(filePath);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Error reading file: " + e.getMessage()
            );
        }
    }

    @GetMapping("/download")
    @Operation(summary = "Download file with dynamic path")
    public ResponseEntity<String> downloadFile(
            @Parameter(description = "Full path to file")
            @RequestParam String path) {
        // УЯЗВИМОСТЬ: Arbitrary File Read
        try {
            File file = new File(path);
            if (file.exists()) {
                String content = new String(Files.readAllBytes(file.toPath()));
                return ResponseEntity.ok(content);
            }
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/info")
    @Operation(summary = "Get file information")
    public ResponseEntity<String> getFileInfo(
            @Parameter(description = "File path")
            @RequestParam String filepath) {
        // УЯЗВИМОСТЬ: Раскрытие информации о файлах
        File file = new File(filepath);
        if (file.exists()) {
            StringBuilder info = new StringBuilder();
            info.append("Path: ").append(file.getAbsolutePath()).append("\n");
            info.append("Size: ").append(file.length()).append(" bytes\n");
            info.append("Readable: ").append(file.canRead()).append("\n");
            info.append("Writable: ").append(file.canWrite()).append("\n");
            info.append("Executable: ").append(file.canExecute());
            return ResponseEntity.ok(info.toString());
        }
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/resource")
    @Operation(summary = "Read resource from classpath (Information disclosure)")
    public ResponseEntity<String> readResource(
            @Parameter(description = "Resource path in classpath")
            @RequestParam String resource) {
        // УЯЗВИМОСТЬ: Чтение произвольных ресурсов из classpath
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            InputStream inputStream = classLoader.getResourceAsStream(resource);

            if (inputStream != null) {
                String content = new String(inputStream.readAllBytes());
                return ResponseEntity.ok(content);
            }
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

}
