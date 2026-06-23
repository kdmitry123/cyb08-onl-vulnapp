package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/health")
@Tag(name = "Health Check", description = "System health and diagnostic endpoints")
public class HealthCheckController {

    private final RestTemplate restTemplate;
    private final String internalApiUrl;
    private final String internalApiKey;

    public HealthCheckController(RestTemplate restTemplate,
                                 @Value("${internal.api.url}") String internalApiUrl,
                                 @Value("${internal.api.key}") String internalApiKey) {
        this.restTemplate = restTemplate;
        this.internalApiUrl = internalApiUrl;
        this.internalApiKey = internalApiKey;
    }

    @GetMapping("/system")
    @Operation(summary = "Get system information (Information disclosure)")
    public ResponseEntity<Map<String, Object>> getSystemInfo() {
        // УЯЗВИМОСТЬ: Раскрытие детальной информации о системе
        Map<String, Object> info = new HashMap<>();

        info.put("timestamp", LocalDateTime.now().toString());
        info.put("hostname", getHostname());
        info.put("javaVersion", System.getProperty("java.version"));
        info.put("javaVendor", System.getProperty("java.vendor"));
        info.put("osName", System.getProperty("os.name"));
        info.put("osVersion", System.getProperty("os.version"));
        info.put("osArch", System.getProperty("os.arch"));
        info.put("availableProcessors", Runtime.getRuntime().availableProcessors());
        info.put("totalMemory", Runtime.getRuntime().totalMemory());
        info.put("freeMemory", Runtime.getRuntime().freeMemory());
        info.put("maxMemory", Runtime.getRuntime().maxMemory());

        // УЯЗВИМОСТЬ: Раскрытие переменных окружения
        Map<String, String> envVars = new HashMap<>();
        // Фильтруем только "безопасные" переменные
        System.getenv().forEach((key, value) -> {
            if (!key.toLowerCase().contains("key") &&
                    !key.toLowerCase().contains("secret") &&
                    !key.toLowerCase().contains("password") &&
                    !key.toLowerCase().contains("token")) {
                envVars.put(key, value);
            }
        });
        info.put("environmentVariables", envVars);

        // УЯЗВИМОСТЬ: Раскрытие системных свойств
        Properties sysProps = System.getProperties();
        Map<String, String> props = new HashMap<>();
        sysProps.forEach((key, value) -> {
            String keyStr = key.toString();
            if (!keyStr.toLowerCase().contains("password") &&
                    !keyStr.toLowerCase().contains("secret") &&
                    !keyStr.toLowerCase().contains("key")) {
                props.put(keyStr, value.toString());
            }
        });
        info.put("systemProperties", props);

        return ResponseEntity.ok(info);
    }

    @GetMapping("/internal-status")
    @Operation(summary = "Check Internal API status (SSRF via health check)")
    public ResponseEntity<Map<String, Object>> checkInternalStatus() {
        // УЯЗВИМОСТЬ: SSRF через health check
        Map<String, Object> status = new HashMap<>();
        status.put("publicApi", "UP");

        try {
            String response = restTemplate.getForObject(
                    internalApiUrl + "/actuator/health", String.class
            );
            status.put("internalApi", response);
        } catch (Exception e) {
            status.put("internalApi", "DOWN - " + e.getMessage());
        }

        try {
            String response = restTemplate.getForObject(
                    internalApiUrl + "/actuator/env", String.class
            );
            status.put("internalApiEnv", response);
        } catch (Exception e) {
            status.put("internalApiEnv", "UNAVAILABLE");
        }

        return ResponseEntity.ok(status);
    }

    @GetMapping("/disk")
    @Operation(summary = "Get disk usage information")
    public ResponseEntity<Map<String, Object>> getDiskInfo() {
        // УЯЗВИМОСТЬ: Раскрытие информации о файловой системе
        Map<String, Object> diskInfo = new HashMap<>();
        List<Map<String, Object>> drives = new ArrayList<>();

        for (File root : File.listRoots()) {
            Map<String, Object> drive = new HashMap<>();
            drive.put("path", root.getAbsolutePath());
            drive.put("totalSpace", root.getTotalSpace());
            drive.put("freeSpace", root.getFreeSpace());
            drive.put("usableSpace", root.getUsableSpace());
            drives.add(drive);
        }

        diskInfo.put("drives", drives);

        // Информация о директориях приложения
        Map<String, String> appDirs = new HashMap<>();
        appDirs.put("userDir", System.getProperty("user.dir"));
        appDirs.put("userHome", System.getProperty("user.home"));
        appDirs.put("tmpDir", System.getProperty("java.io.tmpdir"));
        diskInfo.put("applicationDirectories", appDirs);

        return ResponseEntity.ok(diskInfo);
    }

    @GetMapping("/threads")
    @Operation(summary = "Get thread dump information")
    public ResponseEntity<Map<String, Object>> getThreadInfo() {
        // УЯЗВИМОСТЬ: Раскрытие дампа потоков
        Map<String, Object> threadInfo = new HashMap<>();
        List<Map<String, Object>> threads = new ArrayList<>();

        for (Map.Entry<Thread, StackTraceElement[]> entry :
                Thread.getAllStackTraces().entrySet()) {
            Thread thread = entry.getKey();
            Map<String, Object> threadData = new HashMap<>();
            threadData.put("name", thread.getName());
            threadData.put("id", thread.threadId());
            threadData.put("state", thread.getState().toString());
            threadData.put("priority", thread.getPriority());
            threadData.put("isDaemon", thread.isDaemon());

            List<String> stackTrace = new ArrayList<>();
            for (StackTraceElement element : entry.getValue()) {
                stackTrace.add(element.toString());
            }
            threadData.put("stackTrace", stackTrace);

            threads.add(threadData);
        }

        threadInfo.put("threadCount", threads.size());
        threadInfo.put("threads", threads);

        return ResponseEntity.ok(threadInfo);
    }

    private String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }
}