package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@RestController
@RequestMapping("/api/templates")
@Tag(name = "Template Engine", description = "Template processing with SSTI and SpEL injection vulnerabilities")
public class TemplateController {

    @PostMapping("/render")
    @Operation(summary = "Render template with user data (SSTI vulnerability)")
    public ResponseEntity<String> renderTemplate(
            @Parameter(description = "Template with variables")
            @RequestBody Map<String, Object> templateData) {

        String template = (String) templateData.get("template");
        @SuppressWarnings("unchecked")
        Map<String, Object> variables = (Map<String, Object>) templateData.get("variables");

        // УЯЗВИМОСТЬ: Server-Side Template Injection (SSTI)
        // Шаблон может содержать выражения ${...} которые будут выполнены
        String result = processTemplate(template, variables);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/expression")
    @Operation(summary = "Evaluate expression (SpEL Injection vulnerability)")
    public ResponseEntity<String> evaluateExpression(
            @Parameter(description = "Expression to evaluate")
            @RequestBody String expression) {

        // УЯЗВИМОСТЬ: Expression Language Injection через несколько движков

        // Попытка 1: Nashorn JavaScript Engine
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("nashorn");

            if (engine != null) {
                Object result = engine.eval(expression);
                return ResponseEntity.ok("JavaScript Result: " + result);
            }
        } catch (Exception e) {
            // Переходим к следующему методу
        }

        // Попытка 2: Spring Expression Language (SpEL)
        try {
            ExpressionParser parser = new SpelExpressionParser();
            StandardEvaluationContext context = new StandardEvaluationContext();

            // УЯЗВИМОСТЬ: Добавляем опасные объекты в контекст
            context.setVariable("system", System.class);
            context.setVariable("runtime", Runtime.class);
            context.setVariable("exec", Runtime.getRuntime());

            Expression exp = parser.parseExpression(expression);
            Object result = exp.getValue(context);

            return ResponseEntity.ok("SpEL Result: " + result);
        } catch (Exception e) {
            // Попытка 3: Прямое выполнение через ProcessBuilder
            if (expression.startsWith("exec:") || expression.startsWith("cmd:")) {
                try {
                    String command = expression.startsWith("exec:") ?
                            expression.substring(5) : expression.substring(4);

                    ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", command);
                    Process process = pb.start();

                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(process.getInputStream())
                    );
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }

                    BufferedReader errorReader = new java.io.BufferedReader(
                            new InputStreamReader(process.getErrorStream())
                    );
                    while ((line = errorReader.readLine()) != null) {
                        output.append("ERROR: ").append(line).append("\n");
                    }

                    process.waitFor();
                    return ResponseEntity.ok("Command Result:\n" + output.toString());
                } catch (Exception ex) {
                    return ResponseEntity.badRequest().body(
                            "Command execution failed: " + ex.getMessage()
                    );
                }
            }

            return ResponseEntity.badRequest().body(
                    "Expression evaluation failed: " + e.getMessage()
            );
        }
    }

    @PostMapping("/compile")
    @Operation(summary = "Compile and run code (Code Injection vulnerability)")
    public ResponseEntity<String> compileAndRun(
            @Parameter(description = "Code to compile and execute")
            @RequestBody Map<String, String> codeData) {

        String language = codeData.getOrDefault("language", "java");
        String code = codeData.get("code");

        if (code == null || code.isEmpty()) {
            return ResponseEntity.badRequest().body("No code provided");
        }

        // УЯЗВИМОСТЬ: Выполнение произвольного кода
        try {
            if ("javascript".equalsIgnoreCase(language) || "js".equalsIgnoreCase(language)) {
                ScriptEngineManager manager = new ScriptEngineManager();
                ScriptEngine engine = manager.getEngineByName("javascript");
                if (engine != null) {
                    Object result = engine.eval(code);
                    return ResponseEntity.ok("JavaScript Result: " + result);
                }
            } else if ("python".equalsIgnoreCase(language) || "py".equalsIgnoreCase(language)) {
                // Сохраняем код во временный файл и выполняем
                Path tempFile = Files.createTempFile("script_", ".py");
                Files.writeString(tempFile, code);

                ProcessBuilder pb = new ProcessBuilder("python3", tempFile.toString());
                Process process = pb.start();

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                );
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                process.waitFor();
                Files.deleteIfExists(tempFile);

                return ResponseEntity.ok("Python Result:\n" + output);
            } else {
                // Shell execution
                Path tempFile = Files.createTempFile("script_", ".sh");
                Files.writeString(tempFile, code);
                tempFile.toFile().setExecutable(true);

                ProcessBuilder pb = new ProcessBuilder("/bin/bash", tempFile.toString());
                Process process = pb.start();

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                );
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                process.waitFor();
                Files.deleteIfExists(tempFile);

                return ResponseEntity.ok("Shell Result:\n" + output);
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Code execution failed: " + e.getMessage()
            );
        }

        return ResponseEntity.badRequest().body("Unsupported language: " + language);
    }

    /**
     * УЯЗВИМОСТЬ: Примитивный template engine с выполнением выражений.
     */
    private String processTemplate(String template, Map<String, Object> variables) {
        String result = template;

        // Заменяем переменные {{variable}}
        if (variables != null) {
            for (Map.Entry<String, Object> entry : variables.entrySet()) {
                result = result.replace(
                        "{{" + entry.getKey() + "}}",
                        String.valueOf(entry.getValue())
                );
            }
        }

        // УЯЗВИМОСТЬ: Выполнение встроенных выражений ${...}
        while (result.contains("${")) {
            int start = result.indexOf("${");
            int end = result.indexOf("}", start);

            if (end > start) {
                String expression = result.substring(start + 2, end);
                String replacement;

                try {
                    replacement = String.valueOf(evaluateExpressionValue(expression));
                } catch (Exception e) {
                    replacement = "ERROR: " + e.getMessage();
                }

                result = result.substring(0, start) + replacement +
                        result.substring(end + 1);
            } else {
                break;
            }
        }

        return result;
    }

    private Object evaluateExpressionValue(String expression) {
        // УЯЗВИМОСТЬ: Выполнение различных типов выражений

        if (expression.startsWith("system:")) {
            String property = expression.substring(7);
            return System.getProperty(property, "Property not found");

        } else if (expression.startsWith("env:")) {
            String envVar = expression.substring(4);
            String value = System.getenv(envVar);
            return value != null ? value : "Environment variable not found";

        } else if (expression.startsWith("exec:")) {
            // Выполнение команд ОС
            String command = expression.substring(5);
            try {
                Process process = Runtime.getRuntime().exec(
                        new String[]{"/bin/bash", "-c", command}
                );
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                );
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                process.waitFor();
                return output.toString().trim();
            } catch (Exception e) {
                return "Execution error: " + e.getMessage();
            }

        } else if (expression.startsWith("spel:")) {
            String spelExpr = expression.substring(5);
            try {
                ExpressionParser parser = new SpelExpressionParser();
                Expression exp = parser.parseExpression(spelExpr);
                return exp.getValue();
            } catch (Exception e) {
                return "SpEL error: " + e.getMessage();
            }

        } else if (expression.startsWith("file:")) {
            String filePath = expression.substring(5);
            try {
                return new String(Files.readAllBytes(
                        Paths.get(filePath)
                ));
            } catch (Exception e) {
                return "File read error: " + e.getMessage();
            }
        }

        return "${" + expression + "}";
    }
}
