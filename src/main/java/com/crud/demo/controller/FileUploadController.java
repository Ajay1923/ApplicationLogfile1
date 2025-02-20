package com.crud.demo.controller;

import com.crud.demo.model.StatisticsEntry;
import com.crud.demo.model.StatisticsFinal;


import com.crud.demo.service.StatisticsFinalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpSession;
import java.io.*;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Controller
public class FileUploadController {

    private List<String> allLogs;
    private List<String> detailedErrorLogs;
    private List<String> downloadedFilenames = new ArrayList<>();
    
    @Autowired
    private StatisticsFinalService statisticsFinalService;

    @Autowired
    private HttpSession httpSession;
	
    @GetMapping("/")
    public String index() {
        return "webpage";
    }
    @GetMapping("/chat")
    public String chat(Model model) {
        return "chat";
    }
    @GetMapping("/webpage")
    public String webpage(Model model) {
        return "webpage";
    }
    
    @GetMapping("/file")
    public String upload(Model model) {
        // Add the uploaded logs and counts to the model for display
        if (allLogs != null && detailedErrorLogs != null) {
            model.addAttribute("uploadedFileName", httpSession.getAttribute("uploadedFileName"));
            model.addAttribute("counts", httpSession.getAttribute("logCounts"));
            model.addAttribute("allLogs", allLogs);
            model.addAttribute("detailedErrorLogs", detailedErrorLogs);
        }
        return "file";
    }

    @PostMapping("/upload")
    public String uploadLogFile(@RequestParam("logfile") MultipartFile logFile, Model model) {
        Long userId = getCurrentUserId();

        if (logFile.isEmpty()) {
            model.addAttribute("error", "Please select a file to upload.");
            return "webpage";
        }
        String uploadedFileName = logFile.getOriginalFilename();
        StringBuilder downloadedExceptions = new StringBuilder();
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(logFile.getInputStream()))) {
            List<String> logLines = reader.lines().collect(Collectors.toList());

            Map<String, Integer> counts = countLogOccurrences(logLines);
            Map<String, Integer> filteredCounts = counts.entrySet().stream()
                .filter(entry -> entry.getValue() > 0)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            
            allLogs = logLines;
            detailedErrorLogs = extractDetailedErrorLogs(logLines);


            List<String> detailedErrorLogs = extractDetailedErrorLogs(logLines);

            // Add data to the model and save in session
            httpSession.setAttribute("uploadedFileName", uploadedFileName);
            httpSession.setAttribute("logCounts", filteredCounts);
            httpSession.setAttribute("uploadTimestamp", timestamp);
            httpSession.setAttribute("allLogs", logLines);
            httpSession.setAttribute("detailedErrorLogs", detailedErrorLogs);

            model.addAttribute("uploadedFileName", uploadedFileName);
            model.addAttribute("counts", filteredCounts);
            model.addAttribute("allLogs", logLines);
            model.addAttribute("detailedErrorLogs", detailedErrorLogs);
            model.addAttribute("timestamp", timestamp);
            
         // Capture the exceptions downloaded
            Set<String> uniqueDownloadedExceptions = new HashSet<>();
            for (String exceptionType : filteredCounts.keySet()) {
                if (filteredCounts.get(exceptionType) > 0) {
                    uniqueDownloadedExceptions.add(exceptionType);
                }
            }

            String downloadedExceptionsStr = String.join(", ", uniqueDownloadedExceptions);
            
            Set<String> uniqueResultingfilenames = new HashSet<>();
            for (String resultingfilenames : filteredCounts.keySet()) {
                if (filteredCounts.get(resultingfilenames) > 0) {
                	uniqueResultingfilenames.add(resultingfilenames);
                }
            }

            String resultingfilenamesStr = String.join(", ", uniqueResultingfilenames);
            
            String resultingFileName = generateResultingFileName(uploadedFileName, "Statistics");

            // Save statistics
            statisticsFinalService.saveStatistics(
                userId,
                uploadedFileName,
                null,
                filteredCounts.getOrDefault("AccessException", 0),
                filteredCounts.getOrDefault("CloudClientException", 0),
                filteredCounts.getOrDefault("InvalidFormatException", 0),
                filteredCounts.getOrDefault("NullPointerException", 0),
                filteredCounts.getOrDefault("SchedulerException", 0),
                filteredCounts.getOrDefault("SuperCsvException", 0),
                filteredCounts.getOrDefault("ValidationException", 0),
                filteredCounts.getOrDefault("ERROR", 0),
                filteredCounts.getOrDefault("INFO", 0),
                filteredCounts.keySet().toString(),
                "Uploaded",
                String.join(", ", filteredCounts.keySet())
            );

        } catch (IOException e) {
            model.addAttribute("error", "Failed to process the file: " + e.getMessage());
        }

        return "webpage";
    }

    private Long getCurrentUserId() {		
		return null;
	}

    private Map<String, List<String>> logsPerFile = new HashMap<>();
    @PostMapping("/uploadFolder")
    public String uploadLogFolder(@RequestParam("logfolder") MultipartFile[] files, Model model) {
    Long userId = getCurrentUserId();

    if (files == null || files.length == 0) {
        model.addAttribute("error", "Please select a folder containing log files.");
        return "webpage";
    }

    Map<String, List<String>> logsPerFile = new HashMap<>();
    List<String> allLines = new ArrayList<>();
    List<String> filenames = new ArrayList<>();
    StringBuilder downloadedExceptions = new StringBuilder();
    String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

    // To track overall counts across all files
    Map<String, Integer> aggregatedCounts = new HashMap<>();
    Set<String> uniqueDownloadedExceptions = new HashSet<>();
    Set<String> uniqueResultingFilenames = new HashSet<>();

    try {
        for (MultipartFile file : files) {
            if (file.isEmpty()) continue;
            String filename = file.getOriginalFilename();
            filenames.add(filename);

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()))) {
                List<String> lines = reader.lines().collect(Collectors.toList());
                allLines.addAll(lines);
                logsPerFile.put(filename, lines);

                // Process each file individually
                Map<String, Integer> counts = countLogOccurrences(lines);
                Map<String, Integer> filteredCounts = counts.entrySet().stream()
                    .filter(entry -> entry.getValue() > 0)
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                // Extract detailed error logs if needed (custom logic)
                allLogs = allLines;
                detailedErrorLogs = extractDetailedErrorLogs(allLines);
                // Store unique exception types
                uniqueDownloadedExceptions.addAll(filteredCounts.keySet());
                uniqueResultingFilenames.addAll(filteredCounts.keySet());

                // Update aggregated counts
                for (Map.Entry<String, Integer> entry : filteredCounts.entrySet()) {
                    aggregatedCounts.put(entry.getKey(), 
                        aggregatedCounts.getOrDefault(entry.getKey(), 0) + entry.getValue());
                }

                // Save statistics for each file separately
                statisticsFinalService.saveStatistics(
                    userId,
                    filename,
                    null,
                    filteredCounts.getOrDefault("AccessException", 0),
                    filteredCounts.getOrDefault("CloudClientException", 0),
                    filteredCounts.getOrDefault("InvalidFormatException", 0),
                    filteredCounts.getOrDefault("NullPointerException", 0),
                    filteredCounts.getOrDefault("SchedulerException", 0),
                    filteredCounts.getOrDefault("SuperCsvException", 0),
                    filteredCounts.getOrDefault("ValidationException", 0),
                    filteredCounts.getOrDefault("ERROR", 0),
                    filteredCounts.getOrDefault("INFO", 0),
                    filteredCounts.keySet().toString(),
                    "Uploaded",
                    String.join(", ", filteredCounts.keySet())
                );
            }
        }

        // Save aggregated statistics 
        String uploadedFileName = "Folder: " + String.join(", ", filenames);
        String downloadedExceptionsStr = String.join(", ", uniqueDownloadedExceptions);
        String resultingFilenamesStr = String.join(", ", uniqueResultingFilenames);
        String resultingFileName = generateResultingFileName(uploadedFileName, "Statistics");

        // Store data in session
        httpSession.setAttribute("logsPerFile", logsPerFile);
        httpSession.setAttribute("uploadedFileName", uploadedFileName);
        httpSession.setAttribute("logCounts", aggregatedCounts);
        httpSession.setAttribute("uploadTimestamp", timestamp);
        httpSession.setAttribute("allLogs", allLines);
        httpSession.setAttribute("detailedErrorLogs", extractDetailedErrorLogs(allLines));
        httpSession.setAttribute("filenames", filenames);

        // Save aggregated statistics for the entire upload session
        statisticsFinalService.saveStatistics(
            userId,
            uploadedFileName,
            null,
            aggregatedCounts.getOrDefault("AccessException", 0),
            aggregatedCounts.getOrDefault("CloudClientException", 0),
            aggregatedCounts.getOrDefault("InvalidFormatException", 0),
            aggregatedCounts.getOrDefault("NullPointerException", 0),
            aggregatedCounts.getOrDefault("SchedulerException", 0),
            aggregatedCounts.getOrDefault("SuperCsvException", 0),
            aggregatedCounts.getOrDefault("ValidationException", 0),
            aggregatedCounts.getOrDefault("ERROR", 0),
            aggregatedCounts.getOrDefault("INFO", 0),
            aggregatedCounts.keySet().toString(),
            "Uploaded",
            downloadedExceptionsStr
        );

        // Add attributes to the model
        model.addAttribute("filenames", filenames);
        model.addAttribute("uploadedFileName", uploadedFileName);
        model.addAttribute("counts", aggregatedCounts);
        model.addAttribute("allLogs", allLines);
        model.addAttribute("detailedErrorLogs", extractDetailedErrorLogs(allLines));
        model.addAttribute("timestamp", timestamp);

    } catch (IOException e) {
        model.addAttribute("error", "Failed to process files: " + e.getMessage());
    }

    return "webpage";
}


    @GetMapping("/getFileLogs")
    @ResponseBody
    public Map<String, Object> getFileLogs(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        Map<String, List<String>> logsPerFile = (Map<String, List<String>>) httpSession.getAttribute("logsPerFile");
        List<String> fileLogs = logsPerFile != null ? logsPerFile.get(filename) : null;

        if (fileLogs != null) {
            Map<String, Integer> counts = countLogOccurrences(fileLogs);
            Map<String, Integer> filteredCounts = counts.entrySet().stream()
                .filter(entry -> entry.getValue() > 0)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

            response.put("counts", filteredCounts);
            response.put("detailedErrorLogs", extractDetailedErrorLogs(fileLogs));
            response.put("allLogs", fileLogs);
        }
        return response;
    }

    @PostMapping("/searchExceptionData")
    public String searchExceptionData(@RequestParam("query") String query, Model model, HttpSession httpSession) {
        List<String> responses = (List<String>) httpSession.getAttribute("searchResponses");
        if (responses == null) {
            responses = new ArrayList<>();
        }
        String response = handleSearchQuery(query, (List<String>) httpSession.getAttribute("allLogs"));
        responses.add(response);
        httpSession.setAttribute("searchResponses", responses);
        model.addAttribute("responses", responses);

        return "chat";
    }

    private String handleSearchQuery(String query, List<String> uploadedFileData) {
        query = query.trim().toLowerCase();

        if (query.contains("exception count")) {
            return getExceptionCountResponse(uploadedFileData);
        } else if (query.contains("error count")) {
            return String.format("ERROR count: %d", countLogLevel(uploadedFileData, "ERROR"));
        } else if (query.contains("info count")) {
            return String.format("INFO count: %d", countLogLevel(uploadedFileData, "INFO"));
        } else if (query.contains("debug count")) {
            return String.format("DEBUG count: %d", countLogLevel(uploadedFileData, "DEBUG"));
        } else if (query.contains("stacktrace")) {
            return handleStackTraceQuery(query, uploadedFileData);
        } else if (query.contains("hello") || query.contains("hi")) {
            return "Hello! How can I assist you today?";
        } else if (query.contains("help")) {
            return "Greet me with 'Hello' or 'Hi'\n" +
                   "I can help you with the following:\n" +
                   "Ask for exception counts\n" +
                   "Ask for ERROR, INFO, or DEBUG counts\n" +
                   "Ask for a particular exception's stacktrace (e.g., 'NullPointerException stacktrace')\n" +
                   "Just type your query!";
        } else {
            return searchInLogs(query, uploadedFileData);
        }
    }

    private String getExceptionCountResponse(List<String> uploadedFileData) {
        Map<String, Integer> counts = countLogOccurrences(uploadedFileData);
        StringBuilder response = new StringBuilder("Log counts:\n");

        List<String> specificExceptions = Arrays.asList(
            "NullPointerException", "ValidationException", "SchedulerException",
            "AccessException", "InvalidFormatException", "CloudClientException", "SuperCsvException"
        );

        for (String exception : specificExceptions) {
            response.append(exception).append(": ").append(counts.getOrDefault(exception, 0)).append("\n");
        }

        response.append("ERROR: ").append(counts.getOrDefault("ERROR", 0)).append("\n");
        response.append("INFO: ").append(counts.getOrDefault("INFO", 0)).append("\n");
        response.append("DEBUG: ").append(counts.getOrDefault("DEBUG", 0)).append("\n");
        return response.toString();
    }

    private String searchInLogs(String query, List<String> uploadedFileData) {
        StringBuilder response = new StringBuilder();
        int count = 0;
        for (String line : uploadedFileData) {
            if (line.toLowerCase().contains(query)) {
                response.append("I found this in the uploaded files: ").append(line).append("\n");
                count++;
            }
            if (count >= 1000) break;
        }
        return response.length() > 0 ? response.toString() : "I'm sorry, the query is not valid.";
    }

    private String handleStackTraceQuery(String query, List<String> uploadedFileData) {
        String exceptionName = query.replace("stacktrace", "").trim();
        if (!exceptionName.isEmpty()) {
            String stackTrace = getStackTraceForException(uploadedFileData, exceptionName);
            return stackTrace.isEmpty() ? "No stack trace found for " + exceptionName : stackTrace;
        } else {
            return "Please specify the exception name for the stack trace (e.g., 'NullPointerException stacktrace').";
        }
    }

    private String getStackTraceForException(List<String> fileData, String exceptionName) {
        List<String> detailedLogs = extractDetailedErrorLogs(fileData);
        StringBuilder stackTrace = new StringBuilder();
        for (String log : detailedLogs) {
            if (log.toLowerCase().contains(exceptionName.toLowerCase())) {
                stackTrace.append(log).append("\n");
            }
        }
        return stackTrace.toString().isEmpty() ? "No stack trace found for " + exceptionName : stackTrace.toString();
    }

    private Map<String, Integer> countLogOccurrences(List<String> logLines) {
        Map<String, Integer> counts = new HashMap<>();
        counts.put("ERROR", countOccurrences(logLines, "ERROR"));
        counts.put("INFO", countOccurrences(logLines, "INFO"));
        counts.put("DEBUG", countOccurrences(logLines, "DEBUG"));
        counts.put("NullPointerException", countOccurrences(logLines, "NullPointerException"));
        counts.put("ValidationException", countOccurrences(logLines, "ValidationException"));
        counts.put("SchedulerException", countOccurrences(logLines, "SchedulerException"));
        counts.put("AccessException", countOccurrences(logLines, "AccessException"));
        counts.put("InvalidFormatException", countOccurrences(logLines, "InvalidFormatException"));
        counts.put("CloudClientException", countOccurrences(logLines, "CloudClientException"));
        counts.put("SuperCsvException", countOccurrences(logLines, "SuperCsvException"));
        return counts;
    }

    private int countOccurrences1(List<String> logLines, String searchTerm) {
        return (int) logLines.stream().filter(line -> line.contains(searchTerm)).count();
    }

    private int countLogLevel(List<String> fileData, String logLevel) {
        return (int) fileData.stream().filter(line -> line.contains(logLevel)).count();
    }

    private List<String> extractDetailedErrorLogs1(List<String> logLines) {
        List<String> detailedLogs = new ArrayList<>();
        StringBuilder currentLogEntry = new StringBuilder();
        boolean isCapturing = false;

        for (String line : logLines) {
            if (line.matches(".*\\b(ERROR|INFO|DEBUG)\\b.*")) {
                if (isCapturing) {
                    detailedLogs.add(currentLogEntry.toString().trim());
                }
                currentLogEntry = new StringBuilder();
                isCapturing = true;
                currentLogEntry.append("\n").append(line.trim()).append("\n");
            } else if (line.trim().startsWith("at ") && isCapturing) {
                currentLogEntry.append("\t").append(line.trim()).append("\n");
            } else if (isCapturing) {
                currentLogEntry.append(line.trim()).append("\n");
            }
        }

        if (isCapturing) {
            detailedLogs.add(currentLogEntry.toString().trim());
        }

        return detailedLogs;
    }

    @GetMapping("/downloadErrorLogs")
    public ResponseEntity<InputStreamResource> downloadLogs(Model model) throws IOException {
        if (detailedErrorLogs == null) {
            return ResponseEntity.badRequest().body(null);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Detailed Error Logs:\n").append(String.join("\n", detailedErrorLogs)).append("\n\n");

        ByteArrayInputStream in = new ByteArrayInputStream(sb.toString().getBytes());
        InputStreamResource resource = new InputStreamResource(in);

        String resultingFileName = generateResultingFileName("DetailedErrorLogs", "");

        // Append the filename to the session        
        // Save the resulting file name
        saveResultingFileName(resultingFileName, "Downloaded");
        saveDownloadedException(resultingFileName, "Detailed Error Logs");

        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=" + resultingFileName)
            .contentType(MediaType.TEXT_PLAIN)
            .body(resource);
    }


    @GetMapping("/downloadFilteredErrorLogs")
    public ResponseEntity<InputStreamResource> downloadFilteredLogs(@RequestParam("exceptionType") String exceptionType) throws IOException {
        if (detailedErrorLogs == null || exceptionType == null || exceptionType.isEmpty()) {
            return ResponseEntity.badRequest().body(null);
        }

        List<String> filteredLogs = detailedErrorLogs.stream()
            .filter(stackTrace -> stackTrace.contains(exceptionType))
            .collect(Collectors.toList());
        List<String> downloadedFilenames = (List<String>) httpSession.getAttribute("downloadedFilenames");
        if (downloadedFilenames == null) {
            downloadedFilenames = new ArrayList<>();
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.join("\n", filteredLogs)).append("\n\n\n");

        ByteArrayInputStream in = new ByteArrayInputStream(sb.toString().getBytes());
        InputStreamResource resource = new InputStreamResource(in);

        // Generate the resulting file name with the respective exception name
        String resultingFileName = generateResultingFileName(exceptionType, "FilteredLogs");
        // Store the downloaded filename
        downloadedFilenames.add(resultingFileName);
        httpSession.setAttribute("downloadedFilenames", downloadedFilenames);
        // Save the resulting file name to the database
        saveResultingFileName(resultingFileName, "Downloaded");
        // Save the resulting file name and exception type to the downloadedException field in the database
        saveDownloadedException(resultingFileName, exceptionType);

        // Set the file name dynamically in the response header
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=" + resultingFileName)
            .contentType(MediaType.TEXT_PLAIN)
            .body(resource);
    }

    @GetMapping("/filteredErrorLogs")
    @ResponseBody
    public List<String> filteredErrorLogs(@RequestParam("exceptionType") String exceptionType) {
        if (detailedErrorLogs == null || exceptionType == null || exceptionType.isEmpty()) {
            return Collections.emptyList();
        }

        return detailedErrorLogs.stream()
            .filter(stackTrace -> stackTrace.contains(exceptionType))
            .collect(Collectors.toList());
    }

    private int countOccurrences(List<String> logLines, String keyword) {
        return (int) logLines.stream().filter(line -> line.contains(keyword)).count();
    }

    private List<String> extractDetailedErrorLogs(List<String> logLines) {
        List<String> detailedLogs = new ArrayList<>();
        boolean isCapturing = false;  // Tracks whether we are capturing a log entry
        StringBuilder currentStackTrace = new StringBuilder();  // Holds the current stack trace
        String currentLogType = "";  // Tracks the current log type being captured (ERROR, INFO, DEBUG)

        for (String line : logLines) {
            if (line.contains("ERROR")) {
                if (!currentLogType.equals("ERROR")) {
                    if (isCapturing) {
                        // If we were already capturing, add the previous log entry before starting a new one
                        detailedLogs.add(currentStackTrace.toString().trim());
                    }
                    // Start capturing a new ERROR entry
                    isCapturing = true;
                    currentStackTrace = new StringBuilder();  
                    currentStackTrace.append(line).append("\n");
                    currentLogType = "ERROR";  // Update the log type
                } else if (isCapturing) {
                    // Continue capturing ERROR log
                    currentStackTrace.append(line).append("\n");
                }
            } else if (line.contains("INFO")) {
                if (!currentLogType.equals("INFO")) {
                    if (isCapturing) {
                        detailedLogs.add(currentStackTrace.toString().trim());
                    }
                    isCapturing = true;
                    currentStackTrace = new StringBuilder();  
                    currentStackTrace.append(line).append("\n");
                    currentLogType = "INFO";  
                } else if (isCapturing) {
                    currentStackTrace.append(line).append("\n");
                }
            } else if (line.contains("DEBUG")) {
                if (!currentLogType.equals("DEBUG")) {
                    if (isCapturing) {
                        detailedLogs.add(currentStackTrace.toString().trim());
                    }
                    isCapturing = true;
                    currentStackTrace = new StringBuilder();  
                    currentStackTrace.append(line).append("\n");
                    currentLogType = "DEBUG";
                } else if (isCapturing) {
                    currentStackTrace.append(line).append("\n");
                }
            } else if (isCapturing) {
                if (line.isEmpty() || line.startsWith("ERROR") || line.startsWith("INFO") || line.startsWith("DEBUG")) {
                    // End the current stack trace when a new log type or empty line is encountered
                    detailedLogs.add(currentStackTrace.toString().trim());
                    isCapturing = false;  // Reset capturing flag
                } else {
                    // Continue adding lines to the current stack trace
                    currentStackTrace.append(line).append("\n");
                }
            }
        }
        // If we were still capturing at the end of the loop, add the last captured log
        if (isCapturing) {
            detailedLogs.add(currentStackTrace.toString().trim());
        }

        return detailedLogs;
    }


    private String generateResultingFileName(String baseName, String suffix) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH:mm:ss");
        String timestamp = LocalDateTime.now().format(formatter);
        return baseName + "_" + timestamp + (suffix.isEmpty() ? "" : "_" + suffix) + ".txt";
    }

    private void saveResultingFileName(String filename, String status) {
        Long userId = getCurrentUserId();
        // Retrieve the existing list of filenames from the session
        List<String> resultingFileNames = (List<String>) httpSession.getAttribute("resultingFileNames");
        if (resultingFileNames == null) {
            resultingFileNames = new ArrayList<>();
        }

        // Add the new filename to the list
        resultingFileNames.add(filename);

        // Save the updated list of filenames back to the session
        httpSession.setAttribute("resultingFileNames", resultingFileNames);

        // Update the statistics with the resulting file name and status
        statisticsFinalService.updateResultingFileName(userId, filename, status);
    }
    private void saveDownloadedException(String filename, String exceptionType) {
        Long userId = getCurrentUserId();
        // Retrieve the existing list of downloaded filenames from the session
        List<String> downloadedFilenames = (List<String>) httpSession.getAttribute("downloadedFilenames");
        if (downloadedFilenames == null) {
            downloadedFilenames = new ArrayList<>();
        }

        // Add the new filename to the list
        downloadedFilenames.add(filename);

        // Save the updated list of downloaded filenames back to the session
        httpSession.setAttribute("downloadedFilenames", downloadedFilenames);

        // Update the statistics with the resulting file name and the exception type as "Downloaded Exception"
        statisticsFinalService.updateDownloadedException(userId, filename, exceptionType);
    }


    @GetMapping("/statistics")
    public String statistics(Model model,HttpSession session) {
        Long userId = getCurrentUserId();
        List<StatisticsFinal> statisticsList = statisticsFinalService.getStatisticsByUserId(userId);
        model.addAttribute("statistics", statisticsList);
    

        // Retrieve and display all resulting file names
        List<String> resultingFileNames = (List<String>) httpSession.getAttribute("resultingFileNames");
        model.addAttribute("resultingFileNames", resultingFileNames != null ? resultingFileNames : Collections.emptyList());

        List<String> downloadedFilenames = (List<String>) httpSession.getAttribute("downloadedFilenames");
        model.addAttribute("downloadedFilenames", downloadedFilenames != null ? downloadedFilenames : Collections.emptyList());

        List<String> filenames = (List<String>) session.getAttribute("filenames");
        if (filenames != null && !filenames.isEmpty()) {
            model.addAttribute("filenames", filenames);
        }
        return "statistics";
    }

    @GetMapping("/filteredlogs")
    public String filteredLogs(@RequestParam("accessType") String accessType, 
                               @RequestParam("count") int count,
                               Model model) {
    	 List<String> filteredLogs = filteredErrorLogs(accessType);
    	 Map<String, Integer> filteredLogCounts = countLogOccurrences(filteredLogs);
    	 
    	 httpSession.setAttribute("filteredLogCounts", filteredLogCounts);
    	 
        model.addAttribute("filteredLogs", filteredLogs);
        model.addAttribute("exceptionType", accessType); // Send the exception type for display
        model.addAttribute("filteredLogCounts", filteredLogCounts);
        return "filteredlogs"; // Ensure this is the correct template name
    }

    @GetMapping("/logAnalysisPage")
    public String logAnalysisPage(Model model, HttpSession session) {
        if (allLogs == null || allLogs.isEmpty()) {
            model.addAttribute("error", "No logs uploaded.");
            return "logAnalysisPage";
        }

        // Retrieve file names from the session
        List<String> filenames = (List<String>) session.getAttribute("filenames");
        model.addAttribute("filenames", filenames);

        // Filter out DEBUG and INFO logs and group stack traces for ERROR logs
        List<String> filteredLogs = new ArrayList<>();
        StringBuilder stackTrace = new StringBuilder();
        boolean isErrorStack = false;

        for (String log : allLogs) {
            if (log == null || log.trim().isEmpty()) {
                continue;
            }

            String logLevel = extractLogLevel(log);
            if (logLevel.equals("ERROR")) {
                // If we encounter a new ERROR, add the previous stack trace (if any) to filteredLogs
                if (isErrorStack && stackTrace.length() > 0) {
                    filteredLogs.add(stackTrace.toString());
                    stackTrace.setLength(0); // Reset the stack trace
                }
                isErrorStack = true; 
            } else if (isErrorStack && (logLevel.equals("DEBUG") || logLevel.equals("INFO"))) {
                // If we encounter DEBUG or INFO while capturing an ERROR stack trace, stop capturing
                if (stackTrace.length() > 0) {
                    filteredLogs.add(stackTrace.toString());
                    stackTrace.setLength(0); // Reset the stack trace
                }
                isErrorStack = false;
            }
            if (isErrorStack) {
                stackTrace.append(log).append("\n");
            }
        }
        // Add the last stack trace if it exists
        if (isErrorStack && stackTrace.length() > 0) {
            filteredLogs.add(stackTrace.toString());
        }
        // Group logs by timestamp and exception type with counts
        Map<String, Map<String, Integer>> groupedLogsCounts = new HashMap<>();
        Map<String, Map<String, List<String>>> groupedLogsStackTraces = new HashMap<>();

        for (String log : filteredLogs) {
            String timestamp = extractTimestamp(log);
            String exceptionType = extractExceptionType(log);
           // Skip logs with unknown exception types
            if (exceptionType == null) {
                continue;
            }
            // Initialize the maps for the timestamp if they don't exist
            groupedLogsCounts.computeIfAbsent(timestamp, k -> new HashMap<>());
            groupedLogsStackTraces.computeIfAbsent(timestamp, k -> new HashMap<>());
            // Initialize the list for the exception type if it doesn't exist
            groupedLogsStackTraces.get(timestamp).computeIfAbsent(exceptionType, k -> new ArrayList<>()); 
           // Add the log to the appropriate list
            groupedLogsStackTraces.get(timestamp).get(exceptionType).add(log);
            // Update the count for the exception type
            groupedLogsCounts.get(timestamp).put(exceptionType, groupedLogsCounts.get(timestamp).getOrDefault(exceptionType, 0) + 1);
        }
        // Sort timestamps in ascending order
        List<String> sortedTimestamps = new ArrayList<>(groupedLogsCounts.keySet());
        sortedTimestamps.sort((t1, t2) -> {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                Date date1 = sdf.parse(t1);
                Date date2 = sdf.parse(t2);
                return date1.compareTo(date2);
            } catch (Exception e) {
                return 0;
            }
        });
        // Add both counts and stack traces to the model
        model.addAttribute("groupedLogsCounts", groupedLogsCounts);
        model.addAttribute("groupedLogsStackTraces", groupedLogsStackTraces);
        model.addAttribute("sortedTimestamps", sortedTimestamps);

        return "logAnalysisPage";
    }
    private String extractTimestamp(String logLine) {
        // Extract timestamp in the format "2024-06-20 01:00:00"
        Pattern pattern = Pattern.compile("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}");
        Matcher matcher = pattern.matcher(logLine);
        return matcher.find() ? matcher.group() : "Unknown";
    }
    private String extractExceptionType(String logLine) {
        // Ordered list of exception types (from most specific to generic)
        List<String> exceptionTypes = Arrays.asList(
                "SchedulerException",  // Place SchedulerException before NullPointerException
                "NullPointerException",
                "AccessException",
                "CloudClientException",
                "ValidationException",
                "InvalidFormatException",
                "SuperCsvException"
                
        );
        // Find the most specific exception type in the log line
        for (String exceptionType : exceptionTypes) {
            if (logLine.contains(exceptionType)) {
                return exceptionType;
            }
        }

        return null;  
    }
    private String extractLogLevel(String logLine) {
        // Extract log level (e.g., ERROR, DEBUG, INFO)
        Pattern pattern = Pattern.compile("^(ERROR|DEBUG|INFO)");
        Matcher matcher = pattern.matcher(logLine);
        return matcher.find() ? matcher.group() : "Other";
    }    
    
}