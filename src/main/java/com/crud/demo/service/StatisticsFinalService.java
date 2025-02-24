package com.crud.demo.service;

import com.crud.demo.model.StatisticsEntry;
import com.crud.demo.model.StatisticsFinal;
import com.crud.demo.repository.StatisticsFinalRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class StatisticsFinalService {

    @Autowired
    private StatisticsFinalRepository statisticsFinalRepository;

    public void saveStatistics(Long userId, String uploadedFileName, String resultingFileName,
            int accessExceptionCount, int cloudClientExceptionCount,
            int invalidFormatExceptionCount, int nullPointerExceptionCount,
            int schedulerExceptionCount, int superCsvExceptionCount,
            int validationExceptionCount,
            int errorCount, int infoCount, int debugCount, 
            String logCodes, String status, 
            String downloadedException,
            String fileType, String subId) {
         StatisticsFinal stats = new StatisticsFinal();
         stats.setUserId(userId);
         stats.setTimestamp(LocalDateTime.now());
         stats.setUploadedFileName(uploadedFileName);
         stats.setFileType(fileType);
         stats.setSubId(subId);


        // Update the resultingFileName and append to the existing list if needed
        String existingResultingFileNames = stats.getResultingFileName();
        if (existingResultingFileNames == null || existingResultingFileNames.isEmpty()) {
            stats.setResultingFileName(resultingFileName);
        } else {
            stats.setResultingFileName(existingResultingFileNames + ", " + resultingFileName);
        }

        stats.setLogCodes(logCodes);
        stats.setStatus(status);

        // Append downloadedException to the existing list of exceptions
        String existingDownloadedExceptions = stats.getDownloadedException();
        if (existingDownloadedExceptions == null || existingDownloadedExceptions.isEmpty()) {
            stats.setDownloadedException(downloadedException);
        } else {
            stats.setDownloadedException(existingDownloadedExceptions + ", " + downloadedException);
        }

        stats.setAccessExceptionCount(accessExceptionCount);
        stats.setCloudClientExceptionCount(cloudClientExceptionCount);
        stats.setInvalidFormatExceptionCount(invalidFormatExceptionCount);
        stats.setNullPointerExceptionCount(nullPointerExceptionCount);
        stats.setSchedulerExceptionCount(schedulerExceptionCount);
        stats.setSuperCsvExceptionCount(superCsvExceptionCount);
        stats.setValidationExceptionCount(validationExceptionCount);
        stats.setErrorCount(errorCount);
        stats.setInfoCount(infoCount);
        stats.setDebugCount(debugCount);

        statisticsFinalRepository.save(stats);
    }

    // Fetch statistics by user ID
    public List<StatisticsFinal> getStatisticsByUserId(Long userId) {
        return statisticsFinalRepository.findAllByUserId(userId);
    }

    // Update the resulting file name and the status
    public void updateResultingFileName(Long userId, String resultingFileName, String status) {
        StatisticsFinal statistics = findLatestStatisticsByUserId(userId);
        if (statistics != null) {
            // Append the new resultingFileName to the existing list if it exists
            String existingResultingFileNames = statistics.getResultingFileName();
            if (existingResultingFileNames == null || existingResultingFileNames.isEmpty()) {
                statistics.setResultingFileName(resultingFileName);
            } else {
                statistics.setResultingFileName(existingResultingFileNames + ", " + resultingFileName);
            }

            statistics.setStatus(status);
            statisticsFinalRepository.save(statistics);
        } else {
            System.out.println("No statistics found for userId: " + userId);
        }
    }

    // Update the downloadedException field based on the userId, filename, and exception type
    public void updateDownloadedException(Long userId, String filename, String exceptionType) {
        StatisticsFinal statistics = findLatestStatisticsByUserId(userId);
        if (statistics != null) {
            // Append the new exceptionType to the existing downloadedException value, if any
            String existingDownloadedException = statistics.getDownloadedException();
            if (existingDownloadedException == null || existingDownloadedException.isEmpty()) {
                statistics.setDownloadedException(exceptionType);
            } else {
                statistics.setDownloadedException(existingDownloadedException + ", " + exceptionType);
            }

            // Only append the filename to the resulting file name if it's not already there
            String existingResultingFileName = statistics.getResultingFileName();
            if (existingResultingFileName == null || existingResultingFileName.isEmpty()) {
                statistics.setResultingFileName(filename);
            } else {
                // Check if the filename is already in the resultingFileName before appending
                if (!existingResultingFileName.contains(filename)) {
                    statistics.setResultingFileName(existingResultingFileName + ", " + filename);
                }
            }

            statisticsFinalRepository.save(statistics);
        } else {
            System.out.println("No statistics found for userId: " + userId);
        }
    }

    public List<StatisticsFinal> getStatisticsByDateRange(Long userId, LocalDateTime fromDate, LocalDateTime toDate) {
        return statisticsFinalRepository.findAllByUserIdAndTimestampBetween(userId, fromDate, toDate);
    }

    public StatisticsFinal findLatestStatisticsByUserId(Long userId) {
        return statisticsFinalRepository.findTopByUserIdOrderByIdDesc(userId);
    }

	public static List<StatisticsEntry> getFilteredStatistics(String selectedFile) {
		// TODO Auto-generated method stub
		return null;
	}

	public void saveStatistics(Long userId, String uploadedFileName, Object object, Integer orDefault,
			Integer orDefault2, Integer orDefault3, Integer orDefault4, Integer orDefault5, Integer orDefault6,
			Integer orDefault7, Integer orDefault8, Integer orDefault9, String string, int i, String string2,
			String string3, String downloadedExceptionsStr) {
		// TODO Auto-generated method stub
		
	}

	public void save(StatisticsFinal folderEntry) {
		// TODO Auto-generated method stub
		
	}
}