#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include "log_manager.h"

static int log_fd = -1;
static int log_counter = 0;

void init_log_manager() {
    printf("[LogManager] Initializing log manager...\n");
    
    // Open or create binary log file
    log_fd = open(LOG_FILE_PATH, O_CREAT | O_RDWR, 0644);
    if (log_fd < 0) {
        perror("[LogManager] Failed to open log file");
        exit(1);
    }
    
    // Initialize log counter
    struct stat file_stat;
    if (fstat(log_fd, &file_stat) == 0) {
        log_counter = file_stat.st_size / sizeof(LogEntry);
    }
    
    printf("[LogManager] Log manager ready. Existing entries: %d\n", log_counter);
}

int write_log_entry(ProcessedEvent *event) {
    if (!event || log_fd < 0) {
        return -1;
    }
    
    // Check log size for rotation
    struct stat file_stat;
    if (fstat(log_fd, &file_stat) == 0 && file_stat.st_size > MAX_LOG_SIZE) {
        printf("[LogManager] Log size limit reached, archiving...\n");
        archive_old_logs();
    }
    
    // Create log entry
    LogEntry entry;
    entry.event = *event;
    entry.log_id = ++log_counter;
    entry.log_time = time(NULL);
    entry.archived = 0;
    
    // Write to end of file
    lseek(log_fd, 0, SEEK_END);
    ssize_t written = write(log_fd, &entry, sizeof(LogEntry));
    
    if (written != sizeof(LogEntry)) {
        perror("[LogManager] Failed to write log entry");
        return -1;
    }
    
    // Also write to text log for readability
    FILE *text_log = fopen(TEXT_LOG_PATH, "a");
    if (text_log) {
        fprintf(text_log, "=== Security Log Entry %d ===\n", entry.log_id);
        fprintf(text_log, "Time: %s", ctime(&entry.log_time));
        fprintf(text_log, "Event ID: %d\n", event->raw_event.event_id);
        fprintf(text_log, "Type: %d\n", event->raw_event.type);
        fprintf(text_log, "User: %s\n", event->raw_event.username);
        fprintf(text_log, "Process: %s\n", event->raw_event.process_name);
        fprintf(text_log, "Threat Level: %d\n", event->threat_level);
        fprintf(text_log, "Analysis: %s\n", event->analysis);
        fprintf(text_log, "Recommendation: %s\n", event->recommendation);
        fprintf(text_log, "Severity: %d\n", event->raw_event.severity);
        fprintf(text_log, "Details: %s\n", event->raw_event.details);
        fprintf(text_log, "================================\n\n");
        fclose(text_log);
    }
    
    printf("[LogManager] Log entry written: ID=%d\n", entry.log_id);
    return entry.log_id;
}

int read_log_entries(LogEntry *entries, int max_entries) {
    if (!entries || max_entries <= 0 || log_fd < 0) {
        return -1;
    }
    
    // Go to beginning of file
    lseek(log_fd, 0, SEEK_SET);
    
    int count = 0;
    ssize_t bytes_read;
    
    while (count < max_entries) {
        bytes_read = read(log_fd, &entries[count], sizeof(LogEntry));
        
        if (bytes_read <= 0) {
            break;
        }
        
        if (bytes_read == sizeof(LogEntry)) {
            count++;
        }
    }
    
    printf("[LogManager] Read %d log entries\n", count);
    return count;
}

int archive_old_logs() {
    printf("[LogManager] Archiving old logs...\n");
    
    time_t now = time(NULL);
    time_t month_ago = now - (30 * 24 * 3600);
    
    // Read all entries
    lseek(log_fd, 0, SEEK_SET);
    LogEntry entry;
    ssize_t bytes_read;
    int archived_count = 0;
    
    // Create archive file
    char archive_name[64];
    snprintf(archive_name, sizeof(archive_name), 
             "security_logs_archive_%ld.bin", now);
    
    int archive_fd = open(archive_name, O_CREAT | O_WRONLY, 0644);
    if (archive_fd < 0) {
        perror("[LogManager] Failed to create archive file");
        return -1;
    }
    
    while ((bytes_read = read(log_fd, &entry, sizeof(LogEntry))) > 0) {
        if (entry.log_time < month_ago && !entry.archived) {
            entry.archived = 1;
            lseek(log_fd, -sizeof(LogEntry), SEEK_CUR);
            write(log_fd, &entry, sizeof(LogEntry));
            
            write(archive_fd, &entry, sizeof(LogEntry));
            archived_count++;
        }
    }
    
    close(archive_fd);
    printf("[LogManager] Archived %d old entries to %s\n", archived_count, archive_name);
    return archived_count;
}

LogStatistics get_log_statistics() {
    LogStatistics stats = {0};
    
    if (log_fd < 0) {
        return stats;
    }
    
    lseek(log_fd, 0, SEEK_SET);
    LogEntry entry;
    ssize_t bytes_read;
    int first = 1;
    
    while ((bytes_read = read(log_fd, &entry, sizeof(LogEntry))) > 0) {
        stats.total_entries++;
        stats.log_size += bytes_read;
        
        if (first) {
            stats.first_entry = entry.log_time;
            first = 0;
        }
        
        stats.last_entry = entry.log_time;
        
        switch (entry.event.threat_level) {
            case THREAT_LEVEL_HIGH: stats.high_threat_count++; break;
            case THREAT_LEVEL_MEDIUM: stats.medium_threat_count++; break;
            case THREAT_LEVEL_LOW: stats.low_threat_count++; break;
        }
    }
    
    printf("[LogManager] Statistics collected: %d total entries\n", stats.total_entries);
    return stats;
}

void export_to_text_file() {
    printf("[LogManager] Exporting logs to text file...\n");
    
    FILE *export_file = fopen("security_logs_export.txt", "w");
    if (!export_file) {
        perror("[LogManager] Failed to create export file");
        return;
    }
    
    fprintf(export_file, "===== SECURITY LOGS EXPORT =====\n");
    fprintf(export_file, "Export Time: %s", ctime(&(time_t){time(NULL)}));
    fprintf(export_file, "================================\n\n");
    
    lseek(log_fd, 0, SEEK_SET);
    LogEntry entry;
    int count = 0;
    
    while (read(log_fd, &entry, sizeof(LogEntry)) > 0) {
        if (!entry.archived) {
            fprintf(export_file, "Log ID: %d\n", entry.log_id);
            fprintf(export_file, "Date: %s", ctime(&entry.log_time));
            fprintf(export_file, "Event Type: %d\n", entry.event.raw_event.type);
            fprintf(export_file, "User: %s\n", entry.event.raw_event.username);
            fprintf(export_file, "Threat: %d\n", entry.event.threat_level);
            fprintf(export_file, "Severity: %d\n", entry.event.raw_event.severity);
            fprintf(export_file, "Analysis: %s\n", entry.event.analysis);
            fprintf(export_file, "----------------------------\n");
            count++;
        }
    }
    
    fclose(export_file);
    printf("[LogManager] Exported %d entries to security_logs_export.txt\n", count);
}

void search_logs_by_threat(int threat_level) {
    printf("[LogManager] Searching logs for threat level %d...\n", threat_level);
    
    lseek(log_fd, 0, SEEK_SET);
    LogEntry entry;
    int found = 0;
    
    while (read(log_fd, &entry, sizeof(LogEntry)) > 0) {
        if (!entry.archived && entry.event.threat_level == threat_level) {
            printf("Found: Log ID=%d, Time=%s, User=%s, Details=%s\n",
                   entry.log_id, ctime(&entry.log_time),
                   entry.event.raw_event.username,
                   entry.event.analysis);
            found++;
        }
    }
    
    printf("[LogManager] Found %d entries with threat level %d\n", found, threat_level);
}

void cleanup_log_manager() {
    printf("[LogManager] Cleaning up log manager...\n");
    
    if (log_fd >= 0) {
        close(log_fd);
        log_fd = -1;
    }
    
    log_counter = 0;
}