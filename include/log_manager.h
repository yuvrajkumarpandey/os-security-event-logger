#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include "event_processor.h"

#define LOG_FILE_PATH "security_logs.bin"
#define TEXT_LOG_PATH "security_logs.txt"
#define MAX_LOG_SIZE 10485760  // 10MB
#define LOG_ROTATION_COUNT 5

// Log entry structure
typedef struct {
    ProcessedEvent event;
    int log_id;
    time_t log_time;
    int archived;  // 0=active, 1=archived
} LogEntry;

// Log statistics
typedef struct {
    int total_entries;
    int high_threat_count;
    int medium_threat_count;
    int low_threat_count;
    time_t first_entry;
    time_t last_entry;
    size_t log_size;
} LogStatistics;

// Function prototypes
void init_log_manager();
int write_log_entry(ProcessedEvent *event);
int read_log_entries(LogEntry *entries, int max_entries);
int archive_old_logs();
LogStatistics get_log_statistics();
void export_to_text_file();
void search_logs_by_threat(int threat_level);
void cleanup_log_manager();

#endif