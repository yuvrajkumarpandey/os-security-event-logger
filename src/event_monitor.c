#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include "event_monitor.h"

static int monitoring_active = 0;
static SecurityEvent event_buffer[100];
static int event_count = 0;

void init_event_monitor() {
    printf("[Monitor] Initializing event monitor...\n");
    monitoring_active = 0;
    event_count = 0;
    memset(event_buffer, 0, sizeof(event_buffer));
}

int monitor_file_access() {
    // Monitor /etc/passwd and /etc/shadow access
    struct stat passwd_stat, shadow_stat;
    static time_t last_passwd_check = 0, last_shadow_check = 0;
    
    if (stat("/etc/passwd", &passwd_stat) == 0) {
        if (last_passwd_check > 0 && passwd_stat.st_mtime > last_passwd_check) {
            SecurityEvent event;
            event.event_id = ++event_count;
            event.type = EVENT_FILE_ACCESS;
            event.timestamp = time(NULL);
            event.pid = getpid();
            event.uid = getuid();
            
            struct passwd *pw = getpwuid(event.uid);
            if (pw) {
                strncpy(event.username, pw->pw_name, MAX_USER_LEN-1);
            } else {
                strcpy(event.username, "unknown");
            }
            
            strcpy(event.process_name, "security_logger");
            snprintf(event.details, sizeof(event.details), 
                    "/etc/passwd modified at %ld", passwd_stat.st_mtime);
            event.severity = 8;
            
            event_buffer[event_count % 100] = event;
            return 1;
        }
        last_passwd_check = passwd_stat.st_mtime;
    }
    
    if (stat("/etc/shadow", &shadow_stat) == 0) {
        if (last_shadow_check > 0 && shadow_stat.st_mtime > last_shadow_check) {
            SecurityEvent event;
            event.event_id = ++event_count;
            event.type = EVENT_FILE_ACCESS;
            event.timestamp = time(NULL);
            event.pid = getpid();
            event.uid = getuid();
            
            struct passwd *pw = getpwuid(event.uid);
            if (pw) {
                strncpy(event.username, pw->pw_name, MAX_USER_LEN-1);
            } else {
                strcpy(event.username, "unknown");
            }
            
            strcpy(event.process_name, "security_logger");
            snprintf(event.details, sizeof(event.details), 
                    "/etc/shadow accessed/modified at %ld", shadow_stat.st_mtime);
            event.severity = 10;
            
            event_buffer[event_count % 100] = event;
            return 1;
        }
        last_shadow_check = shadow_stat.st_mtime;
    }
    
    return 0;
}

int monitor_process_creation() {
    // Simple process monitoring by checking running processes
    static pid_t last_pid = 0;
    pid_t current_pid = getpid();
    
    if (last_pid > 0 && current_pid > last_pid + 100) {
        // Suspicious rapid process creation
        SecurityEvent event;
        event.event_id = ++event_count;
        event.type = EVENT_PROCESS_CREATE;
        event.timestamp = time(NULL);
        event.pid = current_pid;
        event.uid = getuid();
        
        struct passwd *pw = getpwuid(event.uid);
        if (pw) {
            strncpy(event.username, pw->pw_name, MAX_USER_LEN-1);
        } else {
            strcpy(event.username, "unknown");
        }
        
        strcpy(event.process_name, "unknown");
        snprintf(event.details, sizeof(event.details), 
                "Rapid process creation detected. Last PID: %d, Current: %d", 
                last_pid, current_pid);
        event.severity = 6;
        
        event_buffer[event_count % 100] = event;
    }
    
    last_pid = current_pid;
    return 0;
}

void start_monitoring() {
    printf("[Monitor] Starting security event monitoring...\n");
    monitoring_active = 1;
    
    while (monitoring_active) {
        sleep(2);  // Check every 2 seconds
        
        if (monitor_file_access()) {
            printf("[Monitor] File access event detected\n");
        }
        
        if (monitor_process_creation()) {
            printf("[Monitor] Process creation event detected\n");
        }
    }
}

SecurityEvent* get_next_event() {
    static int last_event = 0;
    
    if (last_event < event_count) {
        last_event++;
        return &event_buffer[(last_event - 1) % 100];
    }
    
    return NULL;
}

void stop_monitoring() {
    monitoring_active = 0;
    printf("[Monitor] Monitoring stopped\n");
}

void cleanup_monitor() {
    printf("[Monitor] Cleaning up monitor resources...\n");
    monitoring_active = 0;
    event_count = 0;
}