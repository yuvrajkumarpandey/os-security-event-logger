#ifndef EVENT_MONITOR_H
#define EVENT_MONITOR_H

#include <sys/types.h>
#include <time.h>

#define MAX_PATH_LEN 256
#define MAX_USER_LEN 32
#define MAX_PROCESS_NAME 64

// Event types
typedef enum {
    EVENT_FILE_ACCESS = 1,
    EVENT_PROCESS_CREATE,
    EVENT_USER_LOGIN,
    EVENT_NETWORK_ACCESS,
    EVENT_PERMISSION_CHANGE
} EventType;

// Security event structure
typedef struct {
    int event_id;
    EventType type;
    time_t timestamp;
    pid_t pid;
    uid_t uid;
    char username[MAX_USER_LEN];
    char process_name[MAX_PROCESS_NAME];
    char details[256];
    int severity;  // 1-10 scale
} SecurityEvent;

// Function prototypes
void init_event_monitor();
void start_monitoring();
SecurityEvent* get_next_event();
void stop_monitoring();
void cleanup_monitor();

// Monitoring functions
int monitor_file_access();
int monitor_process_creation();
int monitor_user_sessions();
int monitor_network_connections();

#endif