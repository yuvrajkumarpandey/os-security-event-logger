#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "event_processor.h"

static ProcessedEvent processed_events[MAX_EVENTS];
static int processed_count = 0;
static VulnerabilityPattern patterns[10];
static int pattern_count = 0;

void init_event_processor() {
    printf("[Processor] Initializing event processor...\n");
    processed_count = 0;
    pattern_count = 0;
    memset(processed_events, 0, sizeof(processed_events));
    
    // Add default vulnerability patterns
    VulnerabilityPattern pattern1 = {
        .type = EVENT_FILE_ACCESS,
        .min_severity = 7,
        .pattern_name = "Critical File Access",
        .description = "Unauthorized access to system critical files"
    };
    add_vulnerability_pattern(pattern1);
    
    VulnerabilityPattern pattern2 = {
        .type = EVENT_PROCESS_CREATE,
        .min_severity = 5,
        .pattern_name = "Rapid Process Creation",
        .description = "Possible fork bomb or malware activity"
    };
    add_vulnerability_pattern(pattern2);
    
    VulnerabilityPattern pattern3 = {
        .type = EVENT_USER_LOGIN,
        .min_severity = 6,
        .pattern_name = "Suspicious Login",
        .description = "Login outside normal hours or from unusual location"
    };
    add_vulnerability_pattern(pattern3);
}

ProcessedEvent* process_event(SecurityEvent *event) {
    if (!event || processed_count >= MAX_EVENTS) {
        return NULL;
    }
    
    ProcessedEvent *processed = &processed_events[processed_count];
    processed->raw_event = *event;
    processed->processed_time = time(NULL);
    
    // Analyze based on event type and severity
    switch (event->type) {
        case EVENT_FILE_ACCESS:
            if (event->severity >= 8) {
                processed->threat_level = THREAT_LEVEL_HIGH;
                snprintf(processed->analysis, sizeof(processed->analysis),
                        "High severity file access detected: %s. User: %s, Process: %s",
                        event->details, event->username, event->process_name);
                strcpy(processed->recommendation, 
                       "Review file permissions and audit user activities");
            } else if (event->severity >= 5) {
                processed->threat_level = THREAT_LEVEL_MEDIUM;
                snprintf(processed->analysis, sizeof(processed->analysis),
                        "Medium severity file access: %s", event->details);
                strcpy(processed->recommendation, 
                       "Monitor user file access patterns");
            } else {
                processed->threat_level = THREAT_LEVEL_LOW;
                snprintf(processed->analysis, sizeof(processed->analysis),
                        "Normal file access: %s", event->details);
                strcpy(processed->recommendation, "No action required");
            }
            break;
            
        case EVENT_PROCESS_CREATE:
            processed->threat_level = THREAT_LEVEL_MEDIUM;
            snprintf(processed->analysis, sizeof(processed->analysis),
                    "Process creation detected: %s", event->details);
            strcpy(processed->recommendation, 
                   "Check process tree and resource usage");
            break;
            
        case EVENT_USER_LOGIN:
            if (event->severity >= 7) {
                processed->threat_level = THREAT_LEVEL_HIGH;
                snprintf(processed->analysis, sizeof(processed->analysis),
                        "Suspicious login detected for user: %s", event->username);
                strcpy(processed->recommendation, 
                       "Immediately verify user identity and check logs");
            } else {
                processed->threat_level = THREAT_LEVEL_LOW;
                snprintf(processed->analysis, sizeof(processed->analysis),
                        "Normal user login: %s", event->username);
                strcpy(processed->recommendation, "No action required");
            }
            break;
            
        default:
            processed->threat_level = THREAT_LEVEL_LOW;
            snprintf(processed->analysis, sizeof(processed->analysis),
                    "Unknown event type: %d", event->type);
            strcpy(processed->recommendation, "Monitor for patterns");
    }
    
    // Check against vulnerability patterns
    for (int i = 0; i < pattern_count; i++) {
        if (patterns[i].type == event->type && 
            event->severity >= patterns[i].min_severity) {
            printf("[Processor] Pattern matched: %s\n", patterns[i].pattern_name);
        }
    }
    
    processed_count++;
    printf("[Processor] Event processed: ID=%d, Threat Level=%d\n", 
           event->event_id, processed->threat_level);
    
    return processed;
}

void analyze_event_trends() {
    printf("[Processor] Analyzing event trends...\n");
    
    int high_count = 0, medium_count = 0, low_count = 0;
    time_t now = time(NULL);
    time_t hour_ago = now - 3600;
    
    for (int i = 0; i < processed_count; i++) {
        if (processed_events[i].processed_time > hour_ago) {
            switch (processed_events[i].threat_level) {
                case THREAT_LEVEL_HIGH: high_count++; break;
                case THREAT_LEVEL_MEDIUM: medium_count++; break;
                case THREAT_LEVEL_LOW: low_count++; break;
            }
        }
    }
    
    printf("[Processor] Last hour statistics:\n");
    printf("  High threat events: %d\n", high_count);
    printf("  Medium threat events: %d\n", medium_count);
    printf("  Low threat events: %d\n", low_count);
    
    if (high_count > 5) {
        printf("[Processor] WARNING: High threat event frequency detected!\n");
    }
}

void add_vulnerability_pattern(VulnerabilityPattern pattern) {
    if (pattern_count < 10) {
        patterns[pattern_count++] = pattern;
        printf("[Processor] Added pattern: %s\n", pattern.pattern_name);
    }
}

int get_threat_level() {
    int total_severity = 0;
    int count = 0;
    
    for (int i = 0; i < processed_count && i < 100; i++) {
        total_severity += processed_events[i].raw_event.severity;
        count++;
    }
    
    if (count == 0) return 0;
    
    int avg_severity = total_severity / count;
    
    if (avg_severity >= 8) return THREAT_LEVEL_HIGH;
    if (avg_severity >= 5) return THREAT_LEVEL_MEDIUM;
    return THREAT_LEVEL_LOW;
}

void generate_daily_report() {
    printf("[Processor] ===== DAILY SECURITY REPORT =====\n");
    printf("Total events processed: %d\n", processed_count);
    printf("Current threat level: %d\n", get_threat_level());
    printf("Last 10 processed events:\n");
    
    int start = (processed_count > 10) ? processed_count - 10 : 0;
    for (int i = start; i < processed_count; i++) {
        printf("  Event %d: Type=%d, Threat=%d, %s\n",
               processed_events[i].raw_event.event_id,
               processed_events[i].raw_event.type,
               processed_events[i].threat_level,
               processed_events[i].analysis);
    }
    printf("===================================\n");
}

void cleanup_processor() {
    printf("[Processor] Cleaning up processor resources...\n");
    processed_count = 0;
    pattern_count = 0;
}