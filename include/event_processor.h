#ifndef EVENT_PROCESSOR_H
#define EVENT_PROCESSOR_H

#include "event_monitor.h"

#define MAX_EVENTS 1000
#define THREAT_LEVEL_LOW 0
#define THREAT_LEVEL_MEDIUM 1
#define THREAT_LEVEL_HIGH 2

// Processed event with analysis
typedef struct {
    SecurityEvent raw_event;
    int threat_level;
    char analysis[512];
    char recommendation[256];
    time_t processed_time;
} ProcessedEvent;

// Vulnerability pattern
typedef struct {
    EventType type;
    int min_severity;
    char pattern_name[64];
    char description[256];
} VulnerabilityPattern;

// Function prototypes
void init_event_processor();
ProcessedEvent* process_event(SecurityEvent *event);
void analyze_event_trends();
void add_vulnerability_pattern(VulnerabilityPattern pattern);
int get_threat_level();
void generate_daily_report();
void cleanup_processor();

#endif