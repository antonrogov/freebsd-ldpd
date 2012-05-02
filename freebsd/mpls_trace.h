#ifndef _LDP_TRACE_H_
#define _LDP_TRACE_H_

extern uint32_t ldp_traceflags;
extern uint8_t trace_buffer[16834];
extern int trace_buffer_len;


#define LDP_TRACE_OUT(handle, args...) {																					\
	if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {																				\
		if(trace_buffer_len == 0) {																							\
			trace_buffer_len += snprintf(trace_buffer, sizeof(trace_buffer), "OUT: " args);									\
		} else {																											\
			trace_buffer_len += snprintf(trace_buffer + trace_buffer_len, sizeof(trace_buffer) - trace_buffer_len, args);	\
		}																													\
		if(trace_buffer[strlen(trace_buffer) - 1] == '\n') {																\
			trace_buffer[strlen(trace_buffer) - 1] = '\0';																	\
			printf("Debug: %s\n", trace_buffer);																			\
			trace_buffer_len = 0;																							\
		}																													\
	}																														\
}

#define LDP_TRACE_LOG(handle, class, type, args...) {		\
	if(type & ldp_traceflags) {								\
		LDP_TRACE_OUT(handle,args);							\
	}														\
}

#define LDP_TRACE_PKT(handle, class, type, header, body) {	\
	if(type & ldp_traceflags) {								\
		header;												\
		body;												\
	}														\
}

#define LDP_DUMP_PKT(handle, class, type, func) {	\
	if(type & ldp_traceflags) {						\
		func;										\
	}												\
}

#define LDP_PRINT(data, args...) {				\
	if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {	\
		printf("Debug: PRT: " args);			\
	}											\
}

#define LDP_ENTER(data, args...) {				\
	if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {	\
		printf("Debug: ENTER: " args);			\
		printf("\n");							\
	}											\
}

#define LDP_EXIT(data, args...) {				\
	if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {	\
		printf("Debug: EXIT: " args);			\
		printf("\n");							\
	}											\
}

#endif
