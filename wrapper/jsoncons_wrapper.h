#ifndef JSONCONS_WRAPPER_H
#define JSONCONS_WRAPPER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles
typedef struct JsonDoc JsonDoc;
typedef struct JsonPathResult JsonPathResult;

// Parse JSON from string
JsonDoc* json_parse(const char* str, size_t len);
void json_free(JsonDoc* doc);

// JSONPath query - returns array of matches
JsonPathResult* json_path_query(JsonDoc* doc, const char* path);
void json_path_result_free(JsonPathResult* result);

// Access results
size_t json_path_result_count(JsonPathResult* result);
const char* json_path_result_get(JsonPathResult* result, size_t index, size_t* out_len);

// Get string representation of entire doc
const char* json_stringify(JsonDoc* doc, size_t* out_len);

// Error handling
const char* json_last_error(void);

#ifdef __cplusplus
}
#endif

#endif