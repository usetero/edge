#include "jsoncons_wrapper.h"
#include <jsoncons/json.hpp>
#include <jsoncons_ext/jsonpath/jsonpath.hpp>
#include <string>
#include <vector>

using json = jsoncons::json;
namespace jsonpath = jsoncons::jsonpath;

thread_local std::string g_last_error;
thread_local std::string g_temp_string;

struct JsonDoc {
    json data;
};

struct JsonPathResult {
    json results;  // Array of results
    std::vector<std::string> string_cache;
};

extern "C" {

const char* json_last_error(void) {
    return g_last_error.c_str();
}

JsonDoc* json_parse(const char* str, size_t len) {
    try {
        auto* doc = new JsonDoc();
        doc->data = json::parse(std::string_view(str, len));
        return doc;
    } catch (const std::exception& e) {
        g_last_error = e.what();
        return nullptr;
    }
}

void json_free(JsonDoc* doc) {
    delete doc;
}

JsonPathResult* json_path_query(JsonDoc* doc, const char* path) {
    if (!doc) return nullptr;
    try {
        auto* result = new JsonPathResult();
        result->results = jsonpath::json_query(doc->data, path);
        return result;
    } catch (const std::exception& e) {
        g_last_error = e.what();
        return nullptr;
    }
}

void json_path_result_free(JsonPathResult* result) {
    delete result;
}

size_t json_path_result_count(JsonPathResult* result) {
    if (!result) return 0;
    return result->results.size();
}

const char* json_path_result_get(JsonPathResult* result, size_t index, size_t* out_len) {
    if (!result || index >= result->results.size()) {
        if (out_len) *out_len = 0;
        return nullptr;
    }

    // Cache the string so pointer remains valid
    if (result->string_cache.size() <= index) {
        result->string_cache.resize(index + 1);
    }

    const auto& val = result->results[index];
    if (val.is_string()) {
        result->string_cache[index] = val.as_string();
    } else {
        result->string_cache[index] = val.to_string();
    }

    if (out_len) *out_len = result->string_cache[index].size();
    return result->string_cache[index].c_str();
}

const char* json_stringify(JsonDoc* doc, size_t* out_len) {
    if (!doc) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    g_temp_string = doc->data.to_string();
    if (out_len) *out_len = g_temp_string.size();
    return g_temp_string.c_str();
}

} // extern "C"
