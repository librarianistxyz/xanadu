package org.json;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal org.json.JSONObject shim for JVM conformance testing of xnd-android classes. */
public class JSONObject {
    public static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    private final Map<String, Object> map = new LinkedHashMap<>();

    public JSONObject() {}

    public JSONObject(String source) {
        if (source == null) {
            throw new JSONException("Null JSON source");
        }
        Parser p = new Parser(source);
        Object parsed = p.parseValue();
        p.skipWs();
        if (p.pos != source.length() || !(parsed instanceof JSONObject)) {
            throw new JSONException("Expected JSON object");
        }
        this.map.putAll(((JSONObject) parsed).map);
    }

    public JSONObject put(String key, Object value) {
        if (key == null) throw new JSONException("Null key");
        map.put(key, value == null ? NULL : wrap(value));
        return this;
    }

    public JSONObject put(String key, int value) {
        return put(key, Integer.valueOf(value));
    }

    public JSONObject put(String key, boolean value) {
        return put(key, Boolean.valueOf(value));
    }

    public boolean has(String key) {
        return map.containsKey(key);
    }

    public Object get(String key) {
        if (!map.containsKey(key)) throw new JSONException("Missing key: " + key);
        return map.get(key);
    }

    public String getString(String key) {
        Object v = get(key);
        if (v instanceof String) return (String) v;
        throw new JSONException("Key is not string: " + key);
    }

    public int getInt(String key) {
        Object v = get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        throw new JSONException("Key is not int: " + key);
    }

    public JSONObject getJSONObject(String key) {
        Object v = get(key);
        if (v instanceof JSONObject) return (JSONObject) v;
        throw new JSONException("Key is not JSONObject: " + key);
    }

    public String optString(String key) {
        return optString(key, "");
    }

    public String optString(String key, String fallback) {
        Object v = map.get(key);
        if (v == null || v == NULL) return fallback;
        return String.valueOf(v);
    }

    public int optInt(String key, int fallback) {
        Object v = map.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        return fallback;
    }

    public boolean optBoolean(String key, boolean fallback) {
        Object v = map.get(key);
        if (v instanceof Boolean) return (Boolean) v;
        return fallback;
    }

    public JSONObject optJSONObject(String key) {
        Object v = map.get(key);
        return (v instanceof JSONObject) ? (JSONObject) v : null;
    }

    public Iterator<String> keys() {
        return map.keySet().iterator();
    }

    static Object wrap(Object o) {
        if (o == null || o == NULL || o instanceof JSONObject || o instanceof JSONArray
                || o instanceof String || o instanceof Number || o instanceof Boolean) {
            return o;
        }
        if (o instanceof List) {
            return new JSONArray((List<?>) o);
        }
        return String.valueOf(o);
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    static String valueToString(Object v) {
        if (v == null || v == NULL) return "null";
        if (v instanceof String) return quote((String) v);
        if (v instanceof Number || v instanceof Boolean || v instanceof JSONObject || v instanceof JSONArray) {
            return v.toString();
        }
        return quote(String.valueOf(v));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append(quote(e.getKey())).append(':').append(valueToString(e.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }

    private static final class Parser {
        final String s;
        int pos = 0;

        Parser(String s) {
            this.s = s;
        }

        void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }

        Object parseValue() {
            skipWs();
            if (pos >= s.length()) throw new JSONException("Unexpected end of JSON");
            char c = s.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' && s.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
            if (c == 'f' && s.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
            if (c == 'n' && s.startsWith("null", pos)) { pos += 4; return NULL; }
            return parseNumber();
        }

        JSONObject parseObject() {
            JSONObject obj = new JSONObject();
            pos++; // '{'
            skipWs();
            if (pos < s.length() && s.charAt(pos) == '}') { pos++; return obj; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                if (pos >= s.length() || s.charAt(pos) != ':') throw new JSONException("Expected ':'");
                pos++;
                Object val = parseValue();
                obj.map.put(key, val);
                skipWs();
                if (pos >= s.length()) throw new JSONException("Unterminated object");
                char next = s.charAt(pos++);
                if (next == '}') break;
                if (next != ',') throw new JSONException("Expected ',' or '}'");
            }
            return obj;
        }

        JSONArray parseArray() {
            JSONArray arr = new JSONArray();
            pos++; // '['
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ']') { pos++; return arr; }
            while (true) {
                arr.put(parseValue());
                skipWs();
                if (pos >= s.length()) throw new JSONException("Unterminated array");
                char next = s.charAt(pos++);
                if (next == ']') break;
                if (next != ',') throw new JSONException("Expected ',' or ']'");
            }
            return arr;
        }

        String parseString() {
            if (pos >= s.length() || s.charAt(pos) != '"') throw new JSONException("Expected '\"'");
            pos++;
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= s.length()) throw new JSONException("Bad escape");
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            String hex = s.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default: throw new JSONException("Invalid escape: \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new JSONException("Unterminated string");
        }

        Number parseNumber() {
            int start = pos;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if ("-0123456789.eE+".indexOf(c) >= 0) pos++;
                else break;
            }
            String num = s.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E")) {
                return Double.parseDouble(num);
            }
            long l = Long.parseLong(num);
            if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return (int) l;
            return l;
        }
    }
}
