package org.json;

import java.util.ArrayList;
import java.util.List;

public class JSONArray {
    private final List<Object> items = new ArrayList<>();

    public JSONArray() {}

    public JSONArray(List<?> list) {
        if (list != null) {
            for (Object item : list) {
                items.add(JSONObject.wrap(item));
            }
        }
    }

    public JSONArray put(Object value) {
        items.add(JSONObject.wrap(value));
        return this;
    }

    public int length() {
        return items.size();
    }

    public Object get(int index) {
        return items.get(index);
    }

    public JSONObject getJSONObject(int index) {
        Object val = items.get(index);
        if (val instanceof JSONObject) {
            return (JSONObject) val;
        }
        throw new JSONException("JSONArray[" + index + "] is not a JSONObject");
    }

    public String getString(int index) {
        Object val = items.get(index);
        if (val instanceof String) {
            return (String) val;
        }
        throw new JSONException("JSONArray[" + index + "] is not a String");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(JSONObject.valueToString(items.get(i)));
        }
        sb.append(']');
        return sb.toString();
    }
}
