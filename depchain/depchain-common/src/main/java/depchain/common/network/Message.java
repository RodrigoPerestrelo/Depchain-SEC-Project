package depchain.common.network;


import java.io.Serializable;

import com.google.gson.Gson;
/**
 * Wrapper for delivered message content from AuthenticatedPerfectLinks.
 */
public class Message implements Serializable{

    private static final Gson gson = new Gson();

    public String content;
    public String type;

    /**
     * @param content the message payload
     * @param type    the message type
     */
    public Message(String content, String type) {
        this.content = content;
        this.type = type;
    }

    /** Returns the message payload. */
    public String getContent() {
        return content;
    }

    public String getType() {
        return type;
    }

    /** Serializes this message to a JSON string. */
    public String formatMessage(){
        return gson.toJson(this);
    }

    public static Message fromJson(String json) {
        return gson.fromJson(json, Message.class);
    }
}

