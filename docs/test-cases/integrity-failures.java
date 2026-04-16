// Test case: integrity-failures (A08:2025)
import java.io.*;
import java.beans.XMLDecoder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

public class IntegrityFailures {

    public Object loadSession(byte[] sessionBytes) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(sessionBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        // BUG: ObjectInputStream.readObject on untrusted bytes allows RCE
        // via gadget chains (Commons Collections, etc.)
        return ois.readObject();
    }

    public Object parseJson(String userJson) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // BUG: enableDefaultTyping embeds class names in JSON, letting an
        // attacker instantiate arbitrary classes during deserialization.
        mapper.enableDefaultTyping();
        return mapper.readValue(userJson, Object.class);
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    static class PolymorphicMessage {
        public Object payload;
    }

    public Object loadXmlConfig(InputStream userInput) {
        // BUG: XMLDecoder treats input as a bean script — any caller can
        // construct ProcessBuilder and execute commands.
        XMLDecoder decoder = new XMLDecoder(userInput);
        Object result = decoder.readObject();
        decoder.close();
        return result;
    }
}
