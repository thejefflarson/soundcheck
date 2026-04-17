// ReDoS — intentionally vulnerable. DO NOT deploy.
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class InputValidator {
    // BUG: nested quantifiers — (a+)+ causes exponential backtracking
    private static final Pattern EMAIL = Pattern.compile(
        "^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$");

    // BUG: overlapping alternation with repetition
    private static final Pattern SLUG = Pattern.compile("^([\\w-]+)*$");

    public static boolean validateEmail(String input) {
        return EMAIL.matcher(input).matches();
    }

    public static boolean validateSlug(String input) {
        return SLUG.matcher(input).matches();
    }
}
