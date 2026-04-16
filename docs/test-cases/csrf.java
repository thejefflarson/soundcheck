// Test case: csrf (A01:2025)
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // BUG: CSRF protection explicitly disabled
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}

@Controller
class TransferController {
    @GetMapping("/transfer")
    public String showForm() {
        // BUG: form template has no _csrf hidden field
        return "transfer-form";
        // transfer-form.html contains:
        // <form method="POST" action="/transfer">
        //   <input name="amount"/>
        //   <input name="to"/>
        //   <button>Send</button>
        // </form>
    }

    @PostMapping("/transfer")
    public String doTransfer(String amount, String to) {
        // BUG: no CSRF token validated — disabled globally above
        bankService.transfer(amount, to);
        return "redirect:/done";
    }
}
