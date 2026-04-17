// Path traversal — intentionally vulnerable. DO NOT deploy.
import java.nio.file.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.*;

@RestController
public class FileController {

    private static final String UPLOAD_DIR = "/app/uploads";

    // BUG: Paths.get does not enforce containment
    @GetMapping("/download")
    public Resource download(@RequestParam String filename) {
        Path path = Paths.get(UPLOAD_DIR, filename); // ../../etc/passwd works
        return new FileSystemResource(path.toFile());
    }

    // BUG: no normalization or containment check
    @GetMapping("/read")
    public String readFile(@RequestParam String path) throws Exception {
        Path full = Paths.get(UPLOAD_DIR).resolve(path);
        // resolve doesn't prevent traversal — attacker sends ../../../etc/shadow
        return Files.readString(full);
    }

    // BUG: user controls subdirectory and filename
    @DeleteMapping("/files/{dir}/{name}")
    public String deleteFile(@PathVariable String dir, @PathVariable String name)
            throws Exception {
        Path target = Paths.get(UPLOAD_DIR, dir, name);
        Files.delete(target); // attacker deletes ../../config/application.yml
        return "deleted";
    }
}
