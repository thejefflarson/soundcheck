// Test case: file-upload (A04:2025)
package com.example.upload;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.nio.file.*;

@RestController
public class FileUploadController {

    // BUG: uploads stored in webroot
    private static final String UPLOAD_DIR = "src/main/resources/static/uploads/";

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // BUG: no extension allowlist — any file type accepted
        // BUG: user-controlled filename used directly — path traversal possible
        String filename = file.getOriginalFilename();
        Path dest = Paths.get(UPLOAD_DIR + filename);
        // BUG: no file size limit enforced at application level
        Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);
        return "Uploaded: " + filename;
    }

    @PostMapping("/document")
    public String handleDocument(@RequestParam("doc") MultipartFile file) throws IOException {
        // BUG: Content-Type header trusted without magic-byte validation
        if (!file.getContentType().equals("application/pdf")) {
            return "Only PDF allowed";
        }
        // BUG: original filename preserved
        Files.copy(file.getInputStream(),
                   Paths.get(UPLOAD_DIR + file.getOriginalFilename()));
        return "OK";
    }
}
