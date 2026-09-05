import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.apache.commons.compress.archivers.sevenz.*;
import com.garmin.connectiq.common.signing.*;
import com.garmin.connectiq.common.apps.ExecutableUtils;
import com.garmin.connectiq.common.prgreader.PrgReader;

/** Re-sign compiler-produced IQ packages with the GitHub key using Garmin's SDK. */
public class SignGarmin {
    public static void main(String[] args) throws Exception {
        var key = KeyUtils.getPrivateKey(args[0]);
        var publicKey = KeyUtils.getPublicKey(key);
        Path input = Path.of(args[1]), output = Path.of(args[2]);
        Files.createDirectories(output);
        if (!VerifyingUtils.verifyIqFile(input.toFile(), publicKey)) {
            throw new SecurityException("Input package signature/key mismatch");
        }
        var entries = new TreeMap<String, byte[]>();
        try (var archive = SevenZFile.builder().setFile(input.toFile()).get()) {
            for (var entry : archive.getEntries()) {
                if (!entry.isDirectory()) {
                    try (var stream = archive.getInputStream(entry)) {
                        entries.put(entry.getName(), stream.readAllBytes());
                    }
                }
            }
        }
        if (!Arrays.equals(KeyUtils.getPublicKey(entries.get("dev_key.pub")).getEncoded(), publicKey.getEncoded())) {
            throw new SecurityException("Repository secret does not match existing developer identity");
        }
        Path scratch = Files.createTempFile("garmin-sign-", ".prg");
        int programs = 0;
        try {
            for (var entry : entries.entrySet()) {
                if (!entry.getKey().endsWith(".prg")) continue;
                var reader = ExecutableUtils.readDeveloperSignature(entry.getValue());
                int offset = reader.getSectionOffset(PrgReader.PrgSectionType.DEVELOPER_SIGNATURE);
                Files.write(scratch, ExecutableUtils.stripSignatureFromPrg(entry.getValue(), offset));
                SigningUtils.signPrgAsDeveloper(scratch.toFile(), key);
                if (!VerifyingUtils.verifyDeveloperSignatureOfPrgFile(scratch.toFile())) throw new SecurityException("Invalid signed PRG");
                byte[] signed = Files.readAllBytes(scratch);
                // Same SDK/key must produce identical PRGs; preserve manifest hashes.
                if (!Arrays.equals(signed, entry.getValue())) throw new SecurityException("Re-signing changed compiled program/hash");
                entry.setValue(signed);
                var devices = Map.of("006-B4432-00", "fr165", "006-B4433-00", "fr165m",
                    "006-B4257-00", "fr265", "006-B4258-00", "fr265s", "006-B4315-00", "fr965");
                String device = devices.get(entry.getKey().split("/")[0]);
                if (device == null) throw new SecurityException("Unexpected device in package");
                Files.write(output.resolve(input.getFileName().toString().replace(".iq", "-" + device + ".prg")), signed);
                programs++;
            }
            Files.write(scratch, entries.get("manifest.xml"));
            entries.put("manifest.sig", SigningUtils.computeSignatureForManifest(scratch.toFile(), key));
            entries.put("manifest.sig2", SigningUtils.computeSha256SignatureForManifest(scratch.toFile(), key));
        } finally { Files.deleteIfExists(scratch); }
        Path result = output.resolve(input.getFileName());
        try (var zip = new ZipOutputStream(Files.newOutputStream(result))) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey())); zip.write(entry.getValue()); zip.closeEntry();
            }
        }
        if (programs < 5 || !VerifyingUtils.verifyIqFile(result.toFile(), publicKey)) throw new SecurityException("Invalid signed IQ package");
        System.out.println("Signed and verified " + result.getFileName() + ": " + programs + " programs");
    }
}
