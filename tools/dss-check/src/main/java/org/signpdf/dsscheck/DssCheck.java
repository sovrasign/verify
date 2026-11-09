package org.signpdf.dsscheck;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Validates every PDF of the engine's compatibility corpus with EU DSS and compares the results
 * with the recorded ones.
 *
 * <pre>
 *   DssCheck CORPUS_DIR EXPECTED_JSON [--update]
 * </pre>
 *
 * Two kinds of failure:
 * <ul>
 *   <li>A broken signature or timestamp, whatever was recorded: DSS finds a signed digest that
 *       does not match the bytes, a signature value that does not verify, a message imprint that
 *       does not match, or a signature it does not recognise as PAdES baseline.</li>
 *   <li>Any difference from EXPECTED_JSON: the format DSS reports (PAdES-BASELINE-B, -T, -LT,
 *       -LTA), its indication and sub-indication, and each timestamp. The identities in the corpus
 *       come from test providers and the ephemeral keys have no certificate chain that DSS could
 *       trust, so INDETERMINATE (NO_CERTIFICATE_CHAIN_FOUND) is the expected indication: what this
 *       check guards is that the structure and the cryptography stay what an independent validator
 *       accepts, release after release.</li>
 * </ul>
 *
 * DSS runs offline: no AIA, OCSP or CRL source, so the result depends on the file only.
 */
public final class DssCheck {
    private DssCheck() {}

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("usage: DssCheck CORPUS_DIR EXPECTED_JSON [--update]");
            System.exit(2);
        }
        Path corpus = Path.of(args[0]);
        Path expected = Path.of(args[1]);
        boolean update = args.length > 2 && args[2].equals("--update");

        List<Path> pdfs;
        try (Stream<Path> s = Files.walk(corpus)) {
            pdfs = s.filter(p -> p.toString().endsWith(".pdf")).sorted().toList();
        }
        List<String> broken = new ArrayList<>();
        StringBuilder json = new StringBuilder("{\n  \"dss\": \"").append(dssVersion())
            .append("\",\n  \"files\": {");
        String sep = "\n";
        for (Path pdf : pdfs) {
            String name = corpus.relativize(pdf).toString().replace('\\', '/');
            json.append(sep).append("    ").append(str(name)).append(": ");
            json.append(validate(pdf, name, broken));
            sep = ",\n";
        }
        json.append("\n  }\n}\n");
        String result = json.toString();
        System.out.println("EU DSS " + dssVersion() + ": " + pdfs.size() + " documents validated");

        if (!broken.isEmpty()) {
            System.out.println("Broken signatures or timestamps:");
            broken.forEach(b -> System.out.println("  " + b));
        }
        if (update) {
            Files.writeString(expected, result, StandardCharsets.UTF_8);
            System.out.println("Wrote " + expected);
        } else {
            String want = Files.exists(expected) ? Files.readString(expected, StandardCharsets.UTF_8) : "";
            if (!want.replace("\r\n", "\n").equals(result)) {
                Path actual = Path.of(expected + ".actual");
                Files.writeString(actual, result, StandardCharsets.UTF_8);
                System.out.println("The results differ from " + expected + "; this run's are in "
                    + actual + ". If the change is intended (a new corpus file, a new DSS version),"
                    + " rerun with --update and say why in the pull request.");
                System.exit(1);
            }
            System.out.println("Same results as " + expected);
        }
        if (!broken.isEmpty()) {
            System.exit(1);
        }
    }

    /** The JSON object of one document's results; failures are added to {@code broken}. */
    private static String validate(Path pdf, String name, List<String> broken) {
        DSSDocument doc = new FileDocument(pdf.toFile());
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        verifier.setOcspSource(null);
        verifier.setCrlSource(null);
        Reports reports;
        try {
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
            validator.setCertificateVerifier(verifier);
            reports = validator.validateDocument();
        } catch (RuntimeException e) {
            broken.add(name + ": DSS could not read it: " + e);
            return "{ \"error\": " + str(String.valueOf(e.getMessage())) + " }";
        }
        DiagnosticData dd = reports.getDiagnosticData();
        SimpleReport sr = reports.getSimpleReport();

        StringBuilder out = new StringBuilder("{ \"signatures\": [");
        String sep = "";
        for (String id : sr.getSignatureIdList()) {
            SignatureWrapper sw = dd.getSignatureById(id);
            String format = String.valueOf(sr.getSignatureFormat(id));
            boolean dataIntact = !sw.getDigestMatchers().isEmpty()
                && sw.getDigestMatchers().stream().allMatch(XmlDigestMatcher::isDataIntact);
            boolean intact = sw.isSignatureIntact();
            boolean valid = sw.isSignatureValid();
            if (!dataIntact || !intact || !valid || !format.startsWith("PAdES-BASELINE")) {
                broken.add(name + ": signature " + id + " format " + format + ", data intact "
                    + dataIntact + ", signature intact " + intact + ", valid " + valid);
            }
            out.append(sep).append("{ \"format\": ").append(str(format))
                .append(", \"indication\": ").append(str(String.valueOf(sr.getIndication(id))))
                .append(", \"sub_indication\": ").append(str(String.valueOf(sr.getSubIndication(id))))
                .append(", \"data_intact\": ").append(dataIntact)
                .append(", \"signature_intact\": ").append(intact)
                .append(" }");
            sep = ", ";
        }
        out.append("], \"timestamps\": [");
        sep = "";
        for (TimestampWrapper ts : dd.getTimestampList()) {
            boolean imprint = ts.isMessageImprintDataIntact();
            boolean intact = ts.isSignatureIntact();
            if (!imprint || !intact) {
                broken.add(name + ": timestamp " + ts.getType() + " imprint intact " + imprint
                    + ", signature intact " + intact);
            }
            out.append(sep).append("{ \"type\": ").append(str(String.valueOf(ts.getType())))
                .append(", \"imprint_intact\": ").append(imprint)
                .append(", \"signature_intact\": ").append(intact)
                .append(" }");
            sep = ", ";
        }
        return out.append("] }").toString();
    }

    private static String dssVersion() {
        String v = SignedDocumentValidator.class.getPackage().getImplementationVersion();
        return v == null ? System.getProperty("dss.version", "unknown") : v;
    }

    /** A JSON string. */
    private static String str(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }
}
