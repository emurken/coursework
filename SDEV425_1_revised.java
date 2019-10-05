package sdev425;
/*
 * Homework1 | Eric Murken | March 31, 2019 
 * SDEV 425 7980 Mitigating Software Vulnerabilities 
 * Professor Ronald McFarland
 * Description:
 * Revision of SDEV425_1.java to mitigate security issues in original code.
 * Application receives command-line argument to designate a text file that 
 * contains email addresses, reads the contents of the file, and displays 
 * the email addresses via system output. Revised application checks file 
 * extension / type, processes text file inputs and validates email formats.
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.Objects;
import java.util.regex.Pattern;
import org.apache.commons.io.FilenameUtils;
import org.apache.tika.Tika;

public class SDEV425_1_revised {

    // define email format regex, restrict to alphanumeric, tld must be at least 2 chars
    private static final String emailPatt = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
            + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    // define filename format regex, restrict to alphanumeric chars, no beginning
    // or ending spaces, file extension must have at least 1 char
    private static final String filePatt = "[a-zA-Z0-9](?:[a-zA-Z0-9 ._-]*"
            + "[a-zA-Z0-9])?\\.[a-zA-Z0-9_-]+";

    // normalize using NFKC form - compatibility decomp > canonical comp
    private static String normalizeString(String input) {
        input = Normalizer.normalize(input, Form.NFKC);
        return input;
    }

    /**
     * method to check the file type via Apache Tika
     * @param filename
     * @return extension
     * @throws IOException 
     */
    private static String checkFileType(String filename) throws IOException {
        String extension = null;
        try {
            // new file object for filename
            File file = new File(filename);
            //Instantiate tika class 
            Tika tika = new Tika();
            // use default Tika detect method to determine filetype
            extension = tika.detect(file);
        } catch (IOException e) {
            System.err.println("File error");
            System.exit(0);
        } finally {
            return extension;
        }
    }

    /**
     * validate filename format
     * @param filename
     * @return filename
     */
    private static String checkFilename(String filename) {
        filename = normalizeString(filename);
        Pattern pattern = Pattern.compile(filePatt);
        if (!pattern.matcher(filename).matches()) {
            System.err.println("Invalid file");
            System.exit(0);
        }
        return filename;
    }

    /**
     * validate filetype
     * @param filename
     * @return
     * @throws IOException 
     */
    private static boolean validateType(String filename) throws IOException {
        boolean goodFile;
        String acceptedType = "text/plain";
        String acceptedExt = "txt";
        String filetype = null;

        try {
            // check file type w/ Tika library
            filetype = checkFileType(filename);
        } catch (IOException e) {
            System.err.println("Invalid filename");
            System.exit(0);
        } 
        // check file extension as written
        String extension = FilenameUtils.getExtension(filename);
        // if filetype is not 'text/plain' or does not have a
        //      .txt extension, file is refused
        if ((!Objects.equals(filetype, acceptedType))
                || (!Objects.equals(extension, acceptedExt))) {
            // invalid file type
            goodFile = false;
        } else {
            // file type is OK
            goodFile = true;
        }
        return goodFile;
    }

    /**
     * Encodes invalid characters
     * @param input
     * @return 
     */
    private static String HTMLEntityEncode(String input) {
        StringBuffer sb = new StringBuffer();
        char ch1 = '\u0040'; // @ unicode character
        char ch2 = '\u002e'; // . unicode character
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (Character.isLetterOrDigit(ch) || ch==ch1 || ch==ch2
                    ) {
                sb.append(ch);
            } else {
                sb.append("&#" + (int) ch + ";");
            }
        }
        return sb.toString();
    }

    /**
     * checks email format
     * @param input
     * @return 
     */
    private static String validateOutput(String input) {
        input = normalizeString(input);
        Pattern pattern = Pattern.compile(emailPatt);
        if (!pattern.matcher(input).matches()) {
            // input text does not match approved email format, return 
            // 'invalid format' and encode invalid characters
            input = ("Invalid format: \n    " + HTMLEntityEncode(input));
        }
        return input;
    }

    public static void main(String[] args) throws IOException {
        String filename;
        boolean fileCheck;

        // Check for command line argument
        if (args.length > 0) {
            filename = args[0];
            // normalize filename
            filename = checkFilename(filename);

            // check input file type, restricts file input to .txt files only
            fileCheck = validateType(filename);

            if (fileCheck == false) {
                // incorrect file type - display generic error message
                System.err.println("Invalid file");
                System.exit(0);
            } else { // file type accepted
                // create BufferedReader object and digest file line-by-line
                BufferedReader inputStream = null;
                String fileLine;
                String sanLine;
                try {
                    inputStream = new BufferedReader(new FileReader(filename));
                    System.out.println("Email Addresses:");
                    // read document line-by-line using BufferedReader
                    while ((fileLine = inputStream.readLine()) != null) {
                        // sanitize output prior to display
                        sanLine = validateOutput(fileLine);
                        System.out.println(sanLine);
                    }
                } catch (IOException io) {
                    System.err.println("File error");
                } finally {
                    // close the streams
                    try {
                        if (inputStream != null) {
                            inputStream.close();
                        }
                    } catch (IOException io) {
                        System.err.println("File error");
                    }
                }
            }
        } else {
            System.err.println("No argument provided.");
            System.exit(0);
        }
    }
}
