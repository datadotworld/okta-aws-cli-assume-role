package com.okta.tools;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

@Value
@Builder
public class ConfigParser {

    private static final Logger LOGGER = LogManager.getLogger(ConfigParser.class);

    @NonNull
    private String oktaOrg;
    @NonNull
    private String oktaUsername;
    @NonNull
    private String oktaAWSAppURL;
    @NonNull
    private String awsIamKey;
    @NonNull
    private String awsIamSecret;
    private String awsRegion;

    public static String HOME_DIR_FILE = System.getProperty("user.home") + System.getProperty("file.separator") + ".okta/aws-config.properties";
    public static String WORK_DIR_FILE = System.getProperty("user.dir") + System.getProperty("file.separator") + "config.properties";

    static ConfigParser getConfig() throws IOException {
        FileReader reader = null;

        if (new File(WORK_DIR_FILE).exists()) {
            LOGGER.info("Using configuration file from: " + WORK_DIR_FILE);
            reader = new FileReader(new File(WORK_DIR_FILE));
        } else if (new File(HOME_DIR_FILE).exists()) {
            LOGGER.info("Using configuration file from: " + HOME_DIR_FILE);
            reader = new FileReader(new File(HOME_DIR_FILE));
        } else {
            throw new FileNotFoundException("Neither " + HOME_DIR_FILE + " or " + WORK_DIR_FILE + " configuration files found");
        }

        Properties props = new Properties();
        props.load(reader);

        return ConfigParser.builder()
                .oktaOrg(props.getProperty("OKTA_ORG"))
                .oktaUsername(props.getProperty("OKTA_USERNAME"))
                .oktaAWSAppURL(props.getProperty("OKTA_AWS_APP_URL"))
                .awsIamKey(props.getProperty("AWS_IAM_KEY"))
                .awsIamSecret(props.getProperty("AWS_IAM_SECRET"))
                .awsRegion(props.getProperty("AWS_DEFAULT_REGION", "us-east-1"))
                .build();
    }

}
