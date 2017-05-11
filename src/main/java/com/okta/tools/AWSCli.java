/*!
 * Copyright (c) 2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package com.okta.tools;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.profile.ProfilesConfigFile;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.AttachedPolicy;
import com.amazonaws.services.identitymanagement.model.GetPolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetPolicyResult;
import com.amazonaws.services.identitymanagement.model.GetPolicyVersionRequest;
import com.amazonaws.services.identitymanagement.model.GetPolicyVersionResult;
import com.amazonaws.services.identitymanagement.model.GetRolePolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetRolePolicyResult;
import com.amazonaws.services.identitymanagement.model.GetRoleRequest;
import com.amazonaws.services.identitymanagement.model.GetRoleResult;
import com.amazonaws.services.identitymanagement.model.ListAttachedRolePoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListAttachedRolePoliciesResult;
import com.amazonaws.services.identitymanagement.model.ListRolePoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListRolePoliciesResult;
import com.amazonaws.services.identitymanagement.model.Policy;
import com.amazonaws.services.identitymanagement.model.Role;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Scanner;

//Amazon SDK namespaces
//Okta SDK namespaces

public class AWSCli {

    //User specific variables
    private static String oktaOrg = "";
    private static String oktaUsername = "";
    private static String oktaAWSAppURL = "";
    private static String awsIamKey = null;
    private static String awsIamSecret = null;
    private static String awsRegion;

    private static final String DefaultProfileName = "default";

    private static String crossAccountRoleName = null;
    private static String roleToAssume; //the ARN of the role the user wants to eventually assume (not the cross-account role, the "real" role in the target account)
    private static int selectedPolicyRank; //the zero-based rank of the policy selected in the selected cross-account role (in case there is more than one policy tied to the current policy)
    private static final Logger logger = LogManager.getLogger(AWSCli.class);

    public static void main(String[] args) throws Exception {
        awsSetup();
        extractCredentials();

        // Step #1: Initiate the authentication and capture the SAML assertion.
        String resultSAML = "";
        try {

            String strOktaSessionToken = oktaAuthntication();
            // TODO - Optionally cache okta session
            if (!strOktaSessionToken.equalsIgnoreCase(""))
                //Step #2 get SAML assertion from Okta
                resultSAML = awsSamlHandler(strOktaSessionToken);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            logger.error("\nUnable to establish a connection with AWS. \nPlease verify that your OKTA_AWS_APP_URL parameter is correct and try again");
            System.exit(0);
        } catch (ClientProtocolException e) {
            logger.error("\nNo Org found, please specify an OKTA_ORG parameter in your config.properties file");
            System.exit(0);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Step #3: Assume an AWS role using the SAML Assertion from Okta
        AssumeRoleWithSAMLResult assumeResult = assumeAWSRole(resultSAML);

        com.amazonaws.services.securitytoken.model.AssumedRoleUser aru = assumeResult.getAssumedRoleUser();
        String arn = aru.getArn();


        // Step #4: Get the final role to assume and update the config file to add it to the user's profile
        getRoleToAssume(crossAccountRoleName);
        logger.trace("Role to assume ARN: " + roleToAssume);

        // Step #5: Write the credentials to ~/.aws/credentials
        String profileName = setAWSCredentials(assumeResult, arn);

        updateConfigFile(profileName, roleToAssume);
        updateConfigFile(DefaultProfileName, roleToAssume);

        // Print Final message
        resultMessage(profileName);
    }

    /* Authenticates users credentials via Okta, return Okta session token
     * Postcondition: returns String oktaSessionToken
     * */
    private static String oktaAuthntication() throws JSONException, IOException {
        CloseableHttpResponse responseAuthenticate = null;
        int requestStatus = 0;

        //Redo sequence if response from AWS doesn't return 200 Status
        while (requestStatus != 200) {

            // Prompt for user credentials
            Scanner scanner = new Scanner(System.in);

            Console console = System.console();
            String oktaPassword;
            if (console != null) {
                oktaPassword = new String(console.readPassword("Password: "));
            } else { // hack to be able to debug in an IDE
                System.out.print("Password: ");
                oktaPassword = scanner.next();
            }

            responseAuthenticate = authnticateCredentials(oktaUsername, oktaPassword);
            requestStatus = responseAuthenticate.getStatusLine().getStatusCode();
            authnFailHandler(requestStatus, responseAuthenticate);
        }

        //Retrieve and parse the Okta response for session token
        BufferedReader br = new BufferedReader(new InputStreamReader(
                (responseAuthenticate.getEntity().getContent())));

        String outputAuthenticate = br.readLine();
        JSONObject jsonObjResponse = new JSONObject(outputAuthenticate);

        responseAuthenticate.close();

        if (jsonObjResponse.getString("status").equals("MFA_REQUIRED")) {
            return MFA.mfa(jsonObjResponse);
        } else {
            return jsonObjResponse.getString("sessionToken");
        }
    }

    /*Uses user's credentials to obtain Okta session Token */
    private static CloseableHttpResponse authnticateCredentials(String username, String password) throws JSONException, IOException {
        HttpPost httpost;
        CloseableHttpClient httpClient = HttpClients.createDefault();


        //HTTP Post request to Okta API for session token
        httpost = new HttpPost("https://" + oktaOrg + "/api/v1/authn");
        httpost.addHeader("Accept", "application/json");
        httpost.addHeader("Content-Type", "application/json");
        httpost.addHeader("Cache-Control", "no-cache");

        //construction of request JSON
        JSONObject jsonObjRequest = new JSONObject();
        jsonObjRequest.put("username", username);
        jsonObjRequest.put("password", password);

        StringEntity entity = new StringEntity(jsonObjRequest.toString(), StandardCharsets.UTF_8);
        entity.setContentType("application/json");
        httpost.setEntity(entity);

        return httpClient.execute(httpost);
    }

    /* creates required AWS credential file if necessary" */
    private static void awsSetup() throws FileNotFoundException, UnsupportedEncodingException {
        //check if credentials file has been created
        File f = new File(System.getProperty("user.home") + "/.aws/credentials");
        //creates credentials file if it doesn't exist yet
        if (!f.exists()) {
            //noinspection ResultOfMethodCallIgnored
            f.getParentFile().mkdirs();

            PrintWriter writer = new PrintWriter(f, "UTF-8");
            writer.println("[default]");
            writer.println("aws_access_key_id=");
            writer.println("aws_secret_access_key=");
            writer.close();
        }

        f = new File(System.getProperty("user.home") + "/.aws/config");
        //creates credentials file if it doesn't exist yet
        if (!f.exists()) {
            //noinspection ResultOfMethodCallIgnored
            f.getParentFile().mkdirs();

            PrintWriter writer = new PrintWriter(f, "UTF-8");
            writer.println("[profile default]");
            writer.println("output = json");
            writer.println("region = " + awsRegion);
            writer.close();
        }
    }

    /* Parses application's config file for app URL and Okta Org */
    private static void extractCredentials() throws IOException {
        ConfigParser config = ConfigParser.getConfig();
        oktaOrg = config.getOktaOrg();
        oktaUsername = config.getOktaUsername();
        oktaAWSAppURL = config.getOktaAWSAppURL();
        awsIamKey = config.getAwsIamKey();
        awsIamSecret = config.getAwsIamSecret();
        awsRegion = config.getAwsRegion();
    }

    /*Handles possible authentication failures */
    private static void authnFailHandler(int requestStatus, CloseableHttpResponse response) {
        //invalid creds
        if (requestStatus == 400 || requestStatus == 401) {
            logger.error("You provided invalid credentials, please run this program again.");
        } else if (requestStatus == 500) {
            //failed connection establishment
            logger.error("\nUnable to establish connection with: " +
                    oktaOrg + " \nPlease verify that your Okta org url is correct and try again");
            System.exit(0);
        } else if (requestStatus != 200) {
            //other
            throw new RuntimeException("Failed : HTTP error code : "
                    + response.getStatusLine().getStatusCode());
        }
    }

    /*Handles possible AWS assertion retrieval errors */
    private static void samlFailHandler(CloseableHttpResponse responseSAML) throws UnknownHostException {
        if (responseSAML.getStatusLine().getStatusCode() == 500) {
            //incorrectly formatted app url
            throw new UnknownHostException();
        } else if (responseSAML.getStatusLine().getStatusCode() != 200) {
            //other
            throw new RuntimeException("Failed : HTTP error code : "
                    + responseSAML.getStatusLine().getStatusCode());
        }
    }

    /* Handles user selection prompts */
    static int numSelection(int max) {
        Scanner scanner = new Scanner(System.in);

        int selection = -1;
        while (selection == -1) {
            //prompt user for selection
            System.out.print("Selection: ");
            String selectInput = scanner.nextLine();
            try {
                selection = Integer.parseInt(selectInput) - 1;
                if (selection >= max) {
                    throw new InputMismatchException();
                }
            } catch (InputMismatchException e) {
                //raised by something other than a number entered
                logger.error("Invalid input: Please enter a number corresponding to a role \n");
                selection = -1;
            } catch (NumberFormatException e) {
                //raised by number too high or low selected
                logger.error("Invalid input: Please enter in a number \n");
                selection = -1;
            }
        }
        return selection;
    }

    /* Retrieves SAML assertion from Okta containing AWS roles */
    private static String awsSamlHandler(String oktaSessionToken) throws IOException {
        HttpGet httpget;
        CloseableHttpResponse responseSAML;
        CloseableHttpClient httpClient = HttpClients.createDefault();
        String resultSAML = "";
        String outputSAML;

        // Part 2: Get the Identity Provider and Role ARNs.
        // Request for AWS SAML response containing roles
        httpget = new HttpGet(oktaAWSAppURL + "?onetimetoken=" + oktaSessionToken);
        responseSAML = httpClient.execute(httpget);
        samlFailHandler(responseSAML);

        //Parse SAML response
        BufferedReader brSAML = new BufferedReader(new InputStreamReader(
                (responseSAML.getEntity().getContent())));
        //responseSAML.close();

        while ((outputSAML = brSAML.readLine()) != null) {
            if (outputSAML.contains("SAMLResponse")) {
                resultSAML = outputSAML.substring(outputSAML.indexOf("value=") + 7, outputSAML.indexOf("/>") - 1);
                break;
            }
        }
        httpClient.close();
        return resultSAML;
    }


    /* Assumes SAML role selected by the user based on authorized Okta AWS roles given in SAML assertion result SAML
     * Precondition: String resultSAML
     * Postcondition: returns type AssumeRoleWithSAMLResult
     */
    private static AssumeRoleWithSAMLResult assumeAWSRole(String resultSAML) {
        // Decode SAML response
        resultSAML = resultSAML.replace("&#x2b;", "+").replace("&#x3d;", "=");
        String resultSAMLDecoded = new String(Base64.decodeBase64(resultSAML));

        ArrayList<String> principalArns = new ArrayList<>();
        ArrayList<String> roleArns = new ArrayList<>();

        //When the app is not assigned to you no assertion is returned
        if (!resultSAMLDecoded.contains("arn:aws")) {
            logger.error("\nYou do not have access to AWS through Okta. \nPlease contact your administrator.");
            System.exit(0);
        }

        System.out.println("\nPlease choose the role you would like to assume: ");

        //Gather list of applicable AWS roles
        int i = 0;
        while (resultSAMLDecoded.contains("arn:aws")) {
            /*Trying to parse the value of the Role SAML Assertion that typically looks like this:
            <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
            arn:aws:iam::[AWS-ACCOUNT-ID]:saml-provider/Okta,arn:aws:iam::[AWS-ACCOUNT-ID]:role/[ROLE_NAME]
            </saml2:AttributeValue>
      </saml2:Attribute>
            */
            int start = resultSAMLDecoded.indexOf("arn:aws");
            int end = resultSAMLDecoded.indexOf("</saml2:", start);
            String resultSAMLRole = resultSAMLDecoded.substring(start, end);
            String[] parts = resultSAMLRole.split(",");
            principalArns.add(parts[0]);
            roleArns.add(parts[1]);
            System.out.println("[ " + (i + 1) + " ]: " + roleArns.get(i));
            resultSAMLDecoded = (resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("</saml2:AttributeValue") + 1));
            i++;
        }

        //Prompt user for role selection
        int selection = numSelection(roleArns.size());

        String principalArn = principalArns.get(selection);
        String roleArn = roleArns.get(selection);
        crossAccountRoleName = roleArn.substring(roleArn.indexOf("/") + 1);
        logger.debug("Cross-account role is " + crossAccountRoleName);


        //creates empty AWS credentials to prevent the AWSSecurityTokenServiceClient object from unintentionally loading the previous profile we just created
        BasicAWSCredentials awsCreds = new BasicAWSCredentials("", "");

        //use user credentials to assume AWS role
        AWSSecurityTokenServiceClient stsClient = new AWSSecurityTokenServiceClient(awsCreds);

        AssumeRoleWithSAMLRequest assumeRequest = new AssumeRoleWithSAMLRequest()
                .withPrincipalArn(principalArn)
                .withRoleArn(roleArn)
                .withSAMLAssertion(resultSAML)
                .withDurationSeconds(3600); //default token duration to 12 hours

        return stsClient.assumeRoleWithSAML(assumeRequest);
    }

    private static void getRoleToAssume(String roleName) {

        if (roleName != null && !roleName.equals("") && awsIamKey != null && awsIamSecret != null && !awsIamKey.equals("") && !awsIamSecret.equals("")) {

            logger.debug("Creating the AWS Identity Management client");
            AmazonIdentityManagementClient identityManagementClient
                    = new AmazonIdentityManagementClient(new BasicAWSCredentials(awsIamKey, awsIamSecret));

            logger.debug("Getting role: " + roleName);
            GetRoleResult roleresult = identityManagementClient.getRole(new GetRoleRequest().withRoleName(roleName));
            logger.debug("GetRoleResult: " + roleresult.toString());
            Role role = roleresult.getRole();
            logger.debug("getRole: " + role.toString());
            ListAttachedRolePoliciesResult arpr = identityManagementClient.listAttachedRolePolicies(new ListAttachedRolePoliciesRequest().withRoleName(roleName));
            logger.debug("ListAttachedRolePoliciesResult: " + arpr.toString());
            ListRolePoliciesResult lrpr = identityManagementClient.listRolePolicies(new ListRolePoliciesRequest().withRoleName(roleName));
            logger.debug("ListRolePoliciesResult: " + lrpr.toString());

            List<String> inlinePolicies = lrpr.getPolicyNames();
            if (inlinePolicies.size() == 0) {
                logger.debug("There are no inlines policies");
            }
            List<AttachedPolicy> managedPolicies = arpr.getAttachedPolicies();
            if (managedPolicies.size() == 0) {
                logger.debug("There are no managed policies");
            }

            selectedPolicyRank = 0; //by default, we select the first policy

            if (managedPolicies.size() >= 1) //we prioritize managed policies over inline policies
            {
                if (managedPolicies.size() > 1) //if there's more than one policy, we're asking the user to select one of them
                {
                    List<String> lstManagedPolicies = new ArrayList<>();

                    for (AttachedPolicy managedPolicy : managedPolicies) {
                        lstManagedPolicies.add(managedPolicy.getPolicyName());
                    }

                    logger.debug("Managed Policies: " + managedPolicies.toString());

                    selectedPolicyRank = selectPolicy(lstManagedPolicies);
                }

                AttachedPolicy attachedPolicy = managedPolicies.get(selectedPolicyRank);
                logger.debug("Selected policy " + attachedPolicy.toString());
                GetPolicyRequest gpr = new GetPolicyRequest().withPolicyArn(attachedPolicy.getPolicyArn());

                GetPolicyResult rpr = identityManagementClient.getPolicy(gpr);
                logger.debug("GetPolicyResult: " + attachedPolicy.toString());
                Policy policy = rpr.getPolicy();

                GetPolicyVersionResult pvr = identityManagementClient.getPolicyVersion(new GetPolicyVersionRequest().withPolicyArn(policy.getArn()).withVersionId(policy.getDefaultVersionId()));
                logger.debug("GetPolicyVersionResult: " + pvr.toString());

                String policyDoc = pvr.getPolicyVersion().getDocument();

                roleToAssume = processPolicyDocument(policyDoc);
            } else if (inlinePolicies.size() >= 1) //processing inline policies if we have no managed policies
            {
                logger.debug("Inline Policies " + inlinePolicies.toString());

                if (inlinePolicies.size() > 1) {
                    //ask the user to select one policy if there are more than one

                    logger.debug("Inline Policies: " + inlinePolicies.toString());

                    selectedPolicyRank = selectPolicy(inlinePolicies);
                }

                //Have to set the role name and the policy name (both are mandatory fields
                //TODO: handle more than 1 policy (ask the user to choose it?)
                GetRolePolicyRequest grpr = new GetRolePolicyRequest().withRoleName(roleName).withPolicyName(inlinePolicies.get(selectedPolicyRank));
                GetRolePolicyResult rpr = identityManagementClient.getRolePolicy(grpr);
                String policyDoc = rpr.getPolicyDocument();

                roleToAssume = processPolicyDocument(policyDoc);
            }
        }
    }

    private static int selectPolicy(List<String> lstPolicies) {

        System.out.println("\nPlease select a role policy: ");

        //Gather list of policies for the selected role
        int i = 1;
        for (String strPolicyName : lstPolicies) {
            System.out.println("[ " + i + " ]: " + strPolicyName);
            i++;
        }

        //Prompt user for policy selection
        return numSelection(lstPolicies.size());
    }

    private static String processPolicyDocument(String policyDoc) {

        String strRoleToAssume = null;
        try {
            String policyDocClean = URLDecoder.decode(policyDoc, "UTF-8");
            logger.debug("Clean Policy Document: " + policyDocClean);
            ObjectMapper objectMapper = new ObjectMapper();

            try {
                JsonNode rootNode = objectMapper.readTree(policyDocClean);
                JsonNode statement = rootNode.path("Statement");
                logger.debug("Statement node: " + statement.toString());
                JsonNode resource = null;
                if (statement.isArray()) {
                    logger.debug("Statement is array");
                    for (int i = 0; i < statement.size(); i++) {
                        String action = statement.get(i).path("Action").textValue();
                        if (action != null && action.equals("sts:AssumeRole")) {
                            resource = statement.get(i).path("Resource");
                            logger.debug("Resource node: " + resource.toString());
                            break;
                        }
                    }
                } else {
                    logger.debug("Statement is NOT array");
                    if (statement.get("Action").textValue().equals("sts:AssumeRole")) {
                        resource = statement.path("Resource");
                        logger.debug("Resource node: " + resource.toString());
                    }
                }
                if (resource != null) {
                    if (resource.isArray()) { //if we're handling a policy with an array of AssumeRole attributes
                        ArrayList<String> lstRoles = new ArrayList<>();
                        for (final JsonNode node : resource) {
                            lstRoles.add(node.asText());
                        }
                        strRoleToAssume = selectRole(lstRoles);
                    } else {
                        strRoleToAssume = resource.textValue();
                        logger.debug("Role to assume: " + roleToAssume);
                    }
                }
            } catch (IOException ignored) {
            }
        } catch (UnsupportedEncodingException ignored) {

        }
        return strRoleToAssume;
    }

    /* Prompts the user to select a role in case the role policy contains an array of roles instead of a single role
    */
    private static String selectRole(List<String> lstRoles) {
        String strSelectedRole;

        System.out.println("\nPlease select the role you want to assume: ");

        //Gather list of roles for the selected managed policy
        int i = 1;
        for (String strRoleName : lstRoles) {
            System.out.println("[ " + i + " ]: " + strRoleName);
            i++;
        }

        //Prompt user for policy selection
        int selection = numSelection(lstRoles.size());

        if (selection < 0 && lstRoles.size() > selection) {
            System.out.println("\nYou entered an invalid number. Please try again.");
            return selectRole(lstRoles);
        }

        strSelectedRole = lstRoles.get(selection);

        return strSelectedRole;
    }

    /* Retrieves AWS credentials from AWS's assumedRoleResult and write the to aws credential file
     * Precondition :  AssumeRoleWithSAMLResult assumeResult
     */
    private static String setAWSCredentials(AssumeRoleWithSAMLResult assumeResult, String credentialsProfileName) throws IOException {
        BasicSessionCredentials temporaryCredentials =
                new BasicSessionCredentials(
                        assumeResult.getCredentials().getAccessKeyId(),
                        assumeResult.getCredentials().getSecretAccessKey(),
                        assumeResult.getCredentials().getSessionToken());

        String awsAccessKey = temporaryCredentials.getAWSAccessKeyId();
        String awsSecretKey = temporaryCredentials.getAWSSecretKey();
        String awsSessionToken = temporaryCredentials.getSessionToken();

        if (credentialsProfileName.startsWith("arn:aws:sts::")) {
            credentialsProfileName = credentialsProfileName.substring(13);
        }
        if (credentialsProfileName.contains(":assumed-role")) {
            credentialsProfileName = credentialsProfileName.replaceAll(":assumed-role", "");
        }

        Object[] args = {credentialsProfileName, selectedPolicyRank};
        MessageFormat profileNameFormat = new MessageFormat("{0}/{1}");
        credentialsProfileName = profileNameFormat.format(args);

        //update the credentials file with the unique profile name
        updateCredentialsFile(credentialsProfileName, awsAccessKey, awsSecretKey, awsSessionToken);
        //also override the default profile
        updateCredentialsFile(DefaultProfileName, awsAccessKey, awsSecretKey, awsSessionToken);

        return credentialsProfileName;
    }

    private static void updateCredentialsFile(String profileName, String awsAccessKey, String awsSecretKey, String awsSessionToken)
            throws IOException {

        ProfilesConfigFile profilesConfigFile = null;
        Object[] args = {profileName};
        MessageFormat profileNameFormatWithBrackets = new MessageFormat("[{0}]");
        String profileNameWithBrackets = profileNameFormatWithBrackets.format(args);

        try {
            profilesConfigFile = new ProfilesConfigFile();
        } catch (AmazonClientException ace) {
            populateCredentialsFile(profileNameWithBrackets, awsAccessKey, awsSecretKey, awsSessionToken);
        }

        try {
            if (profilesConfigFile != null && profilesConfigFile.getCredentials(profileName) != null) {
                //if we end up here, it means we were  able to find a matching profile
                populateCredentialsFile(profileNameWithBrackets, awsAccessKey, awsSecretKey, awsSessionToken);
            }
        } catch (AmazonClientException | IllegalArgumentException e) {
            //this could happen if the default profile doesn't have a valid AWS Access Key ID
            //in this case, error would be "Unable to load credentials into profile [default]: AWS Access Key ID is not specified."
            populateCredentialsFile(profileNameWithBrackets, awsAccessKey, awsSecretKey, awsSessionToken);
        }
    }

    private static void populateCredentialsFile(String profileNameLine, String awsAccessKey, String awsSecretKey, String awsSessionToken)
            throws IOException {

        File inFile = new File(System.getProperty("user.home") + "/.aws/credentials");
        FileInputStream fis = new FileInputStream(inFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        File tempFile = new File(inFile.getAbsolutePath() + ".tmp");
        PrintWriter pw = new PrintWriter(new FileWriter(tempFile));

        //first, we add our refreshed profile
        writeNewProfile(pw, profileNameLine, awsAccessKey, awsSecretKey, awsSessionToken);

        String line;
        int lineCounter = 0;

        //second, we're copying all the other profile from the original credentials file
        while ((line = br.readLine()) != null) {

            if (line.equalsIgnoreCase(profileNameLine) || (lineCounter > 0 && lineCounter < 4)) {
                //we found the line we must replace and we will skip 3 additional lines
                ++lineCounter;
            } else {
                if ((!line.equalsIgnoreCase("") && !line.equalsIgnoreCase("\n"))) {
                    if (line.startsWith("[")) {
                        //this is the start of a new profile, so we're adding a separator line
                        pw.println();
                    }
                    pw.println(line);
                }
            }
        }

        pw.flush();
        pw.close();
        br.close();

        //delete the original credentials file
        if (!inFile.delete()) {
            System.out.println("Could not delete original credentials file");
        }

        // Rename the new file to the filename the original file had.
        if (!tempFile.renameTo(inFile)) {
            System.out.println("Could not rename file");
        }
    }

    private static void updateConfigFile(String profileName, String roleToAssume) throws IOException {

        File inFile = new File(System.getProperty("user.home") + "/.aws/config");

        FileInputStream fis = new FileInputStream(inFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        File tempFile = new File(inFile.getAbsolutePath() + ".tmp");
        PrintWriter pw = new PrintWriter(new FileWriter(tempFile));

        //first, we add our refreshed profile
        writeNewRoleToAssume(pw, profileName, roleToAssume);

        String line;

        //second, we're copying all the other profiles from the original config file
        while ((line = br.readLine()) != null) {

            if (line.contains(profileName)) {
                //we found the section we must replace but we don't necessarily know how many lines we need to skip
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("[")) {
                        pw.println(line); //this is a new profile line, so we're copying it
                        break;
                    }
                }
            } else {
                if ((!line.contains(profileName) && !line.equalsIgnoreCase("\n"))) {
                    pw.println(line);
                    logger.debug(line);
                }
            }


        }

        pw.flush();
        pw.close();
        br.close();

        //delete the original credentials file
        if (!inFile.delete()) {
            System.out.println("Could not delete original config file");
        } else {
            // Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile))
                System.out.println("Could not rename file");
        }
    }

    private static void writeNewProfile(PrintWriter pw, String profileNameLine, String awsAccessKey, String awsSecretKey, String awsSessionToken) {

        pw.println(profileNameLine);
        pw.println("aws_access_key_id=" + awsAccessKey);
        pw.println("aws_secret_access_key=" + awsSecretKey);
        pw.println("aws_session_token=" + awsSessionToken);
        //pw.println();
        //pw.println();
    }

    private static void writeNewRoleToAssume(PrintWriter pw, String profileName, String roleToAssume) {

        pw.println("[profile " + profileName + "]");
        if (roleToAssume != null && !roleToAssume.equals(""))
            pw.println("role_arn=" + roleToAssume);
        pw.println("source_profile=" + profileName);
        pw.println("region=" + awsRegion);
    }

    /* prints final status message to user */
    private static void resultMessage(String profileName) {
        Calendar date = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat();
        date.add(Calendar.HOUR, 1);

        //change with file customization
        System.out.println("\n----------------------------------------------------------------------------------------------------------------------");
        System.out.println("Your new access key pair has been stored in the aws configuration file with the following profile name: " + profileName);
        System.out.println("The AWS Credentials file is located in " + System.getProperty("user.home") + "/.aws/credentials.");
        System.out.println("Note that it will expire at " + dateFormat.format(date.getTime()));
        System.out.println("After this time you may safely rerun this script to refresh your access key pair.");
        System.out.println("To use these credentials, please call the aws cli with the --profile option "
                + "(e.g. aws --profile " + profileName + " ec2 describe-instances)");
        System.out.println("You can also omit the --profile option to use the last configured profile "
                + "(e.g. aws s3 ls)");
        System.out.println("----------------------------------------------------------------------------------------------------------------------");
    }


}
