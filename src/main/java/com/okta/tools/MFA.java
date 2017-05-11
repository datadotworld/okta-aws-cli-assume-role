package com.okta.tools;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Scanner;

class MFA {
    static String mfa(JSONObject authResponse) {

        try {
            //User selects which factor to use
            JSONObject factor = selectFactor(authResponse);
            String factorType = factor.getString("factorType");
            String stateToken = authResponse.getString("stateToken");

            //factor selection handler
            switch (factorType) {
                case ("question"): {
                    //question factor handler
                    String sessionToken = questionFactor(factor, stateToken);
                    if (sessionToken.equals("change factor")) {
                        System.out.println("Factor Change Initiated");
                        return mfa(authResponse);
                    }
                    return sessionToken;
                }
                case ("sms"): {
                    //sms factor handler
                    String sessionToken = smsFactor(factor, stateToken);
                    if (sessionToken.equals("change factor")) {
                        System.out.println("Factor Change Initiated");
                        return mfa(authResponse);
                    }
                    return sessionToken;

                }
                case ("token:software:totp"): {
                    //token factor handler
                    String sessionToken = totpFactor(factor, stateToken);
                    if (sessionToken.equals("change factor")) {
                        System.out.println("Factor Change Initiated");
                        return mfa(authResponse);
                    }
                    return sessionToken;
                }
                case ("push"): {
                    //push factor handles
                    String result = pushFactor(factor, stateToken);
                    if (result.equals("timeout") || result.equals("change factor")) {
                        return mfa(authResponse);
                    }
                    return result;
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (ClientProtocolException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return "";
    }

    /*Handles factor selection based on factors found in parameter authResponse, returns the selected factor
* Precondition: JSINObject authResponse
* Postcondition: return session token as String sessionToken
*/
    public static JSONObject selectFactor(JSONObject authResponse) throws JSONException {
        JSONArray factors = authResponse.getJSONObject("_embedded").getJSONArray("factors");
        JSONObject factor;
        String factorType;
        System.out.println("\nMulti-Factor authentication is required. Please select a factor to use.");
        //list factor to select from to user
        System.out.println("Factors:");
        for (int i = 0; i < factors.length(); i++) {
            factor = factors.getJSONObject(i);
            factorType = factor.getString("factorType");
            if (factorType.equals("question")) {
                factorType = "Security Question";
            } else if (factorType.equals("sms")) {
                factorType = "SMS Authentication";
            } else if (factorType.equals("token:software:totp")) {
                String provider = factor.getString("provider");
                if (provider.equals("GOOGLE")) {
                    factorType = "Google Authenticator";
                } else {
                    factorType = "Okta Verify";
                }
            }
            System.out.println("[ " + (i + 1) + " ] : " + factorType);
        }

        //Handles user factor selection
        int selection = numSelection(factors.length());
        return factors.getJSONObject(selection);
    }


    private static String questionFactor(JSONObject factor, String stateToken) throws JSONException, ClientProtocolException, IOException {
        String question = factor.getJSONObject("profile").getString("questionText");
        Scanner scanner = new Scanner(System.in);
        String sessionToken = "";
        String answer = "";

        //prompt user for answer
        System.out.println("\nSecurity Question Factor Authentication\nEnter 'change factor' to use a different factor\n");
        while (sessionToken == "") {
            if (answer != "") {
                System.out.println("Incorrect answer, please try again");
            }
            System.out.println(question);
            System.out.println("Answer: ");
            answer = scanner.nextLine();
            //verify answer is correct
            if (answer.toLowerCase().equals("change factor")) {
                return answer;
            }
            sessionToken = verifyAnswer(answer, factor, stateToken, "question");
        }
        return sessionToken;
    }


    /*Handles sms factor authentication
     * Precondition: question factor as JSONObject factor, current state token stateToken
     * Postcondition: return session token as String sessionToken
     */
    private static String smsFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException {
        Scanner scanner = new Scanner(System.in);
        String answer = "";
        String sessionToken = "";

        //prompt for sms verification
        System.out.println("\nSMS Factor Authentication \nEnter 'change factor' to use a different factor");
        while (sessionToken == "") {
            if (answer != "") {
                System.out.println("Incorrect passcode, please try again or type 'new code' to be sent a new sms token");
            } else {
                //send initial code to user
                sessionToken = verifyAnswer("", factor, stateToken, "sms");
            }
            System.out.println("SMS Code: ");
            answer = scanner.nextLine();
            //resends code
            if (answer.equals("new code")) {
                answer = "";
                System.out.println("New code sent! \n");
            } else if (answer.toLowerCase().equals("change factor")) {
                return answer;
            }
            //verifies code
            sessionToken = verifyAnswer(answer, factor, stateToken, "sms");
        }
        return sessionToken;
    }


    /*Handles token factor authentication, i.e: Google Authenticator or Okta Verify
     * Precondition: question factor as JSONObject factor, current state token stateToken
     * Postcondition: return session token as String sessionToken
     */
    private static String totpFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException {
        Scanner scanner = new Scanner(System.in);
        String sessionToken = "";
        String answer = "";

        //prompt for token
        System.out.println("\n" + factor.getString("provider") + " Token Factor Authentication\nEnter 'change factor' to use a different factor");
        while (sessionToken == "") {
            if (answer != "") {
                System.out.println("Invalid token, please try again");
            }

            System.out.println("Token: ");
            answer = scanner.nextLine();
            //verify auth Token
            if (answer.toLowerCase().equals("change factor")) {
                return answer;
            }
            sessionToken = verifyAnswer(answer, factor, stateToken, "token:software:totp");
        }
        return sessionToken;
    }


    /*Handles push factor authentication
     *
     *
     */
    private static String pushFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException {
        Calendar newTime = null;
        Calendar time = Calendar.getInstance();
        String sessionToken = "";

        System.out.println("\nPush Factor Authentication");
        while (sessionToken == "") {
            //System.out.println("Token: ");
            //prints waiting tick marks
            //if( time.compareTo(newTime) > 4000){
            //    System.out.println("...");
            //}
            //Verify if Okta Push has been pushed
            sessionToken = verifyAnswer(null, factor, stateToken, "push");
            System.out.println(sessionToken);
            if (sessionToken.equals("Timeout")) {
                System.out.println("Session has timed out");
                return "timeout";
            }
            time = newTime;
            newTime = Calendar.getInstance();
        }
        return sessionToken;
    }


    /*Handles verification for all Factor types
     * Precondition: question factor as JSONObject factor, current state token stateToken
     * Postcondition: return session token as String sessionToken
     */
    private static String verifyAnswer(String answer, JSONObject factor, String stateToken, String factorType)
            throws JSONException, ClientProtocolException, IOException {

        String sessionToken = null;

        JSONObject profile = new JSONObject();
        String verifyPoint = factor.getJSONObject("_links").getJSONObject("verify").getString("href");

        profile.put("stateToken", stateToken);

        JSONObject jsonObjResponse = null;

        //if (factorType.equals("question")) {

        if (answer != null && answer != "") {
            profile.put("answer", answer);
        }

        //create post request
        CloseableHttpResponse responseAuthenticate = null;
        CloseableHttpClient httpClient = HttpClients.createDefault();

        HttpPost httpost = new HttpPost(verifyPoint);
        httpost.addHeader("Accept", "application/json");
        httpost.addHeader("Content-Type", "application/json");
        httpost.addHeader("Cache-Control", "no-cache");

        StringEntity entity = new StringEntity(profile.toString(), StandardCharsets.UTF_8);
        entity.setContentType("application/json");
        httpost.setEntity(entity);
        responseAuthenticate = httpClient.execute(httpost);

        BufferedReader br = new BufferedReader(new InputStreamReader((responseAuthenticate.getEntity().getContent())));

        String outputAuthenticate = br.readLine();
        jsonObjResponse = new JSONObject(outputAuthenticate);

        if (jsonObjResponse.has("errorCode")) {
            String errorSummary = jsonObjResponse.getString("errorSummary");
            System.out.println(errorSummary);
            System.out.println("Please try again");
            if (factorType.equals("question")) {
                questionFactor(factor, stateToken);
            }

            if (factorType.equals("token:software:totp")) {
                totpFactor(factor, stateToken);
            }
        }
        //}

        if (jsonObjResponse != null && jsonObjResponse.has("sessionToken"))
            sessionToken = jsonObjResponse.getString("sessionToken");

        String pushResult = null;
        if (factorType.equals("push")) {
            if (jsonObjResponse.has("_links")) {
                JSONObject linksObj = jsonObjResponse.getJSONObject("_links");

                //JSONObject pollLink = links.getJSONObject("poll");
                JSONArray names = linksObj.names();
                JSONArray links = linksObj.toJSONArray(names);
                String pollUrl = "";
                for (int i = 0; i < links.length(); i++) {
                    JSONObject link = links.getJSONObject(i);
                    String linkName = link.getString("name");
                    if (linkName.equals("poll")) {
                        pollUrl = link.getString("href");
                        break;
                        //System.out.println("[ " + (i+1) + " ] :" + factorType );
                    }
                }


                while (pushResult == null || pushResult.equals("WAITING")) {
                    pushResult = null;
                    CloseableHttpResponse responsePush = null;
                    httpClient = HttpClients.createDefault();

                    HttpPost pollReq = new HttpPost(pollUrl);
                    pollReq.addHeader("Accept", "application/json");
                    pollReq.addHeader("Content-Type", "application/json");
                    pollReq.addHeader("Cache-Control", "no-cache");

                    entity = new StringEntity(profile.toString(), StandardCharsets.UTF_8);
                    entity.setContentType("application/json");
                    pollReq.setEntity(entity);

                    responsePush = httpClient.execute(pollReq);

                    br = new BufferedReader(new InputStreamReader((responsePush.getEntity().getContent())));

                    String outputTransaction = br.readLine();
                    JSONObject jsonTransaction = new JSONObject(outputTransaction);


                    if (jsonTransaction.has("factorResult")) {
                        pushResult = jsonTransaction.getString("factorResult");
                    }

                    if (pushResult == null && jsonTransaction.has("status")) {
                        pushResult = jsonTransaction.getString("status");
                    }

                    System.out.println("Waiting for you to approve the Okta push notification on your device...");
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException iex) {

                    }

                    //if(pushResult.equals("SUCCESS")) {
                    if (jsonTransaction.has("sessionToken")) {
                        sessionToken = jsonTransaction.getString("sessionToken");
                    }
                    //}
                    /*
                    if(pushResult.equals("TIMEOUT")) {
                        sessionToken = "timeout";
                    }
*/
                }
            }

        }


        if (sessionToken != null)
            return sessionToken;
        else
            return pushResult;
    }
}
