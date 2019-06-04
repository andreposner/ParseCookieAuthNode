/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package org.forgerock.auth.mobileid;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;

import org.apache.commons.lang.StringUtils;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.joda.time.DateTime;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;

import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/** 
 * A node that checks to see if zero-page login headers have specified username and shared key 
 * for this request.
 *
 * @author andre.posner
 * @version 1.0.0
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = ParseCookieAuthNode.Config.class)
public class ParseCookieAuthNode extends SingleOutcomeNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "ParseCookieAuthNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    // shouldd be moved to configuration:
    private String sharedSecret = "ThisIsaSharedSecret";
    private String salt = "ThisIsaSalt";

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String cookieName() {
            return "EDATA";
        }

        @Attribute(order = 200)
        default String delimiter() {
            return "|";
        }

        @Attribute(order = 300)
        default Boolean  cookieEncrypted() {
            return false;
        }
    }


    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ParseCookieAuthNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    public void debugmessage(String s) {
        System.out.println(s);
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {


        debugmessage("[" + DEBUG_FILE + "]: parseCookieNode started ...");
        debugmessage("[" + DEBUG_FILE + "]: Configuration: cookie name: '" + config.cookieName() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Configuration: delimiter : '" + config.delimiter() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Configuration: cookie encrypted: '" + config.cookieEncrypted().toString() + "'.");

        String sCookies = context.request.cookies.toString();
        String[] cookie = sCookies.split(",");
        for (String a : cookie) {
            boolean match = a.contains(config.cookieName());
            if (match) {
                String[] parts = a.split("=");
                String cName = parts[0].replace("{", "");
                String rawValue = parts[1].replace("}", "");
                String decodedValue ;
                if (config.cookieEncrypted()) {
                    debugmessage("[" + DEBUG_FILE + "]: Found cookie '" + cName + "' with value '" + rawValue + "'; decrypting cookie value ...");
                    decodedValue = decrypt(rawValue, sharedSecret, salt);
                    debugmessage("[" + DEBUG_FILE + "]: Cookie decryptec and decoded resulting value is '" + decodedValue +  "'; splitting it ...");
                }
                else
                {
                    debugmessage("[" + DEBUG_FILE + "]: Found cookie '" + cName + "' with value '" + rawValue + "'; decoding cookie value ...");
                    byte[] decodedBytes = Base64.getDecoder().decode(rawValue);
                    decodedValue = new String(decodedBytes);
                    debugmessage("[" + DEBUG_FILE + "]: Cookie decoded resulting value is '" + decodedValue +  "'; splitting it ...");
                }

                String[] ssvalues = decodedValue.split("\\|");
                for (int i=0; i<ssvalues.length; i++) {
                    // very, very dirty
                    switch ( i ) {
                        case 0:
                            String key0 = "eidPseudonym";
                            // It is possible that the restrictedId/eidPseudonym contains characters which are not allowed as AM Username
                            if (StringUtils.containsAny(ssvalues[i], "\\/+;,%[]|?"))
                            {
                            	debugmessage("[" + DEBUG_FILE + "]: eidPseudonym contains a special character '\\,/,+,;,,,%,[,],|,?'. Replace everyone with a '-'");
                            	String decodedid =  ssvalues[i].replaceAll("\\\\|;|\\;|/|\\+|,|%|\\]|\\[|\\?|\\|", "-");
	                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key0 + "' with value '" + decodedid + "' ( index was '" + i + "') to shared state.");
                            	context.sharedState.put(key0, decodedid);
                            } else
                            {
	                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key0 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
	                            context.sharedState.put(key0, ssvalues[i]);
                            }
                            break;
                        case 1:
                            String key1 = "eidGivenname";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key1 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key1, ssvalues[i]);
                            break;
                        case 2:
                            String key2 = "eidLastname";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key2 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key2, ssvalues[i]);
                            break;
                        case 3:
                            String key3 = "eidCity";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key3 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key3, ssvalues[i]);
                            break;
                        case 4:
                            String key4 = "eidStreet";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key4 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key4, ssvalues[i]);
                            break;
                        case 5:
                            String key5 = "eidZip";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key5 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key5, ssvalues[i]);
                            break;
                        case 6:
                            String key6 = "eidBirthdate";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key6 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key6, ssvalues[i]);
                            break;
                        case 7:
                        	String key7 = "eidCountry";
                            debugmessage("[" + DEBUG_FILE + "]: Adding key '" + key7 + "' with value '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");
                            context.sharedState.put(key7, ssvalues[i]);
                            break;
                        default:
                            debugmessage("[" + DEBUG_FILE + "]: No case defined for '" + ssvalues[i] + "' ( index was '" + i + "') to shared state.");

                            
                        	
                    }
                }

            }
        }
        return goToNext().build();
    }

    public static String decrypt(String strToDecrypt, String secret, String salt) {
        try
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

}