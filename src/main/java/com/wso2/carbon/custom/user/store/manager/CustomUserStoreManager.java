package com.wso2.carbon.custom.user.store.manager;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;
import org.wso2.carbon.user.core.UserStoreException;

import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomUserStoreManager extends ActiveDirectoryUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);

    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
            ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);

        log.info("CustomUserStoreManager initialized...");
    }

    public CustomUserStoreManager() {
    }

    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        log.debug("Custom update policy");

        validatePasswordLastUpdate(userName); // 24hr Password policy
        userAttributesCheck(userName, newCredential);
        customPasswordValidityChecks(newCredential, userName); // Custom Password Validation Policy
        super.doUpdateCredentialByAdmin(userName, newCredential);

    }

    @Override
    public void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
            String profileName, boolean requirePasswordChange) throws UserStoreException {
        customPasswordValidityChecks(credential, userName); // Custom Validation Rules.
        super.doAddUser(userName, credential, roleList, claims, profileName, requirePasswordChange);
    }

    @Override
    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        validatePasswordLastUpdate(userName); // 24hr Password change policy
        userAttributesCheck(userName, newCredential); //User Attribute Check
        customPasswordValidityChecks(newCredential, userName); // Custom validation rules
        super.doUpdateCredential(userName, newCredential, oldCredential);

    }

    @Override
    public Properties getDefaultUserStoreProperties() {

        Properties properties = super.getDefaultUserStoreProperties();
        Property[] optionalProperties = properties.getOptionalProperties();

        boolean foundPasswordSpecialWordsCheckProperty = false;
        boolean foundPasswordUserAttributesCheckProperty = false;
        boolean foundPasswordLengthCheckProperty = false;
        boolean foundPasswordUpperCaseJavaRegExProperty = false;
        boolean foundPasswordNumbersJavaRegExProperty = false;
        boolean foundPasswordLowerCaseJavaRegExProperty = false;
        boolean foundPasswordSpecialCharJavaRegExProperty = false;
        boolean foundPasswordLastUpdatedColumnNameProperty = false;
        boolean foundEnablePasswordValidationWithAvailableAttributesProperty = false;


        for (Property property : optionalProperties) {
            if (CustomUserStoreManagerConstants.AD_PASSWORD_SPECIAL_WORDS_CHECK.equals(property.getName())) {
                foundPasswordSpecialWordsCheckProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_USER_ATTRIBUTES_CHECK.equals((property.getName()))) {
                foundPasswordUserAttributesCheckProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_LENGTH_CHECK.equals(property.getName())) {
                foundPasswordLengthCheckProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_UPPERCASE_JAVA_REGEX.equals(property.getName())) {
                foundPasswordUpperCaseJavaRegExProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_NUMBERS_JAVA_REGEX.equals(property.getName())) {
                foundPasswordNumbersJavaRegExProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_LOWERCASE_JAVA_REGEX.equals(property.getName())) {
                foundPasswordLowerCaseJavaRegExProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_SPECIAL_CHAR_JAVA_REGEX.equals(property.getName())) {
                foundPasswordSpecialCharJavaRegExProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_PASSWORD_LAST_UPDATE_COLUMN_NAME.equals(property.getName())) {
                foundPasswordLastUpdatedColumnNameProperty = true;
            } else if (CustomUserStoreManagerConstants.AD_ENABLE_PASSWORD_VALIDATION_WITH_AVAILABLE_USER_ATTRIBUTES.
                    equals(property.getName())) {
                foundEnablePasswordValidationWithAvailableAttributesProperty = true;
            }
        }

        List<Property> optionalPropertyList = new ArrayList<>(Arrays.asList(optionalProperties));

        if (!foundPasswordSpecialWordsCheckProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_SPECIAL_WORDS_CHECK, "",
                    "To configure the special words the password should be validated against. " +
                            "Use a comma to define multiple words. Do not use white spaces in between.", null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordUserAttributesCheckProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_USER_ATTRIBUTES_CHECK, "",
                    "To configure the attributes of the user the password should be validated against. " +
                            "Use a comma to define multiple attributes. Do not use white spaces in between.", null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordLengthCheckProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_LENGTH_CHECK, "",
                    "Additional regex validation. Default value is empty. Do not change unless you know the use case." +
                    " To configure the password character length.", null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordUpperCaseJavaRegExProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_UPPERCASE_JAVA_REGEX,
                    "",
                    "Additional regex validation. Default value is empty. Do not change unless you know the use case.",
                    null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordNumbersJavaRegExProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_NUMBERS_JAVA_REGEX,
                    "",
                    "Additional regex validation. Default value is empty. Do not change unless you know the use case.",
                    null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordLowerCaseJavaRegExProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_LOWERCASE_JAVA_REGEX,
                    "",
                    "Additional regex validation. Default value is empty. Do not change unless you know the use case.",
                    null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordSpecialCharJavaRegExProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_SPECIAL_CHAR_JAVA_REGEX,
                    "",
                    "Additional regex validation. Default value is empty. Do not change unless you know the use case.",
                    null);
            optionalPropertyList.add(property);
        }
        if (!foundPasswordLastUpdatedColumnNameProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_PASSWORD_LAST_UPDATE_COLUMN_NAME,
                    "",
                    "To configure the password last update attribute.", null);
            optionalPropertyList.add(property);
        }
        if (!foundEnablePasswordValidationWithAvailableAttributesProperty) {
            Property property = new Property(CustomUserStoreManagerConstants.AD_ENABLE_PASSWORD_VALIDATION_WITH_AVAILABLE_USER_ATTRIBUTES,
                    "",
                    "To enable changing of password with available user attributes from the ones define in " +
                            "PasswordUserAttributesCheck property. Default value is false.", null);
            optionalPropertyList.add(property);
        }

        properties.setOptionalProperties(optionalPropertyList.toArray(new Property[optionalPropertyList.size()]));

        return properties;
    }

    private void customPasswordValidityChecks(Object credential, String userName) throws UserStoreException {

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        specialWordCheck(credentialObj);
        passwordCriteriaCheck(credentialObj);

    }

    private void validatePasswordLastUpdate(String userName) throws UserStoreException {

        String[] passwordLastUpdateAttribute = {
                this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_LAST_UPDATE_COLUMN_NAME) };
        if (ArrayUtils.isNotEmpty(passwordLastUpdateAttribute)) {
            Map<String, String> userProperties = getUserPropertyValues(userName, passwordLastUpdateAttribute, UserCoreConstants.DEFAULT_PROFILE);
            if (!userProperties.isEmpty()) {
                String lastChanged = userProperties.get(passwordLastUpdateAttribute[0]);
                long adTime = convertAdTime(lastChanged);
                Date changedTime = new Date(adTime);
                GregorianCalendar gc = new GregorianCalendar();
                gc.add(10, -24);
                Date date = gc.getTime();
                if (!changedTime.before((date))) {
                    log.debug("Can not change password twice within 24 hours.");
                    throw new UserStoreException("Can not change password twice within 24 hours.");
                }
            } else {
                log.warn("User properties for given column name is not found. Skipping Password Last update validation.");
            }
        }
    }

    private void specialWordCheck(Secret credentialObj) throws UserStoreException {

        String specialWordConfig = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_SPECIAL_WORDS_CHECK);
        if (StringUtils.isNotBlank(specialWordConfig)) {
            String[] specialWords = StringUtils.split(specialWordConfig, CustomUserStoreManagerConstants.SEPARATE_CHAR);
            String credential = String.valueOf(credentialObj.getChars());
            if (ArrayUtils.isNotEmpty(specialWords) && credential != null) {
                for (String pattern: specialWords) {
                    if (credential.contains(pattern)) {
                        log.debug("Special Word Detected: " + pattern);
                        throw new UserStoreException("Special Words detected in the password.");
                    }
                }
            }
        } else {
            log.warn("Values for SpecialWord Validation check not configured. Skipping validation.");
        }
    }

    private void userAttributesCheck(String userName, Object credential) throws UserStoreException {

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }
        log.debug("Loading User Attributes");
        String userAttributesConfig = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_USER_ATTRIBUTES_CHECK);
        String validationBypassUserAttributesConfig = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_ENABLE_PASSWORD_VALIDATION_WITH_AVAILABLE_USER_ATTRIBUTES);
        boolean enableValidationWithAvailableAttributes = false;
        if (StringUtils.isNotBlank(validationBypassUserAttributesConfig)) {
            if (StringUtils.equalsIgnoreCase("true", validationBypassUserAttributesConfig)) {
                enableValidationWithAvailableAttributes = true;
            }
        }
        if (StringUtils.isNotBlank(userAttributesConfig)) {
            String[] properties = StringUtils.split(userAttributesConfig, CustomUserStoreManagerConstants.SEPARATE_CHAR);
            if (ArrayUtils.isNotEmpty(properties)) {
                Map<String, String> userProperties = getUserPropertyValues(userName, properties, UserCoreConstants.DEFAULT_PROFILE);
                if (enableValidationWithAvailableAttributes) {
                    if (MapUtils.isNotEmpty(userProperties)) {
                        for (String propValue : userProperties.values()) {
                            if (String.valueOf(credentialObj.getChars()).contains(propValue)) {
                                log.debug("Password contains user attribute values.");
                                throw new UserStoreException("Password contains user attribute values.");
                            }
                        }
                    } else {
                        log.debug("Can not complete user attribute validation: Defined User attributes in PasswordUserAttributesCheck property are empty for the user.");
                        throw new UserStoreException("Can not complete user attribute validation: Can not find password validation user attributes for the user.");
                    }
                } else {
                    if (MapUtils.isNotEmpty(userProperties) && (properties.length == userProperties.size())) {
                        for (String prop : properties) {
                            if (String.valueOf(credentialObj.getChars()).contains(userProperties.get(prop))) {
                                log.debug("Password contains user attribute values.");
                                throw new UserStoreException("Password contains user attribute values.");
                            }
                        }
                    } else {
                        log.debug("Validation for user attribute in password failed: User attribute are empty or unable to find all attributes require for password validation.");
                        throw new UserStoreException("Validation for user attribute in password failed: User attribute are empty or unable to find all attributes require for password validation.");
                    }
                }
            }
        } else {
            log.warn(
                    "Values for user attributes password validation not configured. Skipping user attributes password validation.");
        }
    }

    private void passwordCriteriaCheck(Secret credentialObj) throws UserStoreException {

        boolean regMatchCapital = true;
        boolean regMatchSimple = true;
        boolean regMatchNumber = true;
        boolean regMatchSpecialChar = true;
        int validityCount = 0;
        ArrayList<Boolean> regExValidationCount = new ArrayList<>();
        log.debug("Loading Regular Expressions");

        String passwordLength = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_LENGTH_CHECK);
        String regularCapitalExpression = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_UPPERCASE_JAVA_REGEX);
        String regularNumberExpression = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_NUMBERS_JAVA_REGEX);
        String regularSimpleExpression = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_LOWERCASE_JAVA_REGEX);
        String regularSpecialCharExpression = this.realmConfig.getUserStoreProperty(CustomUserStoreManagerConstants.AD_PASSWORD_SPECIAL_CHAR_JAVA_REGEX);

        if (StringUtils.isNotBlank(passwordLength)) {
            if (Integer.valueOf(passwordLength) > credentialObj.getChars().length) {
                log.debug("Password length does not meet the expected criteria.");
                throw new UserStoreException("Password does not meet the expected criteria.");
            }
        }

        if (StringUtils.isNotBlank(regularCapitalExpression)) {
            regMatchCapital = this.isFormatCorrect(regularCapitalExpression, credentialObj.getChars());
        }
        if (StringUtils.isNotBlank(regularSimpleExpression)) {
            regMatchSimple = this.isFormatCorrect(regularSimpleExpression, credentialObj.getChars());
        }
        if (StringUtils.isNotBlank(regularNumberExpression)) {
            regMatchNumber = this.isFormatCorrect(regularNumberExpression, credentialObj.getChars());
        }
        if (StringUtils.isNotBlank(regularSpecialCharExpression)) {
            regMatchSpecialChar = this.isFormatCorrect(regularSpecialCharExpression, credentialObj.getChars());
        }

        regExValidationCount.add(regMatchCapital);
        regExValidationCount.add(regMatchSimple);
        regExValidationCount.add(regMatchNumber);
        regExValidationCount.add(regMatchSpecialChar);

        for (boolean validity : regExValidationCount) {
            if (validity)
                validityCount++;
        }

        if (validityCount < 3) {
            log.debug("Regular Expression check failed.");
            throw new UserStoreException("Password doesn't meet the expected criteria.");
        }

        log.debug("Regular Expression check passed.");
    }

    private boolean isFormatCorrect(String regularExpression, char[] attribute) {
        CharBuffer charBuffer = CharBuffer.wrap(attribute);
        Pattern pattern = Pattern.compile(regularExpression);
        Matcher matcher = pattern.matcher(charBuffer);
        return matcher.find();
    }

    private boolean isFormatCorrectPasswordLength(String regularExpression, char[] attribute) {
        CharBuffer charBuffer = CharBuffer.wrap(attribute);
        Pattern pattern = Pattern.compile(regularExpression);
        Matcher matcher = pattern.matcher(charBuffer);
        return matcher.lookingAt();
    }

    private long convertAdTime(String adTimeInMilis) {
        return (Long.parseLong(adTimeInMilis) / CustomUserStoreManagerConstants.AD_TIME_TO_UNIX_DIVISION)
                - CustomUserStoreManagerConstants.AD_TIME_TO_UNIX_ADDITION;
    }

}