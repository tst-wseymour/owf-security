package ozone.securitysample.authentication.audit;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import ozone.security.authentication.OWFUserDetailsImpl;
import sun.security.x509.X509CertImpl;

public class SecurityAuditLogger
{
  private static final Logger logAudit = Logger.getLogger(SecurityAuditLogger.class);
  private static final AuthenticationUtils MP_AUTH_UTILS = new AuthenticationUtils();
  protected DateFormat eventDateFormatter = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss Z");
  private static final String LOGIN_ACTION = "LOGIN";
  private static final String LOGOUT_ACTION = "LOGOUT";
  private static final String STATE_SUCCESS = "SUCCESS";
  private static final String STATE_FAILURE = "FAILURE";
  private static final String SUCCESS_LOGIN_STATUS = "LOGIN SUCCESS - ACCESS GRANTED";
  private static final String FAILURE_LOGIN_STATUS = "LOGIN FAILURE - ACCESS DENIED";

  public boolean isInfo()
  {
    return logAudit.getLevel() == Level.INFO;
  }

  public boolean isDebug()
  {
    return logAudit.getLevel() == Level.DEBUG;
  }

  public void logSuccessLoginMsg(InteractiveAuthenticationSuccessEvent event)
  {
    if (event == null) {
      return;
    }
    Authentication authentication = event.getAuthentication();
    logEventSuccessMsg(authentication, "LOGIN");
  }

  public void logSuccessLogoutMsg(Authentication authentication)
  {
    logEventSuccessMsg(authentication, "LOGOUT");
  }

  private void logEventSuccessMsg(Authentication authentication, String actionType)
  {
    if (authentication == null) {
      return;
    }
    Object user = authentication.getPrincipal();
    Object credentials = authentication.getCredentials();
    HashMap detailsMap = (HashMap)MP_AUTH_UTILS.getDetailsMap(authentication);
    if ((user instanceof OWFUserDetailsImpl)) {
      StringBuffer auditLogMsgBuffer = new StringBuffer("[USER ").append(actionType).append("]:").append(getMsgByActionType("SUCCESS", actionType)).append(" USER [").append((String)detailsMap.get("USERNAME")).append("], ").append("with DISPLAY NAME [").append(((OWFUserDetailsImpl)user).getDisplayName()).append("], ").append("with AUTHORITIES [").append(((OWFUserDetailsImpl)user).displayAuthorities()).append("], ").append("with ORGANIZATION [").append(((OWFUserDetailsImpl)user).getOrganization()).append("], ").append("with EMAIL [").append(((OWFUserDetailsImpl)user).getEmail()).append("] ").append("with CREDENTIALS [");

      if ((credentials instanceof X509CertImpl)) {
        if (isDebug()) {
          X509CertImpl x509Credentials = (X509CertImpl)credentials;

          auditLogMsgBuffer.append("CERTIFICATE ").append(actionType).append(" >> Signature Algorithm: [").append(x509Credentials.getSigAlgName()).append(", OID = ").append(x509Credentials.getSigAlgOID()).append("]; ");

          auditLogMsgBuffer.append("Subject: [").append(x509Credentials.getSubjectDN()).append("]; ");

          auditLogMsgBuffer.append("Validity: [").append("From: ").append(x509Credentials.getNotBefore()).append(", To: ").append(x509Credentials.getNotAfter()).append("]; ");

          auditLogMsgBuffer.append("Issuer: [").append(x509Credentials.getIssuerDN()).append("]; ");
        }
        else
        {
          auditLogMsgBuffer.append("CERTIFICATE ").append(actionType);
        }
      } else if (((credentials instanceof String)) && (((String)credentials).toLowerCase().contains("cas"))) {
        if (isDebug())
          auditLogMsgBuffer.append("CAS ").append(actionType).append(" >> ").append(credentials);
        else {
          auditLogMsgBuffer.append("CAS ").append(actionType);
        }
      }
      else if (isDebug())
        auditLogMsgBuffer.append("SUCCESSFUL ").append(actionType).append(" >> ").append(credentials);
      else {
        auditLogMsgBuffer.append("SUCCESSFUL ").append(actionType);
      }

      auditLogMsgBuffer.append("]");
      String auditLogMsg = auditLogMsgBuffer.toString();

      String sessionId = (String)detailsMap.get("SESSION_ID");
      if (isInfo()) {
        logAuditMsg((String)detailsMap.get("IP_ADDRESS"), sessionId, (String)detailsMap.get("USERNAME"), auditLogMsg, 20000);
      }
      else if (isDebug())
        logAuditMsg((String)detailsMap.get("IP_ADDRESS"), sessionId, (String)detailsMap.get("USERNAME"), auditLogMsg, 10000);
    }
  }

  public void logFailureLoginMsg(AbstractAuthenticationFailureEvent event)
  {
    logEventFailureMsg(event, "LOGIN");
  }

  private void logEventFailureMsg(AbstractAuthenticationFailureEvent event, String actionType)
  {
    if (event == null) {
      return;
    }

    Authentication authentication = (Authentication)event.getSource();
    if (authentication == null) {
      return;
    }
    Object user = authentication.getPrincipal();
    Object credentials = authentication.getCredentials();
    String eventExceptionMsg = event.getException().getMessage();
    HashMap detailsMap = (HashMap)MP_AUTH_UTILS.getDetailsMap(authentication);
    String failureMsg = "";
    if ((event instanceof AuthenticationFailureProviderNotFoundEvent)) {
      StringBuffer auditLogMsgBuffer = new StringBuffer();
      auditLogMsgBuffer.append("Login for ").append("a user with principal '" + user + "' ").append("attempted with authenticated credentials [");

      if ((credentials instanceof X509CertImpl)) {
        if (isDebug()) {
          X509CertImpl x509Credentials = (X509CertImpl)credentials;

          auditLogMsgBuffer.append("CERTIFICATE ").append(actionType).append(" >> Signature Algorithm: [").append(x509Credentials.getSigAlgName()).append(", OID = ").append(x509Credentials.getSigAlgOID()).append("]; ");

          auditLogMsgBuffer.append("Subject: [").append(x509Credentials.getSubjectDN()).append("]; ");

          auditLogMsgBuffer.append("Validity: [").append("From: ").append(x509Credentials.getNotBefore()).append(", To: ").append(x509Credentials.getNotAfter()).append("]; ");

          auditLogMsgBuffer.append("Issuer: [").append(x509Credentials.getIssuerDN()).append("]; ");
        }
        else
        {
          auditLogMsgBuffer.append("CERTIFICATE ").append(actionType);
        }
      } else if (((credentials instanceof String)) && (((String)credentials).toLowerCase().contains("cas"))) {
        if (isDebug())
          auditLogMsgBuffer.append("CAS ").append(actionType).append(" >> ").append(credentials);
        else {
          auditLogMsgBuffer.append("CAS ").append(actionType);
        }
      }
      else if (isDebug())
        auditLogMsgBuffer.append("FAILURE ").append(actionType).append(" >> ").append(credentials);
      else {
        auditLogMsgBuffer.append("FAILURE ").append(actionType);
      }

      auditLogMsgBuffer.append("]; However, the Provider was not found. Access is DENIED.");
      if (isDebug()) {
        auditLogMsgBuffer.append(actionType).append(" Exception Message: [").append(eventExceptionMsg).append("]");
      }

      failureMsg = auditLogMsgBuffer.toString();
    } else {
      failureMsg = "Authentication Failure Message : " + eventExceptionMsg;
    }

    String auditLogMsg = "[USER " + actionType + "]:" + getMsgByActionType("FAILURE", actionType) + " with FAILURE MSG [" + failureMsg + "]";

    String sessionId = (String)detailsMap.get("SESSION_ID");
    if (isInfo()) {
      logAuditMsg((String)detailsMap.get("IP_ADDRESS"), sessionId, (String)detailsMap.get("USERNAME"), auditLogMsg, 20000);
    }
    else if (isDebug())
      logAuditMsg((String)detailsMap.get("IP_ADDRESS"), sessionId, (String)detailsMap.get("USERNAME"), auditLogMsg, 10000);
  }

  private String getMsgByActionType(String eventState, String actionType)
  {
    if (("LOGIN".equals(actionType)) && ("SUCCESS".equals(eventState)))
      return "LOGIN SUCCESS - ACCESS GRANTED";
    if (("LOGIN".equals(actionType)) && ("FAILURE".equals(eventState))) {
      return "LOGIN FAILURE - ACCESS DENIED";
    }
    return actionType;
  }

  public void logAuditMsg(String ipAddress, String sessionId, String username, String msg, int logLevel)
  {
    StringBuffer auditLogStringBuffer = new StringBuffer();
    boolean isExtraSpace = false;
    auditLogStringBuffer.append("[").append(this.eventDateFormatter.format(new Date())).append("] ");
    if (StringUtils.isNotBlank(ipAddress)) {
      auditLogStringBuffer.append("IP: ").append(ipAddress);

      isExtraSpace = true;
    }
    if (StringUtils.isNotBlank(sessionId)) {
      auditLogStringBuffer.append(isExtraSpace ? " " : "").append("SessionID: ").append(sessionId);

      isExtraSpace = true;
    }

    if (StringUtils.isNotBlank(username)) {
      auditLogStringBuffer.append(isExtraSpace ? " " : "").append("User: ").append(username);

      isExtraSpace = true;
    }
    auditLogStringBuffer.append(isExtraSpace ? " " : "").append(msg);

    String auditLogString = auditLogStringBuffer.toString();
    switch (logLevel) {
    case 10000:
      logAudit.debug(auditLogString);
      break;
    case 20000:
      logAudit.info(auditLogString);
      break;
    case 30000:
      logAudit.warn(auditLogString);
      break;
    case 40000:
      logAudit.error(auditLogString);
      break;
    case 50000:
      logAudit.fatal(auditLogString);
      break;
    }
  }

  public Logger getLogAudit()
  {
    return logAudit;
  }
}