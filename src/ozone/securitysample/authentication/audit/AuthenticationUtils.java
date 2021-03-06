package ozone.securitysample.authentication.audit;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;
import ozone.security.authentication.OWFUserDetailsImpl;

public class AuthenticationUtils
{
  public static final String MAP_KEY_IP_ADDRESS = "IP_ADDRESS";
  public static final String MAP_KEY_SESSION_ID = "SESSION_ID";
  public static final String MAP_KEY_USERNAME = "USERNAME";
  public static final String REQUEST_KEY_AUTHENTICATION = "MP_SPRING_SECURITY_AUTHENTICATION";

  public String getValidSessionId(HttpServletRequest request, Map<String, String> detailsMap)
  {
    String sessionId = (String)detailsMap.get("SESSION_ID");
    if (request != null) {
      Cookie sessionCookie = getRequestCookieByName(request, "JSESSIONID");
      if (sessionCookie != null) {
        String sessCookieSessionId = sessionCookie.getValue();
        if ((sessionId == null) || ((sessCookieSessionId != null) && (!sessionId.equals(sessCookieSessionId))))
        {
          sessionId = sessCookieSessionId;
        }
      }
    }
    return sessionId;
  }

  public Cookie getRequestCookieByName(HttpServletRequest request, String cookieName) {
    Assert.notNull(request, "HttpServletRequest required");
    Assert.notNull(cookieName, "String Cookie Name required");

    Cookie requestedCookie = null;
    Cookie[] requestCookies = request.getCookies();
    if (requestCookies != null) {
      for (Cookie currCookie : requestCookies) {
        String currCookieName = currCookie.getName();
        if ((currCookieName != null) && (currCookieName.equals(cookieName))) {
          requestedCookie = currCookie;
          break;
        }
      }
    }
    return requestedCookie;
  }

  public Map<String, String> getDetailsMap(Authentication authentication) {
    if (authentication == null) {
      return new HashMap();
    }

    WebAuthenticationDetails metaDetails = (WebAuthenticationDetails)authentication.getDetails();
    String sessionId = metaDetails == null ? null : metaDetails.getSessionId();
    String ipAddress = metaDetails == null ? null : metaDetails.getRemoteAddress();
    HashMap detailsMap = new HashMap();
    detailsMap.put("IP_ADDRESS", ipAddress);
    detailsMap.put("SESSION_ID", sessionId);

    Object user = authentication.getPrincipal();
    String username = null;
    if ((user instanceof OWFUserDetailsImpl))
      username = ((OWFUserDetailsImpl)user).getUsername();
    else {
      username = (user instanceof String) ? (String)user : null;
    }
    detailsMap.put("USERNAME", username);

    return detailsMap;
  }
}