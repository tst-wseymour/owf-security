package ozone.securitysample.authentication.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import ozone.securitysample.authentication.audit.SecurityAuditLogger;

public class OzoneLogoutHandler
  implements LogoutHandler
{
  private static final SecurityAuditLogger SecurityAuditLogger = new SecurityAuditLogger();

  public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
  {
    Authentication auth = authentication == null ? (Authentication)request.getAttribute("MP_SPRING_SECURITY_AUTHENTICATION") : request == null ? null : authentication;

    if (auth != null)
    {
      SecurityAuditLogger.logSuccessLogoutMsg(auth);
    }
  }
}