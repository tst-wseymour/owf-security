package ozone.securitysample.authentication.basic;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ozone.security.authentication.OWFUserDetails;
import ozone.security.authentication.OWFUserDetailsImpl;
import ozone.security.authorization.model.GrantedAuthorityImpl;
import ozone.security.authorization.model.OwfGroupImpl;

public class MyDetailsService
  implements UserDetailsService
{
  private static final Log log = LogFactory.getLog(MyDetailsService.class);
  private static final String REGEX_COMMA = "\\,";
  private static final String DEFAULT_PROPERTY_FILE = "/users.properties";
  private String propertyFileName = "/users.properties";

  private Map<String, OWFUserDetails> userMap = null;

  public UserDetails loadUserByUsername(String username)
    throws UsernameNotFoundException, DataAccessException
  {
    log.debug("loading user by username [" + username + "]");

    Map userMap = getUserMap();
    OWFUserDetails user = (OWFUserDetails)userMap.get(username);
    if (user == null) {
      log.error("No matching user found [" + username + "].");
      throw new UsernameNotFoundException("The user details service was passed authenticated credentials for '" + username + "', but the credentials were not found. Access is denied.");
    }

    log.info("successfully logged in user [" + user.getUsername() + "], authorities [" + ((OWFUserDetailsImpl)user).displayAuthorities() + "], groups [" + ((OWFUserDetailsImpl)user).displayOwfGroups() + "]");
    return user;
  }

  protected Properties loadPropertiesFile(String propertyFileName)
  {
    Properties properties = new Properties();
    try {
      InputStream inputStream = getClass().getResourceAsStream(propertyFileName);
      if (inputStream != null)
        properties.load(inputStream);
      else
        log.error("Property file [" + propertyFileName + "] not found.");
    }
    catch (IOException e) {
      log.error("I/O error retrieving users.", e);
    }
    return properties;
  }

  protected Map<String, OWFUserDetails> buildUserMap(Properties properties)
  {
    Map userMap = new HashMap();
    Enumeration e = properties.keys();
    while (e.hasMoreElements()) {
      String username = (String)e.nextElement();
      String propValue = properties.getProperty(username);
      String[] values = propValue.split("\\,");
      if ((values != null) && (values.length >= 3))
      {
        String password = values[0];

        String[] roles = values[1].split(":");
        Collection authorities = new ArrayList(roles.length);
        for (int i = 0; i < roles.length; i++)
        {
          authorities.add(new GrantedAuthorityImpl(roles[i]));
        }

        String displayName = values[2];

        int groupStart = 5;
        String org = null;
        if (values.length >= 4) {
          if (values[3].startsWith("[")) {
            groupStart = 3;
          }
          else {
            org = values[3];
          }

        }

        String email = null;
        if ((values.length >= 5) && (groupStart > 3)) {
          if (values[4].startsWith("[")) {
            groupStart = 4;
          }
          else {
            email = values[4];
          }

        }

        Collection owfGroups = new ArrayList();
        for (int i = groupStart; i < values.length; i++)
        {
          String[] groupInfo = values[i].split(";");
          String groupName = groupInfo[0].replace("[", "");
          String groupDescription = groupInfo[1];
          String groupEmail = groupInfo[2];
          boolean active = "active".equals(groupInfo[3].replace("]", ""));
          owfGroups.add(new OwfGroupImpl(groupName, groupDescription, groupEmail, active));
        }

        OWFUserDetailsImpl owfUser = new OWFUserDetailsImpl(username, password, authorities, owfGroups);
        owfUser.setDisplayName(displayName);
        owfUser.setOrganization(org);
        owfUser.setEmail(email);

        userMap.put(username, owfUser);
      }
    }
    return userMap;
  }

  protected void setUserMap(Map<String, OWFUserDetails> userMap) {
    this.userMap = userMap;
  }

  protected Map<String, OWFUserDetails> getUserMap()
  {
    if (this.userMap == null) {
      Properties properties = loadPropertiesFile(this.propertyFileName);
      this.userMap = buildUserMap(properties);
      log.debug("users:" + this.userMap);
      log.debug("loaded [" + this.userMap.size() + "] users");
    }
    return this.userMap;
  }

  public String getPropertyFileName() {
    return this.propertyFileName;
  }

  public void setPropertyFileName(String propertyFileName) {
    this.propertyFileName = propertyFileName;
  }
}