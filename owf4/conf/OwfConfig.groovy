environments {
    production {
        dataSource {
            dbCreate = "none"
            username = "sa"
            password = ""
            driverClassName = "org.hsqldb.jdbcDriver"
            url = "jdbc:hsqldb:file:prodDb;shutdown=true"
            pooled = true
            properties {
                minEvictableIdleTimeMillis = 180000
                timeBetweenEvictionRunsMillis = 180000
                numTestsPerEvictionRun = 3
                testOnBorrow = true
                testWhileIdle = true
                testOnReturn = true
                validationQuery = "SELECT 1 FROM INFORMATION_SCHEMA.SYSTEM_USERS"
            }
        }
        //enable uiperformance plugin which bundles and compresses javascript
        uiperformance.enabled = true
    }
}

beans {
	
	//This block is equivalent to using an org.springframework.beans.factory.config.PropertyOverrideConfigurer
	//See Chapter 14 of the Grails documentation for more information: http://grails.org/doc/1.1/
	
}



println('OwfConfig.groovy completed successfuly.')