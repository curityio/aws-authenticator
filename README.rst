AWS Cognito Authenticator Plugin
================================

AWS Cognito Oauth Authenticator plugin for the Curity Identity Server.

Create AWS Authenticator and configure following values.

Config
~~~~~~

+-------------------+--------------------------------------------------+-----------------------------+
| Name              | Default                                          | Description                 |
+===================+==================================================+=============================+
| ``Client ID``     |                                                  | AWS app client id           |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Client Secret`` |                                                  | AWS app secret key          |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Domain``        |                                                  | URL App domain              |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Authorization`` | /oauht2/authorize                                | URL to the AWS              |
| ``Endpoint``      |                                                  | authorization endpoint      |
|                   |                                                  |                             |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Token``         | /oauth2/token                                    | URL to the AWS              |
| ``Endpoint``      |                                                  | authorization endpoint      |
+-------------------+--------------------------------------------------+-----------------------------+
| ``Scope``         |    ``openid profile``                            | A space-separated list of   |
|                   |                                                  | scopes to request from      |
|                   |                                                  | AWS                         |
+-------------------+--------------------------------------------------+-----------------------------+

Build plugin
~~~~~~~~~~~~

First, collect credentials to the Curity Nexus, to be able to fetch the
SDK. Add nexus credentials in maven settings.

Then, build the plugin by: ``mvn clean package``

Install plugin
~~~~~~~~~~~~~~

| To install a plugin into the server, simply drop its jars and all of
  its required resources, including Server-Provided Dependencies, in the
  ``<plugin_group>`` directory.
| Please visit `curity.io/plugins`_ for more information about plugin
  installation.

Required dependencies/jars
""""""""""""""""""""""""""

Following jars must be in plugin group classpath.

-  `commons-codec-1.9.jar`_
-  `commons-logging-1.2.jar`_
-  `google-collections-1.0-rc2.jar`_
-  `httpclient-4.5.jar`_
-  `httpcore-4.4.1.jar`_
-  `identityserver.plugins.oauth.authenticators-utility-1.0.0.jar`_
-  `jose4j-0.6.2.jar`_


Please visit `curity.io`_ for more information about the Curity Identity
Server.

.. _AWS app: https://www.aws.com/developer/clients/manage
.. _curity.io/plugins: https://support.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation
.. _commons-codec-1.9.jar: http://central.maven.org/maven2/commons-codec/commons-codec/1.9/commons-codec-1.9.jar
.. _commons-logging-1.2.jar: http://central.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar
.. _google-collections-1.0-rc2.jar: http://central.maven.org/maven2/com/google/collections/google-collections/1.0-rc2/google-collections-1.0-rc2.jar
.. _httpclient-4.5.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5/httpclient-4.5.jar
.. _httpcore-4.4.1.jar: http://central.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.1/httpcore-4.4.1.jar
.. _identityserver.plugins.oauth.authenticators-utility-1.0.0.jar: https://github.com/curityio/oauth-authenticator-utility-plugin
.. _jose4j-0.6.2.jar: http://central.maven.org/maven2/org/bitbucket/b_c/jose4j/0.6.2/jose4j-0.6.2.jar
.. _curity.io: https://curity.io/
