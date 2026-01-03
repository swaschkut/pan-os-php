<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

trait transfer_ep_template
{

    static $TPL_SHARED_LOCAL_DB_PROFILE;
    static $TPL_HIPMATCH_DEFAULT_MATCH_LIST_ENTRY_CFG;
    static $TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG;
    static $MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_PORTAL_ENTRY_CONFIG;
    static $MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG;
    static $MU_TPL_CFG_TUNNEL_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG;
    static $CLIENTLESS_VPN_CONFIG;
    static $SAML_AUTH_PROFILE_CONFIG;
    static $SAML_SAAS_AUTH_PROFILE_CONFIG;
    static $SAML_SECONDARY_AUTH_PROFILE_CONFIG;



    function ep_createVariables()
    {

        $MU_TPL_CFG_TUNNEL_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG = '
    <entry name="GlobalProtect_External_Gateway-N">
                        <local-address>
                          <interface>-</interface>
                          <ip/>
                        </local-address>
                        <tunnel-interface>-</tunnel-interface>
    </entry>';
        self::$MU_TPL_CFG_TUNNEL_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG = self::stringToXml( $MU_TPL_CFG_TUNNEL_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG );

    $MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG = '
    <entry name="GlobalProtect_External_Gateway">
                  <client-auth>
                    <entry name="DEFAULT">
                      <os>Any</os>
                      <authentication-profile>Local Users</authentication-profile>
                      <authentication-message>Enter login credentials</authentication-message>
                      <username-label>Username</username-label>
                      <password-label>Password</password-label>
                    </entry>
                  </client-auth>
                  <remote-user-tunnel-configs>
                    <entry name="DEFAULT">
                      <authentication-override>
                        <accept-cookie>
                          <cookie-lifetime>
                            <lifetime-in-hours>24</lifetime-in-hours>
                          </cookie-lifetime>
                        </accept-cookie>
                        <cookie-encrypt-decrypt-cert>Authentication Cookie Cert</cookie-encrypt-decrypt-cert>
                        <generate-cookie>yes</generate-cookie>
                      </authentication-override>
                      <source-user>
                        <member>any</member>
                      </source-user>
                      <os>
                        <member>any</member>
                      </os>
                      <retrieve-framed-ip-address>no</retrieve-framed-ip-address>
                      <no-direct-access-to-local-network>no</no-direct-access-to-local-network>
                    </entry>
                  </remote-user-tunnel-configs>
                  <ssl-tls-service-profile>-</ssl-tls-service-profile>
                  <tunnel-mode>yes</tunnel-mode>
                  <remote-user-tunnel>-</remote-user-tunnel>
                  <roles>
                    <entry name="default">
                      <login-lifetime>
                        <days>30</days>
                      </login-lifetime>
                      <inactivity-logout>
                        <hours>3</hours>
                      </inactivity-logout>
                      <disconnect-on-idle>
                        <minutes>180</minutes>
                      </disconnect-on-idle>
                    </entry>
                  </roles>
    </entry>';
        self::$MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG = self::stringToXml( $MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_GATEWAY_ENTRY_CONFIG );

    $MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_PORTAL_ENTRY_CONFIG = '
    <entry name="GlobalProtect_Portal">
                          <portal-config>
                            <local-address>
                              <interface>-</interface>
                              <ip/>
                            </local-address>
                            <ssl-tls-service-profile>-</ssl-tls-service-profile>
                            <client-auth>
                              <entry name="Clientless">
                                <os>Browser</os>
                                <authentication-profile>Local Users</authentication-profile>
                                <authentication-message>Enter login credentials</authentication-message>
                                <username-label>Username</username-label>
                                <password-label>Password</password-label>
                              </entry> 
                              <entry name="DEFAULT">
                                <os>Any</os>
                                <authentication-profile>Local Users</authentication-profile>
                                <authentication-message>Enter login credentials</authentication-message>
                                <username-label>Username</username-label>
                                <password-label>Password</password-label>
                              </entry>
                            </client-auth>
                            <custom-login-page>factory-default</custom-login-page>
                            <custom-home-page>factory-default</custom-home-page>
                          </portal-config>
                          <client-config>
                            <configs>
                              <entry name="DEFAULT">
                                <gateways>
                                  <external>
                                    <list>
                                      <entry name="GP cloud service">
                                        <fqdn>gpcloudservice.com</fqdn>
                                        <priority-rule>
                                          <entry name="Any">
                                            <priority>1</priority>
                                          </entry>
                                        </priority-rule>
                                        <manual>yes</manual>
                                      </entry>
                                    </list>
                                    <cutoff-time>5</cutoff-time>
                                  </external>
                                </gateways>
                                <authentication-override>
                                  <accept-cookie>
                                    <cookie-lifetime>
                                      <lifetime-in-hours>24</lifetime-in-hours>
                                    </cookie-lifetime>
                                  </accept-cookie>
                                  <cookie-encrypt-decrypt-cert>Authentication Cookie Cert</cookie-encrypt-decrypt-cert>
                                  <generate-cookie>yes</generate-cookie>
                                </authentication-override>
                                <source-user>
                                  <member>any</member>
                                </source-user>
                                <os>
                                  <member>any</member>
                                </os>
                              </entry>
                            </configs>
                            <root-ca>
                              <entry name="Forward-Trust-CA">
                                <install-in-cert-store>yes</install-in-cert-store>
                              </entry>
                              <entry name="Root CA">
                                <install-in-cert-store>yes</install-in-cert-store>
                              </entry>
                            </root-ca>
                          </client-config>
    </entry>';
        self::$MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_PORTAL_ENTRY_CONFIG = self::stringToXml( $MU_TPL_CFG_GLOBAL_PROTECT_GLOBAL_PROTECT_PORTAL_ENTRY_CONFIG );

    $CLIENTLESS_VPN_CONFIG = '
    <clientless-vpn>
      <hostname>bsg-test.gp.panclouddev.com</hostname>
      <login-lifetime>
        <hours>3</hours>
      </login-lifetime>
      <inactivity-logout>
        <minutes>30</minutes>
      </inactivity-logout>
      <dns-proxy>CloudDefault</dns-proxy>
    </clientless-vpn>';
        self::$CLIENTLESS_VPN_CONFIG = self::stringToXml( $CLIENTLESS_VPN_CONFIG );

    $SAML_AUTH_PROFILE_CONFIG = '
    <entry name="SAML-Auth-Profile">
          <multi-factor-auth>
            <mfa-enable>no</mfa-enable>
          </multi-factor-auth>
          <method>
            <saml-idp>
              <attribute-name-username>username</attribute-name-username>
              <attribute-name-usergroup>group</attribute-name-usergroup>
              <server-profile>SAML-IdP-Server</server-profile>
              <enable-single-logout>no</enable-single-logout>
            </saml-idp>
          </method>
          <allow-list>
            <member>all</member>
          </allow-list>
          <username-modifier>%USERINPUT%</username-modifier>
    </entry>';
        self::$SAML_AUTH_PROFILE_CONFIG = self::stringToXml( $SAML_AUTH_PROFILE_CONFIG );

    $SAML_SAAS_AUTH_PROFILE_CONFIG = '
    <entry name="SAML-SaaS-Auth-Profile">
          <multi-factor-auth>
            <mfa-enable>no</mfa-enable>
          </multi-factor-auth>
          <method>
            <saml-idp>
              <attribute-name-username>username</attribute-name-username>
              <server-profile>SAML-IdP-Server</server-profile>
            </saml-idp>
          </method>
          <allow-list>
            <member>all</member>
          </allow-list>
          <username-modifier>%USERINPUT%</username-modifier>
    </entry>';
        self::$SAML_SAAS_AUTH_PROFILE_CONFIG = self::stringToXml( $SAML_SAAS_AUTH_PROFILE_CONFIG );

        $SAML_SECONDARY_AUTH_PROFILE_CONFIG = '
    <entry name="SAML-Secondary-Auth-Profile">
          <multi-factor-auth>
            <mfa-enable>no</mfa-enable>
          </multi-factor-auth>
          <method>
            <saml-idp>
              <attribute-name-username>username</attribute-name-username>
              <attribute-name-usergroup>group</attribute-name-usergroup>
              <server-profile>SAML-IdP-Server</server-profile>
            </saml-idp>
          </method>
          <allow-list>
            <member>all</member>
          </allow-list>
          <username-modifier>%USERINPUT%</username-modifier>
    </entry>';
        self::$SAML_SECONDARY_AUTH_PROFILE_CONFIG = self::stringToXml( $SAML_SECONDARY_AUTH_PROFILE_CONFIG );

        $TPL_HIPMATCH_DEFAULT_MATCH_LIST_ENTRY_CFG = '
        <entry name="hipmatch-gpcs-default">
              <filter>All Logs</filter>
              <send-to-panorama>yes</send-to-panorama>
        </entry>';
        self::$TPL_HIPMATCH_DEFAULT_MATCH_LIST_ENTRY_CFG = self::stringToXml( $TPL_HIPMATCH_DEFAULT_MATCH_LIST_ENTRY_CFG );

        $TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG = '
        <entry name="userid-gpcs-default">
              <filter>All Logs</filter>
              <send-to-panorama>yes</send-to-panorama>
        </entry>';
        self::$TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG = self::stringToXml( $TPL_USERID_DEFAULT_MATCH_LIST_ENTRY_CFG );

        $TPL_SHARED_LOCAL_DB_PROFILE = '
    <entry name="Local-DB-Profile">
        <multi-factor-auth>
            <mfa-enable>no</mfa-enable>
        </multi-factor-auth>
        <method>
            <local-database/>
        </method>
        <allow-list>
            <member>all</member>
        </allow-list>
    </entry>';

        self::$TPL_SHARED_LOCAL_DB_PROFILE = self::stringToXml( $TPL_SHARED_LOCAL_DB_PROFILE );
    }

    function migrate_ep_template( $tpl_cfg, $plugin_xmlroot )
    {
        #self::ep_createVariables();

        $this->template_path_settings( $tpl_cfg, $plugin_xmlroot, "new" );


        //as not available at this stage
        $DEVICEName = "Mobile Users Container";
        $DEVICE = $this->pan_fawkes->findContainer( $DEVICEName);
        if( $DEVICE === null )
            $DEVICE = $this->pan_fawkes->createContainer( $DEVICEName, "Prisma Access" );


        $DEVICEName = "Mobile Users Explicit Proxy";
        $DEVICE = $this->pan_fawkes->findDeviceCloud( $DEVICEName);
        if( $DEVICE === null )
        {
            $DEVICE = $this->pan_fawkes->createDeviceCloud( $DEVICEName, "Mobile Users Container" );
            #$this->expliciteProxypredefined( $DEVICE, $this->fawkes_doc );
        }


        if( $DEVICE != null )
        {
            $cont_xmlroot = $DEVICE->xmlroot;
            $cont_devices = DH::findFirstElementOrCreate( "devices", $cont_xmlroot );
            $cont_devices_entry = DH::findFirstElementOrCreate( "entry", $cont_devices );
            $cont_devices_entry->setAttribute( "name", "localhost.localdomain");

            $cont_devices_entry_network = DH::findFirstElementOrCreate( "network", $cont_devices_entry );
            $cont_devices_entry_network_tunnel = DH::findFirstElementOrCreate( "tunnel", $cont_devices_entry_network );


            // entry/network/tunnel/global-protect-gateway
            $tmp_node = self::$tpl_cfg_network_tunnel_global_protect_gateway_node;
            if( $tmp_node != false )
            {
                $node = $this->fawkes_doc->importNode($tmp_node, TRUE);
                $cont_devices_entry_network_tunnel->appendChild( $node );
                self::$tpl_config_device_entry_network_tunnel_node->removeChild( self::$tpl_cfg_network_tunnel_global_protect_gateway_node );
            }



            // entry/vsys/entry/global-protect
            $MU_tpl_cfg_vsys_node = DH::findFirstElementOrCreate( "vsys", $cont_devices_entry );
            $MU_tpl_cfg_vsys_entry_node = DH::findFirstElementOrCreate( "entry", $MU_tpl_cfg_vsys_node );

            $MU_tpl_cfg_vsys_entry_node->setAttribute( "name", "vsys1");

            $tmp_node = self::$tpl_vsys_gp;


            $node = $this->fawkes_doc->importNode($tmp_node, TRUE);
            $MU_tpl_cfg_vsys_entry_node->appendChild( $node );
            #self::$tpl_cfg_vsys_entry_node->removeChild( self::$tpl_vsys_gp );


            //authentication-profile from Mobile User Container - to mobile user Device Cloud
            $auth_prof_to_move = DH::findFirstElementOrCreate( "authentication-profile", self::$tpl_cfg_vsys_entry_node );
            $node = $this->fawkes_doc->importNode($auth_prof_to_move, TRUE);
            $MU_tpl_cfg_vsys_entry_node->appendChild( $node );
        }





        //Todo: ---------------------rename Local-DB-Profile to Local Users-------------


        //Todo: this profile renaming is ONLY needed if the above part "shared_authentication_profile_node == null" is true
        $tpl_cfg_vsys_entry_authentication_profile_node = DH::findFirstElementOrCreate( "authentication-profile", self::$tpl_cfg_vsys_entry_node );
        $tpl_cfg_vsys_entry_authentication_profile_local_db_entry = DH::findFirstElementByNameAttr( 'entry', 'Local-DB-Profile', $tpl_cfg_vsys_entry_authentication_profile_node );
        if( $tpl_cfg_vsys_entry_authentication_profile_local_db_entry != null )
        {
            $tpl_cfg_vsys_entry_authentication_profile_local_db_entry->setAttribute( "name", "Local Users" );
        }
        else
            $this->printDebug( PH::boldText( "[ERROR] db profile auth 'Local-DB-Profile' not found! - assumption that VSYS1 authentication-profile(s) are already available\n" ) );


        /*
        # for each mu entry perform the xform
        for plugin_cfg_mu_onboarding_entry_node in plugin_cfg_mu_onboarding_entry_nodes:
        */
        if( is_object(self::$plugin_cfg_onboarding_entry_nodes) )
            foreach( self::$plugin_cfg_onboarding_entry_nodes->childNodes as $plugin_cfg_onboarding_entry_node )
            {
                self::stage_shared();
            }

    }
}