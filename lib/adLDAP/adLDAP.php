<?php
namespace adLDAP;
/**
 * PHP LDAP CLASS FOR MANIPULATING ACTIVE DIRECTORY
 * Version 5.0.0
 *
 * PHP Version 5 with SSL and LDAP support
 *
 * Written by Scott Barnett, Richard Hyland
 *   email: scott@wiggumworld.com, adldap@richardhyland.com
 *   http://github.com/adldap/adLDAP
 *
 * Copyright (c) 2006-2014 Scott Barnett, Richard Hyland
 *
 * We'd appreciate any improvements or additions to be submitted back
 * to benefit the entire community :)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * @category ToolsAndUtilities
 * @package adLDAP
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2014 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @version 5.0.0
 * @link http://github.com/adldap/adLDAP
 */

/**
 * Main adLDAP class
 *
 * Can be initialised using $adldap = new adLDAP();
 *
 * Something to keep in mind is that Active Directory is a permissions
 * based directory. If you bind as a domain user, you can't fetch as
 * much information on other users as you could as a domain admin.
 *
 * Before asking questions, please read the Documentation at
 * http://adldap.sourceforge.net/wiki/doku.php?id=api
 */
require_once(dirname(__FILE__) . '/collections/adLDAPCollection.php');
require_once(dirname(__FILE__) . '/classes/adLDAPGroups.php');
require_once(dirname(__FILE__) . '/classes/adLDAPUsers.php');
require_once(dirname(__FILE__) . '/classes/adLDAPFolders.php');
require_once(dirname(__FILE__) . '/classes/adLDAPUtils.php');
require_once(dirname(__FILE__) . '/classes/adLDAPContacts.php');
require_once(dirname(__FILE__) . '/classes/adLDAPExchange.php');
require_once(dirname(__FILE__) . '/classes/adLDAPComputers.php');

class adLDAP {

    /**
     * Define the different types of account in AD
     */
    const ADLDAP_NORMAL_ACCOUNT = 805306368;
    const ADLDAP_WORKSTATION_TRUST = 805306369;
    const ADLDAP_INTERDOMAIN_TRUST = 805306370;
    const ADLDAP_SECURITY_GLOBAL_GROUP = 268435456;
    const ADLDAP_DISTRIBUTION_GROUP = 268435457;
    const ADLDAP_SECURITY_LOCAL_GROUP = 536870912;
    const ADLDAP_DISTRIBUTION_LOCAL_GROUP = 536870913;
    const ADLDAP_FOLDER = 'OU';
    const ADLDAP_CONTAINER = 'CN';

    /**
     * The default port for LDAP non-SSL connections
     */
    const ADLDAP_LDAP_PORT = '389';
    /**
     * The default port for LDAPS SSL connections
     */
    const ADLDAP_LDAPS_PORT = '636';

    /**
     * The account suffix for your domain, can be set when the class is invoked
     *
     * @var string
     */
    protected $accountSuffix = "@mydomain.local";

    /**
     * The base dn for your domain
     *
     * If this is set to null then adLDAP will attempt to obtain this automatically from the rootDSE
     *
     * @var string
     */
    protected $baseDn = "DC=mydomain,DC=local";

    /**
     * Port used to talk to the domain controllers.
     *
     * @var int
     */
    protected $adPort = self::ADLDAP_LDAP_PORT;

    /**
     * Array of domain controllers. Specifiy multiple controllers if you
     * would like the class to balance the LDAP queries amongst multiple servers
     *
     * @var array
     */
    protected $domainControllers = array("dc01.mydomain.local");

    /**
     * Optional account with higher privileges for searching
     * This should be set to a domain admin account
     *
     * @var string
     * @var string
     */
    protected $adminUsernameUsername = NULL;
    protected $adminPassword = NULL;

    /**
     * AD does not return the primary group. http://support.microsoft.com/?kbid=321360
     * This tweak will resolve the real primary group.
     * Setting to false will fudge "Domain Users" and is much faster. Keep in mind though that if
     * someone's primary group is NOT domain users, this is obviously going to mess up the results
     *
     * @var bool
     */
    protected $realPrimaryGroup = TRUE;

    /**
     * Use SSL (LDAPS), your server needs to be setup, please see
     * http://adldap.sourceforge.net/wiki/doku.php?id=ldap_over_ssl
     *
     * @var bool
     */
    protected $useSSL = FALSE;

    /**
     * Use TLS
     * If you wish to use TLS you should ensure that $useSSL is set to false and vice-versa
     *
     * @var bool
     */
    protected $useTLS = FALSE;

    /**
     * Use SSO
     * To indicate to adLDAP to reuse password set by the brower through NTLM or Kerberos
     *
     * @var bool
     */
    protected $useSSO = FALSE;

    /**
     * When querying group memberships, do it recursively
     * eg. User Fred is a member of Group A, which is a member of Group B, which is a member of Group C
     * user_ingroup("Fred","C") will returns true with this option turned on, false if turned off
     *
     * @var bool
     */
    protected $recursiveGroups = TRUE;

    /**
     * When a query returns a referral, follow it.
     *
     * @var int
     */
    protected $followReferrals = 0;

    // You should not need to edit anything below this line
    //******************************************************************************************

    /**
     * Connection and bind default variables
     *
     * @var mixed
     * @var mixed
     */
    protected $ldapConnection;
    protected $ldapBind;
    /**
     * The group class
     *
     * @var \adLDAP\classes\adLDAPGroups
     */
    protected $groupClass;
    /**
     * The user class
     *
     * @var \adLDAP\classes\adLDAPUsers
     */
    protected $userClass;
    /**
     * The folders class
     *
     * @var \adLDAP\classes\adLDAPFolders
     */
    protected $folderClass;
    /**
     * The utils class
     *
     * @var \adLDAP\classes\adLDAPUtils
     */
    protected $utilClass;
    /**
     * The contacts class
     *
     * @var \adLDAP\classes\adLDAPContacts
     */
    protected $contactClass;
    /**
     * The exchange class
     *
     * @var \adLDAP\classes\adLDAPExchange
     */
    protected $exchangeClass;
    /**
     * The computers class
     *
     * @var \adLDAP\classes\adLDAPComputers
     */
    protected $computerClass;

    /**
     * Default Constructor
     *
     * Tries to bind to the AD domain over LDAP or LDAPs
     *
     * @param array $options Array of options to pass to the constructor
     * @throws \Exception - if unable to bind to Domain Controller
     */
    function __construct($options = array()) {
        // You can specifically overide any of the default configuration options setup above
        if (count($options) > 0) {
            if (array_key_exists("account_suffix", $options)) {
                $this->accountSuffix = $options["account_suffix"];
            }
            if (array_key_exists("base_dn", $options)) {
                $this->baseDn = $options["base_dn"];
            }
            if (array_key_exists("domain_controllers", $options)) {
                if (!is_array($options["domain_controllers"])) {
                    throw new adLDAPException('[domain_controllers] option must be an array');
                }
                $this->domainControllers = $options["domain_controllers"];
            }
            if (array_key_exists("admin_username", $options)) {
                $this->adminUsername = $options["admin_username"];
            }
            if (array_key_exists("admin_password", $options)) {
                $this->adminPassword = $options["admin_password"];
            }
            if (array_key_exists("real_primarygroup", $options)) {
                $this->realPrimaryGroup = $options["real_primarygroup"];
            }
            if (array_key_exists("use_ssl", $options)) {
                $this->setUseSSL($options["use_ssl"]);
            }
            if (array_key_exists("use_tls", $options)) {
                $this->useTLS = $options["use_tls"];
            }
            if (array_key_exists("recursive_groups", $options)) {
                $this->recursiveGroups = $options["recursive_groups"];
            }
            if (array_key_exists("follow_referrals", $options)) {
                $this->followReferrals = $options["follow_referrals"];
            }
            if (array_key_exists("ad_port", $options)) {
                $this->setPort($options["ad_port"]);
            }
            if (array_key_exists("sso", $options)) {
                $this->setUseSSO($options["sso"]);
                if (!$this->ldapSaslSupported()) {
                    $this->setUseSSO(FALSE);
                }
            }
        }

        if ($this->ldapSupported() === FALSE) {
            throw new adLDAPException('No LDAP support for PHP.  See: http://www.php.net/ldap');
        }

        $this->connect();
    }

    /**
     * Sets the port number your domain controller communicates over
     *
     * @param int $adPort
     */
    public function setPort($adPort) {
        $this->adPort = $adPort;
    }

    /**
     * Detect ldap_sasl_bind support in PHP
     *
     * @return bool
     */
    protected function ldapSaslSupported() {
        if (!function_exists('ldap_sasl_bind')) {
            return FALSE;
        }

        return TRUE;
    }

    /**
     * Detect LDAP support in php
     *
     * @return bool
     */
    protected function ldapSupported() {
        if (!function_exists('ldap_connect')) {
            return FALSE;
        }

        return TRUE;
    }

    /**
     * Connects and Binds to the Domain Controller
     *
     * @throws adLDAPException
     */
    public function connect() {
        // Connect to the AD/LDAP server as the username/password
        $domainController = $this->randomController();
        if ($this->useSSL) {
            $this->ldapConnection = ldap_connect("ldaps://" . $domainController, $this->adPort);
        } else {
            $this->ldapConnection = ldap_connect("ldap://" . $domainController, $this->adPort);
        }

        // Set some ldap options for talking to AD
        ldap_set_option($this->ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($this->ldapConnection, LDAP_OPT_REFERRALS, $this->followReferrals);

        if ($this->useTLS) {
            ldap_start_tls($this->ldapConnection);
        }

        // Bind as a domain admin if they've set it up
        if ($this->adminUsername !== NULL && $this->adminPassword !== NULL) {
            $this->ldapBind = @ldap_bind($this->ldapConnection, $this->adminUsername . $this->accountSuffix, $this->adminPassword);
            if (!$this->ldapBind) {
                if ($this->useSSL && !$this->useTLS) {
                    // If you have problems troubleshooting, remove the @ character from the ldapldapBind command above to get the actual error message
                    throw new adLDAPException('Bind to Active Directory failed. Either the LDAPs connection failed or the login credentials are incorrect. AD said: ' . $this->getLastError());
                } else {
                    throw new adLDAPException('Bind to Active Directory failed. Check the login credentials and/or server details. AD said: ' . $this->getLastError());
                }
            }
        }
        if ($this->useSSO && $_SERVER['REMOTE_USER'] && $this->adminUsername === NULL && $_SERVER['KRB5CCNAME']) {
            putenv("KRB5CCNAME=" . $_SERVER['KRB5CCNAME']);
            $this->ldapBind = @ldap_sasl_bind($this->ldapConnection, NULL, NULL, "GSSAPI");
            if (!$this->ldapBind) {
                throw new adLDAPException('Rebind to Active Directory failed. AD said: ' . $this->getLastError());
            } else {
                return;
            }
        }

        if ($this->baseDn == NULL) {
            $this->baseDn = $this->findBaseDn();
        }
    }

    /**
     * Select a random domain controller from your domain controller array
     *
     * @return string
     */
    protected function randomController() {
        mt_srand(doubleval(microtime()) * 100000000); // For older PHP versions
        /*if (sizeof($this->domainControllers) > 1) {
            $adController = $this->domainControllers[array_rand($this->domainControllers)];
            // Test if the controller is responding to pings
            $ping = $this->pingController($adController);
            if ($ping === false) {
                // Find the current key in the domain controllers array
                $key = array_search($adController, $this->domainControllers);
                // Remove it so that we don't end up in a recursive loop
                unset($this->domainControllers[$key]);
                // Select a new controller
                return $this->randomController();
            }
            else {
                return ($adController);
            }
        } */

        return $this->domainControllers[array_rand($this->domainControllers)];
    }

    /**
     * Get last error from Active Directory
     *
     * This function gets the last message from Active Directory
     * This may indeed be a 'Success' message but if you get an unknown error
     * it might be worth calling this function to see what errors were raised
     *
     * return string
     */
    public function getLastError() {
        return @ldap_error($this->ldapConnection);
    }

    /**
     * Find the Base DN of your domain controller
     *
     * @throws adLDAPException
     * @return string
     */
    public function findBaseDn() {
        $namingContext = $this->getRootDse(array('defaultnamingcontext'));

        return $namingContext[0]['defaultnamingcontext'][0];
    }

    /**
     * Get the RootDSE properties from a domain controller
     *
     * @param array $attributes The attributes you wish to query e.g. defaultnamingcontext
     * @return array
     * @throws adLDAPException
     */
    public function getRootDse($attributes = array("*", "+")) {
        if (!$this->ldapBind) {
            throw new adLDAPException("Ldap not binded");
        }

        $sr = @ldap_read($this->ldapConnection, NULL, 'objectClass=*', $attributes);
        $entries = @ldap_get_entries($this->ldapConnection, $sr);

        return $entries;
    }

    /**
     * Get the group class interface
     *
     * @return \adLDAP\classes\adLDAPGroups
     */
    public function group() {
        if (!$this->groupClass) {
            $this->groupClass = new \adLDAP\classes\adLDAPGroups($this);
        }

        return $this->groupClass;
    }

    /**
     * Get the folder class interface
     *
     * @return \adLDAP\classes\adLDAPFolders
     */
    public function folder() {
        if (!$this->folderClass) {
            $this->folderClass = new \adLDAP\classes\adLDAPFolders($this);
        }

        return $this->folderClass;
    }

    /**
     * Getters and Setters
     */

    /**
     * Get the contacts class interface
     *
     * @return \adLDAP\classes\adLDAPContacts
     */
    public function contact() {
        if (!$this->contactClass) {
            $this->contactClass = new \adLDAP\classes\adLDAPContacts($this);
        }

        return $this->contactClass;
    }

    /**
     * Get the exchange class interface
     *
     * @return \adLDAP\classes\adLDAPExchange
     */
    public function exchange() {
        if (!$this->exchangeClass) {
            $this->exchangeClass = new \adLDAP\classes\adLDAPExchange($this);
        }

        return $this->exchangeClass;
    }

    /**
     * Get the computers class interface
     *
     * @return \adLDAP\classes\adLDAPComputers
     */
    public function computer() {
        if (!$this->computerClass) {
            $this->computerClass = new \adLDAP\classes\adLDAPComputers($this);
        }

        return $this->computerClass;
    }

    /**
     * Get the account suffix
     *
     * @return string
     */
    public function getAccountSuffix() {
        return $this->accountSuffix;
    }

    /**
     * Set the account suffix
     *
     * @param string $accountSuffix
     * @return void
     */
    public function setAccountSuffix($accountSuffix) {
        $this->accountSuffix = $accountSuffix;
    }

    /**
     * Get the list of domain controllers
     *
     * @return array
     */
    public function getDomainControllers() {
        return $this->domainControllers;
    }

    /**
     * Set the domain controllers array
     *
     * @param array $domainControllers
     * @return void
     */
    public function setDomainControllers(array $domainControllers) {
        $this->domainControllers = $domainControllers;
    }

    /**
     * Gets the port number your domain controller communicates over
     *
     * @return int
     */
    public function getPort() {
        return $this->adPort;
    }

    /**
     * Set the username of an account with higher priviledges
     *
     * @param string $adminUsername
     * @return void
     */
    public function setAdminUsername($adminUsername) {
        $this->adminUsername = $adminUsername;
    }

    /**
     * Get the username of the account with higher priviledges
     *
     * This will throw an exception for security reasons
     */
    public function getAdminUsername() {
        throw new adLDAPException('For security reasons you cannot access the domain administrator account details');
    }

    /**
     * Get the password of the account with higher priviledges
     *
     * This will throw an exception for security reasons
     */
    public function getAdminPassword() {
        throw new adLDAPException('For security reasons you cannot access the domain administrator account details');
    }

    /**
     * Set the password of an account with higher priviledges
     *
     * @param string $adminPassword
     * @return void
     */
    public function setAdminPassword($adminPassword) {
        $this->adminPassword = $adminPassword;
    }

    /**
     * Get the real primary group setting
     *
     * @return bool
     */
    public function getRealPrimaryGroup() {
        return $this->realPrimaryGroup;
    }

    /**
     * Set whether to detect the true primary group
     *
     * @param bool $realPrimaryGroup
     * @return void
     */
    public function setRealPrimaryGroup($realPrimaryGroup) {
        $this->realPrimaryGroup = $realPrimaryGroup;
    }

    /**
     * Get the SSL setting
     *
     * @return bool
     */
    public function getUseSSL() {
        return $this->useSSL;
    }

    /**
     * Set whether to use SSL
     *
     * @param bool $useSSL
     * @return void
     */
    public function setUseSSL($useSSL) {
        $this->useSSL = $useSSL;
        // Set the default port correctly
        if ($this->useSSL) {
            $this->setPort(self::ADLDAP_LDAPS_PORT);
        } else {
            $this->setPort(self::ADLDAP_LDAP_PORT);
        }
    }

    /**
     * Get the TLS setting
     *
     * @return bool
     */
    public function getUseTLS() {
        return $this->useTLS;
    }

    /**
     * Set whether to use TLS
     *
     * @param bool $useTLS
     * @return void
     */
    public function setUseTLS($useTLS) {
        $this->useTLS = $useTLS;
    }

    /**
     * Get the SSO setting
     *
     * @return bool
     */
    public function getUseSSO() {
        return $this->useSSO;
    }

    /**
     * Set whether to use SSO
     * Requires ldap_sasl_bind support. Be sure --with-ldap-sasl is used when configuring PHP otherwise this function will be undefined.
     *
     * @param bool $useSSO
     * @return void
     * @throws adLDAPException
     */
    public function setUseSSO($useSSO) {
        if ($useSSO === TRUE && !$this->ldapSaslSupported()) {
            throw new adLDAPException('No LDAP SASL support for PHP.  See: http://www.php.net/ldap_sasl_bind');
        }
        $this->useSSO = $useSSO;
    }

    /**
     * Get the recursive groups setting
     *
     * @return bool
     */
    public function getRecursiveGroups() {
        return $this->recursiveGroups;
    }

    /**
     * Set whether to lookup recursive groups
     *
     * @param bool $recursiveGroups
     * @return void
     */
    public function setRecursiveGroups($recursiveGroups) {
        $this->recursiveGroups = $recursiveGroups;
    }

    /**
     * Default Destructor
     *
     * Closes the LDAP connection
     *
     * @return void
     */
    function __destruct() {
        $this->close();
    }

    /**
     * Closes the LDAP connection
     *
     * @return void
     */
    public function close() {
        if ($this->ldapConnection) {
            @ldap_close($this->ldapConnection);
        }
    }

    /**
     * Validate a user's login credentials
     *
     * @param string $username A user's AD username
     * @param string $password A user's AD password
     * @param bool $preventRebind
     * @return bool
     * @throws adLDAPException
     */
    public function authenticate($username, $password, $preventRebind = FALSE) {
        // Prevent null binding
        if ($username === NULL || $password === NULL || empty($username) || empty($password)) {
            throw new adLDAPException("Username or password empty");
        }

        // Allow binding over SSO for Kerberos
        if ($this->useSSO && $_SERVER['REMOTE_USER'] && $_SERVER['REMOTE_USER'] == $username && $this->adminUsername === NULL && $_SERVER['KRB5CCNAME']) {
            putenv("KRB5CCNAME=" . $_SERVER['KRB5CCNAME']);
            $this->ldapBind = @ldap_sasl_bind($this->ldapConnection, NULL, NULL, "GSSAPI");
            if (!$this->ldapBind) {
                throw new adLDAPException('Rebind to Active Directory failed. AD said: ' . $this->getLastError());
            } else {
                return TRUE;
            }
        }

        // Bind as the user        
        $ret = TRUE;
        $this->ldapBind = @ldap_bind($this->ldapConnection, $username . $this->accountSuffix, $password);
        if (!$this->ldapBind) {
            $ret = FALSE;
        }

        // Cnce we've checked their details, kick back into admin mode if we have it
        if ($this->adminUsername !== NULL && !$preventRebind) {
            $this->ldapBind = @ldap_bind($this->ldapConnection, $this->adminUsername . $this->accountSuffix, $this->adminPassword);
            if (!$this->ldapBind) {
                // This should never happen in theory
                throw new adLDAPException('Rebind to Active Directory failed. AD said: ' . $this->getLastError());
            }
        }

        return $ret;
    }

    /**
     * Return a list of all found objects (except computer) in AD
     * $search has to match either cn, displayname, samaccountname or sn
     *
     * @param bool $includeDescription Return a description,cn, displayname and distinguishedname of the user
     * @param string $search Search parameter
     * @param bool $sorted Sort the user accounts
     * @return array , if $includeDescription=true then a multi-dimensional array
     * @throws adLDAPException
     */
    public function search($includeDescription = FALSE, $search = "*", $sorted = TRUE) {
        if (!$this->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        // Perform the search and grab all their details
        //$filter = "(|(cn=" . $search . ")(displayname=" . $search . ")(samaccountname=" . $search . "))";
        $filter = "(&(!(objectClass=computer))(|(anr=" . $search . ")))";
        $fields = array("cn", "description", "displayname", "distinguishedname", "samaccountname");
        $sr = ldap_search($this->getLdapConnection(), $this->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->getLdapConnection(), $sr);

        $objectArray = array();
        for ($i = 0; $i < $entries["count"]; $i++) {
            if ($includeDescription && strlen($entries[$i]["description"][0]) > 0) {
                $objectArray[$entries[$i]["samaccountname"][0]] = array($entries[$i]["cn"][0], $entries[$i]["description"][0], $entries[$i]["displayname"][0], $entries[$i]["distinguishedname"][0]);
            } elseif ($includeDescription) {
                // description is set to displayname if no description is present
                $objectArray[$entries[$i]["samaccountname"][0]] = array($entries[$i]["cn"][0], $entries[$i]["displayname"][0], $entries[$i]["displayname"][0], $entries[$i]["distinguishedname"][0]);
            } else {
                array_push($objectArray, $entries[$i]["samaccountname"][0]);
            }
        }
        if ($sorted) {
            asort($objectArray);
        }

        return $objectArray;
    }

    /**
     * Get the bind status
     *
     * @return bool
     */
    public function getLdapBind() {
        return $this->ldapBind;
    }

    /**
     * Get the active LDAP Connection
     *
     * @return resource
     * @throws adLDAPException
     */
    public function getLdapConnection() {
        if (!$this->ldapConnection) {
            throw new adLDAPException("Ldap connection invalid");
        }

        return $this->ldapConnection;
    }

    /**
     * Get the current base DN
     *
     * @return string
     */
    public function getBaseDn() {
        return $this->baseDn;
    }

    /**
     * Set the current base DN
     *
     * @param string $baseDn
     */
    public function setBaseDn($baseDn) {
        $this->baseDn = $baseDn;
    }

    /**
     * Returns objectClass in an array
     *
     * @param $distinguishedName
     * @return array
     * @throws adLDAPException
     * @internal param string $distinguisedName The full DN of a contact
     */
    public function getObjectClass($distinguishedName) {
        if ($distinguishedName === NULL) {
            throw new adLDAPException("distinguishedName is empty");
        }
        if (!$this->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        $filter = "distinguishedName=" . $this->utilities()->ldapSlashes($distinguishedName);

        $fields = array("objectclass");
        $sr = ldap_search($this->getLdapConnection(), $this->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->getLdapConnection(), $sr);

        $objects = array();
        for ($i = 0; $i < $entries[0]["objectclass"]["count"]; $i++) {
            array_push($objects, $entries[0]["objectclass"][$i]);
        }

        return $objects;
    }

    /**
     * Get the utils class interface
     *
     * @return \adLDAP\classes\adLDAPUtils
     */
    public function utilities() {
        if (!$this->utilClass) {
            $this->utilClass = new \adLDAP\classes\adLDAPUtils($this);
        }

        return $this->utilClass;
    }

    /**
     * Schema
     *
     * @param array $attributes Attributes to be queried
     * @return array
     */
    public function adldap_schema($attributes) {

        // LDAP doesn't like NULL attributes, only set them if they have values
        // If you wish to remove an attribute you should set it to a space
        // TO DO: Adapt user_modify to use ldap_mod_delete to remove a NULL attribute
        $mod = array();

        // Check every attribute to see if it contains 8bit characters and then UTF8 encode them
        array_walk($attributes, array($this, 'encode8bit'));

        if (isset($attributes["address_city"])) {
            $mod["l"][0] = $attributes["address_city"];
        }
        if (isset($attributes["address_code"])) {
            $mod["postalCode"][0] = $attributes["address_code"];
        }
        //if ($attributes["address_country"]){ $mod["countryCode"][0]=$attributes["address_country"]; } // use country codes?
        if (isset($attributes["address_country"])) {
            $mod["c"][0] = $attributes["address_country"];
        }
        if (isset($attributes["address_pobox"])) {
            $mod["postOfficeBox"][0] = $attributes["address_pobox"];
        }
        if (isset($attributes["address_state"])) {
            $mod["st"][0] = $attributes["address_state"];
        }
        if (isset($attributes["address_street"])) {
            $mod["streetAddress"][0] = $attributes["address_street"];
        }
        if (isset($attributes["company"])) {
            $mod["company"][0] = $attributes["company"];
        }
        if (isset($attributes["change_password"])) {
            $mod["pwdLastSet"][0] = 0;
        }
        if (isset($attributes["department"])) {
            $mod["department"][0] = $attributes["department"];
        }
        if (isset($attributes["description"])) {
            $mod["description"][0] = $attributes["description"];
        }
        if (isset($attributes["display_name"])) {
            $mod["displayName"][0] = $attributes["display_name"];
        }
        if (isset($attributes["email"])) {
            $mod["mail"][0] = $attributes["email"];
        }
        if (isset($attributes["expires"])) {
            $mod["accountExpires"][0] = $attributes["expires"];
        } //unix epoch format?
        if (isset($attributes["firstname"])) {
            $mod["givenName"][0] = $attributes["firstname"];
        }
        if (isset($attributes["initials"])) {
            $mod["initials"][0] = $attributes["initials"];
        }
        if (isset($attributes["logon_name"])) {
            $mod["userPrincipalName"][0] = $attributes["logon_name"];
        }
        if (isset($attributes["username"])) {
            $mod["samaccountname"][0] = $attributes["username"];
        }
        if (isset($attributes["manager"])) {
            $mod["manager"][0] = $attributes["manager"];
        }  //UNTESTED ***Use DistinguishedName***
        if (isset($attributes["office"])) {
            $mod["physicalDeliveryOfficeName"][0] = $attributes["office"];
        }
        if (isset($attributes["password"])) {
            $mod["unicodePwd"][0] = $this->user()->encodePassword($attributes["password"]);
        }
        if (isset($attributes["profile_path"])) {
            $mod["profilepath"][0] = $attributes["profile_path"];
        }
        if (isset($attributes["script_path"])) {
            $mod["scriptPath"][0] = $attributes["script_path"];
        }
        if (isset($attributes["surname"])) {
            $mod["sn"][0] = $attributes["surname"];
        }
        if (isset($attributes["title"])) {
            $mod["title"][0] = $attributes["title"];
        }
        if (isset($attributes["telephone"])) {
            $mod["telephoneNumber"][0] = $attributes["telephone"];
        }
        if (isset($attributes["mobile"])) {
            $mod["mobile"][0] = $attributes["mobile"];
        }
        if (isset($attributes["pager"])) {
            $mod["pager"][0] = $attributes["pager"];
        }
        if (isset($attributes["ipphone"])) {
            $mod["ipphone"][0] = $attributes["ipphone"];
        }
        if (isset($attributes["web_page"])) {
            $mod["wWWHomePage"][0] = $attributes["web_page"];
        }
        if (isset($attributes["fax"])) {
            $mod["facsimileTelephoneNumber"][0] = $attributes["fax"];
        }
        if (isset($attributes["enabled"])) {
            $mod["userAccountControl"][0] = $attributes["enabled"];
        }
        if (isset($attributes["homephone"])) {
            $mod["homephone"][0] = $attributes["homephone"];
        }

        // Distribution List specific schema
        if (isset($attributes["group_sendpermission"])) {
            $mod["dlMemSubmitPerms"][0] = $attributes["group_sendpermission"];
        }
        if (isset($attributes["group_rejectpermission"])) {
            $mod["dlMemRejectPerms"][0] = $attributes["group_rejectpermission"];
        }

        // Exchange Schema
        if (isset($attributes["exchange_homemdb"])) {
            $mod["homeMDB"][0] = $attributes["exchange_homemdb"];
        }
        if (isset($attributes["exchange_mailnickname"])) {
            $mod["mailNickname"][0] = $attributes["exchange_mailnickname"];
        }
        if (isset($attributes["exchange_proxyaddress"])) {
            $mod["proxyAddresses"][0] = $attributes["exchange_proxyaddress"];
        }
        if (isset($attributes["exchange_usedefaults"])) {
            $mod["mDBUseDefaults"][0] = $attributes["exchange_usedefaults"];
        }
        if (isset($attributes["exchange_policyexclude"])) {
            $mod["msExchPoliciesExcluded"][0] = $attributes["exchange_policyexclude"];
        }
        if (isset($attributes["exchange_policyinclude"])) {
            $mod["msExchPoliciesIncluded"][0] = $attributes["exchange_policyinclude"];
        }
        if (isset($attributes["exchange_addressbook"])) {
            $mod["showInAddressBook"][0] = $attributes["exchange_addressbook"];
        }
        if (isset($attributes["exchange_altrecipient"])) {
            $mod["altRecipient"][0] = $attributes["exchange_altrecipient"];
        }
        if (isset($attributes["exchange_deliverandredirect"])) {
            $mod["deliverAndRedirect"][0] = $attributes["exchange_deliverandredirect"];
        }

        // This schema is designed for contacts
        if (isset($attributes["exchange_hidefromlists"])) {
            $mod["msExchHideFromAddressLists"][0] = $attributes["exchange_hidefromlists"];
        }
        if (isset($attributes["contact_email"])) {
            $mod["targetAddress"][0] = $attributes["contact_email"];
        }

        $map = ["home_directory" => "homeDirectory", "home_drive" => "homeDrive", "msRADIUS-FramedInterfaceId" => "msRADIUS-FramedInterfaceId"];
        foreach ($map as $kAttr => $kMod) {
            if (!array_key_exists($kAttr, $attributes)) {
                continue;
            }

            if (is_null($attributes[$kAttr])) {
                $mod[$kMod] = [];
            } else {
                $mod[$kMod][0] = $attributes[$kAttr];
            }
        }

        return $mod;
    }

    /**
     * Get the userclass interface
     *
     * @return \adLDAP\classes\adLDAPUsers
     */
    public function user() {
        if (!$this->userClass) {
            $this->userClass = new \adLDAP\classes\adLDAPUsers($this);
        }

        return $this->userClass;
    }

    protected function adldap_schema_map_value() {

    }

    /**
     * Convert 8bit characters e.g. accented characters to UTF8 encoded characters
     */
    protected function encode8Bit(&$item, $key) {
        $encode = FALSE;
        if (is_string($item)) {
            for ($i = 0; $i < strlen($item); $i++) {
                if (ord($item[$i]) >> 7) {
                    $encode = TRUE;
                }
            }
        }
        if ($encode === TRUE && $key != 'password') {
            $item = utf8_encode($item);
        }
    }

    /**
     * Test basic connectivity to controller
     *
     * @return bool
     */
    protected function pingController($host) {
        $port = $this->adPort;
        fsockopen($host, $port, $errno, $errstr, 10);
        if ($errno > 0) {
            return FALSE;
        }

        return TRUE;
    }

}

/**
 * adLDAP Exception Handler
 *
 * Exceptions of this type are thrown on bind failure or when SSL is required but not configured
 * Example:
 * try {
 *   $adldap = new adLDAP();
 * }
 * catch (adLDAPException $e) {
 *   echo $e;
 *   exit();
 * }
 */
class adLDAPException extends \Exception {
}

?>
