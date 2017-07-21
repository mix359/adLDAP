<?php

namespace adLDAP\classes;

use adLDAP\adLDAP;
use adLDAP\adLDAPException;

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
 * @subpackage Users
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2014 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @version 5.0.0
 * @link http://github.com/adldap/adLDAP
 */
require_once(dirname(__FILE__) . '/../adLDAP.php');
require_once(dirname(__FILE__) . '/../collections/adLDAPUserCollection.php');

/**
 * USER FUNCTIONS
 */
class adLDAPUsers {

    /**
     * The current adLDAP connection via dependency injection
     * 
     * @var adLDAP
     */
    protected $adldap;

    public function __construct(adLDAP $adldap) {
        $this->adldap = $adldap;
    }

    /**
     * Validate a user's login credentials
     * 
     * @param string $username A user's AD username
     * @param string $password A user's AD password
     * @param bool $preventRebind
     * @return bool
     */
    public function authenticate($username, $password, $preventRebind = false) {
        return $this->adldap->authenticate($username, $password, $preventRebind);
    }

    /**
     * Create a user
     * 
     * If you specify a password here, this can only be performed over SSL
     * 
     * @param array $attributes The attributes to set to the user account
     * @throws adLDAPException
     */
    public function create($attributes) {
        // Check for compulsory fields
        if (!array_key_exists("username", $attributes)) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if (!array_key_exists("firstname", $attributes)) {
            throw new adLDAPException("Missing compulsory field [firstname]");
        }
        if (!array_key_exists("surname", $attributes)) {
            throw new adLDAPException("Missing compulsory field [surname]");
        }
        if (!array_key_exists("email", $attributes)) {
            throw new adLDAPException("Missing compulsory field [email]");
        }
        if (!array_key_exists("container", $attributes)) {
            throw new adLDAPException("Missing compulsory field [container]");
        }
        if (!is_array($attributes["container"])) {
            throw new adLDAPException("Container attribute must be an array.");
        }

        if (array_key_exists("password", $attributes) && (!$this->adldap->getUseSSL() && !$this->adldap->getUseTLS())) {
            throw new \adLDAP\adLDAPException('SSL must be configured on your webserver and enabled in the class to set passwords.');
        }

        if (!array_key_exists("display_name", $attributes)) {
            $attributes["display_name"] = $attributes["firstname"] . " " . $attributes["surname"];
        }

        // Translate the schema
        $add = $this->adldap->adldap_schema($attributes);

        // Additional stuff only used for adding accounts
        $add["cn"][0] = $attributes["display_name"];
        $add["samaccountname"][0] = $attributes["username"];
        $add["objectclass"][0] = "top";
        $add["objectclass"][1] = "person";
        $add["objectclass"][2] = "organizationalPerson";
        $add["objectclass"][3] = "user"; //person?
        //$add["name"][0]=$attributes["firstname"]." ".$attributes["surname"];
        // Set the account control attribute
        $control_options = array("NORMAL_ACCOUNT");
        if (!$attributes["enabled"]) {
            $control_options[] = "ACCOUNTDISABLE";
        }
        $add["userAccountControl"][0] = $this->accountControl($control_options);

        // Determine the container
        $attributes["container"] = array_reverse($attributes["container"]);
         $container = (sizeof($attributes["container"])>0)? ", OU=" . implode(",OU=", $attributes["container"]):"";
       
       // $container = "OU=" . implode(", OU=", $attributes["container"]);

        foreach ($add as $k => $v) {
            if(empty($v))
                unset($add[$k]);
        }

        // Add the entry
        $result = @ldap_add($this->adldap->getLdapConnection(), "CN=" . $add["cn"][0] . $container . "," . $this->adldap->getBaseDn(), $add);
        if ($result != true) {
            throw new adLDAPException("Error during add user: '".ldap_error($this->adldap->getLdapConnection())."'");
        }
    }

    /**
     * Account control options
     *
     * @param array $options The options to convert to int 
     * @return int
     */
    protected function accountControl($options) {
        $val = 0;

        if (is_array($options)) {
            if (in_array("SCRIPT", $options)) {
                $val = $val + 1;
            }
            if (in_array("ACCOUNTDISABLE", $options)) {
                $val = $val + 2;
            }
            if (in_array("HOMEDIR_REQUIRED", $options)) {
                $val = $val + 8;
            }
            if (in_array("LOCKOUT", $options)) {
                $val = $val + 16;
            }
            if (in_array("PASSWD_NOTREQD", $options)) {
                $val = $val + 32;
            }
            //PASSWD_CANT_CHANGE Note You cannot assign this permission by directly modifying the UserAccountControl attribute.
            //For information about how to set the permission programmatically, see the "Property flag descriptions" section.
            if (in_array("ENCRYPTED_TEXT_PWD_ALLOWED", $options)) {
                $val = $val + 128;
            }
            if (in_array("TEMP_DUPLICATE_ACCOUNT", $options)) {
                $val = $val + 256;
            }
            if (in_array("NORMAL_ACCOUNT", $options)) {
                $val = $val + 512;
            }
            if (in_array("INTERDOMAIN_TRUST_ACCOUNT", $options)) {
                $val = $val + 2048;
            }
            if (in_array("WORKSTATION_TRUST_ACCOUNT", $options)) {
                $val = $val + 4096;
            }
            if (in_array("SERVER_TRUST_ACCOUNT", $options)) {
                $val = $val + 8192;
            }
            if (in_array("DONT_EXPIRE_PASSWORD", $options)) {
                $val = $val + 65536;
            }
            if (in_array("MNS_LOGON_ACCOUNT", $options)) {
                $val = $val + 131072;
            }
            if (in_array("SMARTCARD_REQUIRED", $options)) {
                $val = $val + 262144;
            }
            if (in_array("TRUSTED_FOR_DELEGATION", $options)) {
                $val = $val + 524288;
            }
            if (in_array("NOT_DELEGATED", $options)) {
                $val = $val + 1048576;
            }
            if (in_array("USE_DES_KEY_ONLY", $options)) {
                $val = $val + 2097152;
            }
            if (in_array("DONT_REQ_PREAUTH", $options)) {
                $val = $val + 4194304;
            }
            if (in_array("PASSWORD_EXPIRED", $options)) {
                $val = $val + 8388608;
            }
            if (in_array("TRUSTED_TO_AUTH_FOR_DELEGATION", $options)) {
                $val = $val + 16777216;
            }
        }
        return $val;
    }

    /**
     * Delete a user account
     *
     * @param string $username The username to delete (please be careful here!)
     * @param bool $isGUID Is the username a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function delete($username, $isGUID = false) {
        $userinfo = $this->info($username, array("*"), $isGUID);
        if(!isset($userinfo[0])) {
            return;
        }

        $dn = $userinfo[0]['distinguishedname'][0];

        try {
            $this->adldap->folder()->delete($dn);
        } catch (adLDAPException $e) {
            throw new adLDAPException("Error during delete user: '".ldap_error($this->adldap->getLdapConnection())."'");
        }
    }

    /**
     * Groups the user is a member of
     *
     * @param string $username The username to query
     * @param bool $recursive Recursive list of groups
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return array
     * @throws adLDAPException
     */
    public function groups($username, $recursive = NULL, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Username empty");
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        // Search the directory for their information
        $info = @$this->info($username, array("memberof", "primarygroupid"), $isGUID);
        if(!isset($info[0])) {
            return [];
        }

        $groups = $this->adldap->utilities()->niceNames($info[0]["memberof"]); // Presuming the entry returned is our guy (unique usernames)

        if ($recursive === true) {
            foreach ($groups as $id => $groupName) {
                $extraGroups = $this->adldap->group()->recursiveGroups($groupName);
                $groups = array_merge($groups, $extraGroups);
            }
        }
        return $groups;
    }

    /**
     * Find information about the users. Returned in a raw array format from AD
     * 
     * @param string $username The username to query
     * @param array $fields Array of parameters to query
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return array
     * @throws adLDAPException
     */
    public function info($username, $fields = NULL, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Username empty");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        if ($isGUID === true) {
            $username = $this->adldap->utilities()->strGuidToHex($username);
            $filter = "objectGUID=" . $username;
        } else if (strpos($username, "@")) {
            $filter = "userPrincipalName=" . $username;
        } else {
            $filter = "samaccountname=" . $username;
        }
        $filter = "(&(objectCategory=person)({$filter}))";
        if ($fields === NULL) {
            $fields = array("samaccountname", "mail", "memberof", "department", "displayname", "telephonenumber", "primarygroupid", "objectsid");
        }
        if (!in_array("objectsid", $fields)) {
            $fields[] = "objectsid";
        }
        $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        if (!isset($entries[0])) {
            return [];
        }

        if ($entries[0]['count'] >= 1) {
            if (in_array("memberof", $fields)) {
                // AD does not return the primary group in the ldap query, we may need to fudge it
                if ($this->adldap->getRealPrimaryGroup() && isset($entries[0]["primarygroupid"][0]) && isset($entries[0]["objectsid"][0])) {
                    //$entries[0]["memberof"][]=$this->group_cn($entries[0]["primarygroupid"][0]);
                    $entries[0]["memberof"][] = $this->adldap->group()->getPrimaryGroup($entries[0]["primarygroupid"][0], $entries[0]["objectsid"][0]);
                } else {
                    $entries[0]["memberof"][] = "CN=Domain Users,CN=Users," . $this->adldap->getBaseDn();
                }
                if (!isset($entries[0]["memberof"]["count"])) {
                    $entries[0]["memberof"]["count"] = 0;
                }
                $entries[0]["memberof"]["count"] ++;
            }
        }
        return $entries;
    }

    /**
     * Find information about the users. Returned in a raw array format from AD
     *
     * @param string $username The username to query
     * @param array $fields Array of parameters to query
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return \adLDAP\collections\adLDAPUserCollection
     * @throws adLDAPException
     */
    public function infoCollection($username, $fields = NULL, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Username empty");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        $info = $this->info($username, $fields, $isGUID);
        return new \adLDAP\collections\adLDAPUserCollection($info, $this->adldap);
    }

    /**
     * Determine if a user is in a specific group
     * 
     * @param string $username The username to query
     * @param string $group The name of the group to check against
     * @param bool $recursive Check groups recursively
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function inGroup($username, $group, $recursive = NULL, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Username empty");
        }
        if ($group === NULL) {
            throw new adLDAPException("Group empty");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it
        // Get a list of the groups
        $groups = $this->groups($username, $recursive, $isGUID);

        // Return true if the specified group is in the group list
        if (in_array($group, $groups)) {
            return true;
        }
        return false;
    }

    /**
     * Determine a user's password expiry date
     * 
     * @param string $username The username to query
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @requires bcmath http://www.php.net/manual/en/book.bc.php
     * @return array|bool false if not expire
     * @throws adLDAPException
     */
    public function passwordExpiry($username, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Username empty");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if (!function_exists('bcmod')) {
            throw new adLDAPException("Missing function support [bcmod] http://www.php.net/manual/en/book.bc.php");
        };

        $userInfo = $this->info($username, array("pwdlastset", "useraccountcontrol"), $isGUID);
        $pwdLastSet = $userInfo[0]['pwdlastset'][0];
        $status = array();

        if ($userInfo[0]['useraccountcontrol'][0] == '66048') {
            // Password does not expire
            return false;
        }
        if ($pwdLastSet === '0') {
            $status['expiryts'] = time();
            $status['expiryformat'] = date('Y-m-d H:i:s');
            // Password has already expired
            return $status;
        }

        // Password expiry in AD can be calculated from TWO values:
        //   - User's own pwdLastSet attribute: stores the last time the password was changed
        //   - Domain's maxPwdAge attribute: how long passwords last in the domain
        //
         // Although Microsoft chose to use a different base and unit for time measurements.
        // This function will convert them to Unix timestamps
        $sr = ldap_read($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), 'objectclass=*', array('maxPwdAge'));
        if (!$sr) {
            throw new adLDAPException("Error reading user data '".ldap_error($this->adldap->getLdapConnection())."'");
        }
        $info = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
        $maxPwdAge = $info[0]['maxpwdage'][0];

        // See MSDN: http://msdn.microsoft.com/en-us/library/ms974598.aspx
        //
         // pwdLastSet contains the number of 100 nanosecond intervals since January 1, 1601 (UTC),
        // stored in a 64 bit integer.
        //
         // The number of seconds between this date and Unix epoch is 11644473600.
        //
         // maxPwdAge is stored as a large integer that represents the number of 100 nanosecond
        // intervals from the time the password was set before the password expires.
        //
         // We also need to scale this to seconds but also this value is a _negative_ quantity!
        //
         // If the low 32 bits of maxPwdAge are equal to 0 passwords do not expire
        //
         // Unfortunately the maths involved are too big for PHP integers, so I've had to require
        // BCMath functions to work with arbitrary precision numbers.
        if (bcmod($maxPwdAge, 4294967296) === '0') {
            return false;
        }

        // Add maxpwdage and pwdlastset and we get password expiration time in Microsoft's
        // time units.  Because maxpwd age is negative we need to subtract it.
        $pwdExpire = bcsub($pwdLastSet, $maxPwdAge);

        // Convert MS's time to Unix time
        $status['expiryts'] = bcsub(bcdiv($pwdExpire, '10000000'), '11644473600');
        $status['expiryformat'] = date('Y-m-d H:i:s', bcsub(bcdiv($pwdExpire, '10000000'), '11644473600'));

        return $status;
    }

    /**
     * Modify a user
     * 
     * @param string $username The username to query
     * @param array $attributes The attributes to modify.  Note if you set the enabled attribute you must not specify any other attributes
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function modify($username, $attributes, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if (array_key_exists("password", $attributes) && !$this->adldap->getUseSSL() && !$this->adldap->getUseTLS()) {
            throw new \adLDAP\adLDAPException('SSL/TLS must be configured on your webserver and enabled in the class to set passwords.');
        }

        // Find the dn of the user
        $userDn = $this->dn($username, $isGUID);
        if ($userDn === false) {
            throw new adLDAPException("dn of the user empty");
        }

        // Translate the update to the LDAP schema                
        $mod = $this->adldap->adldap_schema($attributes);

        // Check to see if this is an enabled status update
        if (!$mod && !array_key_exists("enabled", $attributes)) {
            throw new adLDAPException("status update not enabled");
        }

        // Set the account control attribute (only if specified)
        if (array_key_exists("enabled", $attributes)) {
            if ($attributes["enabled"]) {
                $controlOptions = array("NORMAL_ACCOUNT");
            } else {
                $controlOptions = array("NORMAL_ACCOUNT", "ACCOUNTDISABLE");
            }
            $mod["userAccountControl"][0] = $this->accountControl($controlOptions);
        }

        // Do the update
        $result = @ldap_modify($this->adldap->getLdapConnection(), $userDn, $mod);
        if ($result == false) {
            throw new adLDAPException("Error during user modify '".ldap_error($this->adldap->getLdapConnection())."'");
        }
    }

    /**
     * Disable a user account
     * 
     * @param string $username The username to disable
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function disable($username, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }

        $attributes = array("enabled" => 0);
        $this->modify($username, $attributes, $isGUID);
    }

    /**
     * Enable a user account
     * 
     * @param string $username The username to enable
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function enable($username, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        $attributes = array("enabled" => 1);
        $this->modify($username, $attributes, $isGUID);
    }

    /**
     * Set the password of a user - This must be performed over SSL
     * 
     * @param string $username The username to modify
     * @param string $password The new password
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function password($username, $password, $isGUID = false) {
        if ($username === NULL) {
            throw new adLDAPException("Missing username");
        }
        if ($password === NULL) {
            throw new adLDAPException("Missing password");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if (!$this->adldap->getUseSSL() && !$this->adldap->getUseTLS()) {
            throw new adLDAPException('SSL must be configured on your webserver and enabled in the class to set passwords.');
        }

        $userDn = $this->dn($username, $isGUID);

        $add = array();
        $add["unicodePwd"][0] = $this->encodePassword($password);

        $result = @ldap_mod_replace($this->adldap->getLdapConnection(), $userDn, $add);
        if ($result === false) {
            $err = ldap_errno($this->adldap->getLdapConnection());
            if ($err) {
                $msg = 'Error ' . $err . ': ' . ldap_err2str($err) . '.';
                if ($err == 53) {
                    $msg .= ' Your password might not match the password policy.';
                }
            } else {
                $msg = "Error setting the user password";
            }
            throw new adLDAPException($msg);
        }
    }

    /**
     * Encode a password for transmission over LDAP
     *
     * @param string $password The password to encode
     * @return string
     */
    public function encodePassword($password) {
        $password = "\"" . $password . "\"";
        $encoded = "";
        for ($i = 0; $i < strlen($password); $i++) {
            $encoded.="{$password{$i}}\000";
        }
        return $encoded;
    }

    /**
     * Obtain the user's distinguished name based on their userid
     *
     *
     * @param string $username The username
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return string
     * @throws adLDAPException
     */
    public function dn($username, $isGUID = false) {
        $user = $this->info($username, array("cn"), $isGUID);
        if (!isset($user[0]) || $user[0]["dn"] === NULL) {
            throw new adLDAPException("Invalid user dn");
        }
        $userDn = $user[0]["dn"];
        return $userDn;
    }

    /**
     * Return a list of all users in AD
     * 
     * @param bool $includeDescription Return a description of the user
     * @param string $search Search parameter
     * @param bool $sorted Sort the user accounts
     * @return array
     * @throws adLDAPException
     */
    public function all($includeDescription = false, $search = "*", $sorted = true) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        // Perform the search and grab all their details
        $filter = "(&(objectClass=user)(samaccounttype=" . adLDAP::ADLDAP_NORMAL_ACCOUNT . ")(objectCategory=person)(cn=" . $search . "))";
        if (is_array($includeDescription)) {
            $fields = array_merge(array("samaccountname", "displayname"), $includeDescription);
        } else {
            $fields = array("samaccountname", "displayname");
        }
        //$sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        //$entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
        $entries = $this->paginated_search($filter, $fields);

        $usersArray = array();
        for ($i = 0; $i < $entries["count"]; $i++) {
            if (is_array($includeDescription)) {
                $id = $entries[$i]["samaccountname"][0];
                $usersArray[$id] = array();
                foreach ($includeDescription as $detail) {
                    $usersArray[$id][$detail] = isset($entries[$i][$detail][0]) ? $entries[$i][$detail][0] : '';
                }
            } else {
                array_push($usersArray, $entries[$i]["samaccountname"][0]);
            }
        }
        if ($sorted) {
            asort($usersArray);
        }
        return $usersArray;
    }

    /**
     * Converts a username (samAccountName) to a GUID
     * 
     * @param string $username The username to query
     * @return string
     * @throws adLDAPException
     */
    public function usernameToGuid($username) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if ($username === null) {
            throw new adLDAPException("Missing username");
        }

        $filter = "samaccountname=" . $username;
        $fields = array("objectGUID");
        $sr = @ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        if (ldap_count_entries($this->adldap->getLdapConnection(), $sr) < 1) {
            throw new adLDAPException("Missing guid for username");
        }

        $entry = @ldap_first_entry($this->adldap->getLdapConnection(), $sr);
        $guid = @ldap_get_values_len($this->adldap->getLdapConnection(), $entry, 'objectGUID');
        $strGUID = $this->adldap->utilities()->binaryToText($guid[0]);
        return $strGUID;
    }

    /**
     * Return a list of all users in AD that have a specific value in a field
     *
     * @param bool $includeDescription Return a description of the user
     * @param string $searchField Field to search search for
     * @param string $searchFilter Value to search for in the specified field
     * @param bool $sorted Sort the user accounts
     * @return array
     * @throws adLDAPException
     */
    public function find($includeDescription = false, $searchField = false, $searchFilter = false, $sorted = true) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        // Perform the search and grab all their details
        $searchParams = "";
        if ($searchField) {
            $searchParams = "(" . $searchField . "=" . $searchFilter . ")";
        }
        $filter = "(&(objectClass=user)(samaccounttype=" . adLDAP::ADLDAP_NORMAL_ACCOUNT . ")(objectCategory=person)" . $searchParams . ")";
        $fields = array("samaccountname", "displayname");
        $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        $usersArray = array();
        for ($i = 0; $i < $entries["count"]; $i++) {
            if ($includeDescription && strlen($entries[$i]["displayname"][0]) > 0) {
                $usersArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["displayname"][0];
            } else if ($includeDescription) {
                $usersArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["samaccountname"][0];
            } else {
                array_push($usersArray, $entries[$i]["samaccountname"][0]);
            }
        }
        if ($sorted) {
            asort($usersArray);
        }
        return $usersArray;
    }

    /**
     * Move a user account to a different OU
     *
     * @param string $username The username to move (please be careful here!)
     * @param array $container The container or containers to move the user to (please be careful here!).
     * accepts containers in 1. parent 2. child order
     * @throws adLDAPException
     */
    public function move($username, $container) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if ($username === null) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if ($container === null) {
            throw new adLDAPException("Missing compulsory field [container]");
        }
        if (!is_array($container)) {
            throw new adLDAPException("Container must be an array");
        }

        $userInfo = $this->info($username, array("*"));
        if(!isset($userInfo[0]) || !isset($userInfo[0]['distinguishedname']) || !isset($userInfo[0]['distinguishedname'][0])) {
            throw new adLDAPException("Invalid or not existent user");
        }

        $dn = $userInfo[0]['distinguishedname'][0];
        $newRDn = "cn=" . $username;
        $container = array_reverse($container);
        $newContainer = "ou=" . implode(",ou=", $container);
        $newBaseDn = strtolower($newContainer) . "," . $this->adldap->getBaseDn();
        $result = @ldap_rename($this->adldap->getLdapConnection(), $dn, $newRDn, $newBaseDn, true);
        if ($result !== true) {
            throw new adLDAPException("Error during user move '".ldap_error($this->adldap->getLdapConnection())."'");
        }
    }

    /**
     * Get the last logon time of any user as a Unix timestamp
     * 
     * @param string $username
     * @return int $unixTimestamp
     * @throws adLDAPException
     */
    public function getLastLogon($username) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if ($username === null) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        $userInfo = $this->info($username, array("lastLogonTimestamp"));
        return adLDAPUtils::convertWindowsTimeToUnixTime($userInfo[0]['lastLogonTimestamp'][0]);
    }
    
    private function paginated_search($filter, $fields, $pageSize = 500)
    {
        $cookie = '';
        $result = [];
        $result['count'] = 0;
        do {
            ldap_set_option($this->adldap->getLdapConnection(), LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_control_paged_result($this->adldap->getLdapConnection(), $pageSize, true, $cookie);

            $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
            $entries['count'] += $result['count'];

            $result = array_merge($result, $entries);

            ldap_control_paged_result_response($this->adldap->getLdapConnection(), $sr, $cookie);
            ldap_free_result($sr);

        } while ($cookie !== null && $cookie != '');

        ldap_control_paged_result($this->adldap->getLdapConnection(), 1000);
        return $result;
    }
    
}

?>
