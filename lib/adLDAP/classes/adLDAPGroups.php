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
 * @subpackage Groups
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2014 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @version 5.0.0
 * @link http://github.com/adldap/adLDAP
 */
require_once(dirname(__FILE__) . '/../adLDAP.php');
require_once(dirname(__FILE__) . '/../collections/adLDAPGroupCollection.php');

/**
 * GROUP FUNCTIONS
 */
class adLDAPGroups {
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
     * Add a group to a group
     *
     * @param string $parent The parent group name
     * @param string $child The child group name
     * @throws adLDAPException
     */
    public function addGroup($parent, $child) {

        // Find the parent group's dn
        $parentGroup = $this->info($parent, array("cn"));
        if ($parentGroup[0]["dn"] === NULL) {
            throw new adLDAPException("Invalid parent group dn");
        }
        $parentDn = $parentGroup[0]["dn"];

        // Find the child group's dn
        $childGroup = $this->info($child, array("cn"));
        if ($childGroup[0]["dn"] === NULL) {
            throw new adLDAPException("Invalid child group dn");
        }
        $childDn = $childGroup[0]["dn"];

        $add = array();
        $add["member"] = $childDn;

        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $parentDn, $add);
        if ($result == FALSE) {
            throw new adLDAPException("Error during add group to group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Group Information.  Returns an array of raw information about a group.
     * The group name is case sensitive
     *
     * @param string $groupName The group name to retrieve info about
     * @param array $fields Fields to retrieve
     * @return array
     * @throws adLDAPException
     */
    public function info($groupName, $fields = NULL) {
        if ($groupName === NULL) {
            throw new adLDAPException("Missing groupName");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        if (stristr($groupName, '+')) {
            $groupName = stripslashes($groupName);
        }

        $filter = "(&(objectCategory=group)(name=" . $this->adldap->utilities()->ldapSlashes($groupName) . "))";
        if ($fields === NULL) {
            $fields = array("member", "memberof", "cn", "description", "distinguishedname", "objectcategory", "samaccountname");
        }
        $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        // Windows 2003: Returns up to 1500 values (Windows 2000 only 1000 is not supported).
        if (isset($entries[0]['member;range=0-1499']) && $entries[0]['member;range=0-1499']['count'] == 1500) {
            $entries[0]['member']['count'] = "0";
            $rangestep = 1499;     // Step site
            $rangelow = 0;        // Initial low range
            $rangehigh = $rangelow + $rangestep;     // Initial high range
            // do until array_keys($members[0])[0] ends with a '*', e. g. member;range=1499-*. It indicates end of the range
            do {
                $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, array("member;range=" . $rangelow . "-" . $rangehigh));
                $members = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
                $memberrange = array_keys($members[0]);
                $membercount = $members[0][$memberrange[0]]['count'];
                // Copy range entries to member
                for ($i = 0; $i <= $membercount - 1; $i++) {
                    $entries[0]['member'][] = $members[0][$memberrange[0]][$i];
                }
                $entries[0]['member']['count'] += $membercount;
                $rangelow += $rangestep + 1;
                $rangehigh += $rangestep + 1;
            } while (substr($memberrange[0], -1) != '*');
        }

        return $entries;
    }

    /**
     * Add a user to a group
     *
     * @param string $group The group to add the user to
     * @param string $user The user to add to the group
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function addUser($group, $user, $isGUID = FALSE) {
        // Adding a user is a bit fiddly, we need to get the full DN of the user
        // and add it using the full DN of the group

        // Find the user's dn
        $userDn = $this->adldap->user()->dn($user, $isGUID);
        if ($userDn === FALSE) {
            throw new adLDAPException("User specified is not valid");
        }

        // Find the group's dn
        $groupInfo = $this->info($group, array("cn"));
        if (!isset($groupInfo[0]) || $groupInfo[0]["dn"] === NULL) {
            throw new adLDAPException("Group specified is not valid");
        }
        $groupDn = $groupInfo[0]["dn"];

        $add = array();
        $add["member"] = $userDn;

        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $groupDn, $add);
        if ($result == FALSE) {
            throw new adLDAPException("Error adding of user to group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Add a contact to a group
     *
     * @param string $group The group to add the contact to
     * @param string $contactDn The DN of the contact to add
     * @throws adLDAPException
     */
    public function addContact($group, $contactDn) {
        // To add a contact we take the contact's DN
        // and add it using the full DN of the group

        // Find the group's dn
        $groupInfo = $this->info($group, array("cn"));
        if ($groupInfo[0]["dn"] === NULL) {
            throw new adLDAPException("Group specified is not valid");
        }
        $groupDn = $groupInfo[0]["dn"];

        $add = array();
        $add["member"] = $contactDn;

        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $groupDn, $add);
        if ($result == FALSE) {
            throw new adLDAPException("Error adding of contact to group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Create a group
     *
     * @param array $attributes Default attributes of the group
     * @throws adLDAPException
     */
    public function create($attributes) {
        if (!is_array($attributes)) {
            throw new adLDAPException("Attributes must be an array");
        }
        if (!array_key_exists("group_name", $attributes)) {
            throw new adLDAPException("Missing compulsory field [group_name]");
        }
        if (!array_key_exists("container", $attributes)) {
            throw new adLDAPException("Missing compulsory field [container]");
        }
        if (!array_key_exists("description", $attributes)) {
            throw new adLDAPException("Missing compulsory field [description]");
        }
        if (!is_array($attributes["container"])) {
            throw new adLDAPException("Container attribute must be an array.");
        }
        $attributes["container"] = array_reverse($attributes["container"]);

        $add = array();
        $add["cn"] = $attributes["group_name"];
        $add["samaccountname"] = $attributes["group_name"];
        $add["objectClass"] = "Group";
        $add["description"] = $attributes["description"];

        $container = (sizeof($attributes["container"]) > 0) ? ", OU=" . implode(",OU=", $attributes["container"]) : "";
        $result = ldap_add($this->adldap->getLdapConnection(), "CN=" . $add["cn"] . $container . "," . $this->adldap->getBaseDn(), $add);
        if ($result != TRUE) {
            throw new adLDAPException("Error creating group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Delete a group account
     *
     * @param string $group The group to delete (please be careful here!)
     * @throws adLDAPException
     */
    public function delete($group) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if ($group === NULL) {
            throw new adLDAPException("Missing compulsory field [group]");
        }

        $groupInfo = $this->info($group, array("*"));
        $dn = $groupInfo[0]['distinguishedname'][0];
        try {
            $this->adldap->folder()->delete($dn);
        } catch (adLDAPException $e) {
            throw new adLDAPException("Error deleting group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Rename group with new group
     *
     * @param $group
     * @param $newName
     * @param $container
     * @throws adLDAPException
     */
    public function rename($group, $newName, $container) {
        $info = $this->info($group);
        if (!isset($info[0]) || $info[0]["dn"] === NULL) {
            throw new adLDAPException("Group specified is not valid");
        }

        $groupDN = $info[0]["dn"];
        $newRDN = 'CN=' . $newName;

        // Determine the container
        $container = array_reverse($container);
        $container = sizeof($container) > 0 ? "OU=" . implode(", OU=", $container) . ', ' : "";

        $mod = ['samaccountname' => [0 => $newName]];

        $result = @ldap_modify($this->adldap->getLdapConnection(), $groupDN, $mod);
        if ($result == false) {
            throw new adLDAPException("Error renaming group '".ldap_error($this->adldap->getLdapConnection())."'");
        }

        // Do the update
        $result = @ldap_rename($this->adldap->getLdapConnection(), $groupDN, $newRDN, $container . $this->adldap->getBaseDn(), TRUE);
        if ($result == FALSE) {
            throw new adLDAPException("Error renaming group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Remove a group from a group
     *
     * @param string $parent The parent group name
     * @param string $child The child group name
     * @throws adLDAPException
     */
    public function removeGroup($parent, $child) {
        $parentGroup = $this->info($parent, array("cn")); // Find the parent dn
        if ($parentGroup[0]["dn"] === NULL) {
            throw new adLDAPException("Parent group specified is not valid");
        }
        $parentDn = $parentGroup[0]["dn"];

        $childGroup = $this->info($child, array("cn")); // Find the child dn
        if ($childGroup[0]["dn"] === NULL) {
            throw new adLDAPException("Group specified is not valid");
        }
        $childDn = $childGroup[0]["dn"];

        $del = array();
        $del["member"] = $childDn;

        $result = @ldap_mod_del($this->adldap->getLdapConnection(), $parentDn, $del);
        if ($result == FALSE) {
            throw new adLDAPException("Error removing group from group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Remove a user from a group
     *
     * @param string $group The group to remove a user from
     * @param string $user The AD user to remove from the group
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @throws adLDAPException
     */
    public function removeUser($group, $user, $isGUID = FALSE) {
        $groupInfo = $this->info($group, array("cn")); // Find the parent dn
        if ($groupInfo[0]["dn"] === NULL) {
            throw new adLDAPException("Group specified is not valid");
        }
        $groupDn = $groupInfo[0]["dn"];

        // Find the users dn
        $userDn = $this->adldap->user()->dn($user, $isGUID);
        if ($userDn === FALSE) {
            throw new adLDAPException("User specified is not valid");
        }

        $del = array();
        $del["member"] = $userDn;

        $result = @ldap_mod_del($this->adldap->getLdapConnection(), $groupDn, $del);
        if ($result == FALSE) {
            throw new adLDAPException("Error during remove of user from group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Remove a contact from a group
     *
     * @param string $group The group to remove a user from
     * @param string $contactDn The DN of a contact to remove from the group
     * @throws adLDAPException
     */
    public function removeContact($group, $contactDn) {
        $groupInfo = $this->info($group, array("cn")); // Find the parent dn
        if ($groupInfo[0]["dn"] === NULL) {
            throw new adLDAPException("Group specified is not valid");
        }
        $groupDn = $groupInfo[0]["dn"];

        $del = array();
        $del["member"] = $contactDn;

        $result = @ldap_mod_del($this->adldap->getLdapConnection(), $groupDn, $del);
        if ($result == FALSE) {
            throw new adLDAPException("Error during remove of contact from group '" . ldap_error($this->adldap->getLdapConnection()) . "'");
        }
    }

    /**
     * Return a list of groups in a group
     *
     * @param string $group The group to query
     * @param bool $recursive Recursively get groups
     * @return array
     * @throws adLDAPException
     */
    public function inGroup($group, $recursive = NULL) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it

        // Search the directory for the members of a group
        $info = $this->info($group, array("member", "cn"));
        if(!isset($info[0]) || !isset($info[0]['member']) || empty($info[0]['member'])) {
            return [];
        }

        $groups = $info[0]["member"];
        $groupArray = array();

        for ($i = 0; $i < $groups["count"]; $i++) {
            $filter = "(&(objectCategory=group)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($groups[$i]) . "))";
            $fields = array("samaccountname", "distinguishedname", "objectClass");
            $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            // not a person, look for a group
            if ($entries['count'] == 0 && $recursive == TRUE) {
                $filter = "(&(objectCategory=group)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($groups[$i]) . "))";
                $fields = array("distinguishedname");
                $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
                $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
                if (!isset($entries[0]['distinguishedname'][0])) {
                    continue;
                }
                $subGroups = $this->inGroup($entries[0]['distinguishedname'][0], $recursive);
                if (is_array($subGroups)) {
                    $groupArray = array_merge($groupArray, $subGroups);
                    $groupArray = array_unique($groupArray);
                }
                continue;
            }
            $groupArray[] = $entries[0]['distinguishedname'][0];
        }

        return $groupArray;
    }

    /**
     * Return a list of members in a group
     *
     * @param string $group The group to query
     * @param bool $recursive Recursively get group members
     * @return array
     * @throws adLDAPException
     */
    public function members($group, $recursive = NULL) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it
        // Search the directory for the members of a group
        $info = $this->info($group, array("member", "cn"));
        if (isset($info[0]) && isset($info[0]["member"])) {
            $users = $info[0]["member"];
            if (!is_array($users)) {
                return [];
            }
        } else {
            return [];
        }

        $userArray = array();

        for ($i = 0; $i < $users["count"]; $i++) {
            $filter = "(&(objectCategory=person)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($users[$i]) . "))";
            $fields = array("samaccountname", "distinguishedname", "objectClass");
            $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            // not a person, look for a group
            if ($entries['count'] == 0 && $recursive == TRUE) {
                $filter = "(&(objectCategory=group)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($users[$i]) . "))";
                $fields = array("samaccountname");
                $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
                $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
                if (!isset($entries[0]['samaccountname'][0])) {
                    continue;
                }
                $subUsers = $this->members($entries[0]['samaccountname'][0], $recursive);
                if (is_array($subUsers)) {
                    $userArray = array_merge($userArray, $subUsers);
                    $userArray = array_unique($userArray);
                }
                continue;
            } else if ($entries['count'] == 0) {
                continue;
            }

            if ((!isset($entries[0]['samaccountname'][0]) || $entries[0]['samaccountname'][0] === NULL) && $entries[0]['distinguishedname'][0] !== NULL) {
                $userArray[] = $entries[0]['distinguishedname'][0];
            } else if ($entries[0]['samaccountname'][0] !== NULL) {
                $userArray[] = $entries[0]['samaccountname'][0];
            }
        }

        return $userArray;
    }

    /**
     * Group Information.  Returns an collection
     * The group name is case sensitive
     *
     * @param string $groupName The group name to retrieve info about
     * @param array $fields Fields to retrieve
     * @return \adLDAP\collections\adLDAPGroupCollection
     * @throws adLDAPException
     */
    public function infoCollection($groupName, $fields = NULL) {
        if ($groupName === NULL) {
            throw new adLDAPException("Field groupName is empty");
        }
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        $info = $this->info($groupName, $fields);
        return new \adLDAP\collections\adLDAPGroupCollection($info, $this->adldap);
    }

    /**
     * Return a complete list of "groups in groups"
     *
     * @param string $group The group to get the list from
     * @return array
     * @throws adLDAPException
     */
    public function recursiveGroups($group) {
        if ($group === NULL) {
            throw new adLDAPException("Field group is empty");
        }

        $stack = array();
        $processed = array();
        $retGroups = array();

        array_push($stack, $group); // Initial Group to Start with 
        while (count($stack) > 0) {
            $parent = array_pop($stack);
            array_push($processed, $parent);

            $info = $this->info($parent, array("memberof"));

            if (isset($info[0]["memberof"]) && is_array($info[0]["memberof"])) {
                $groups = $info[0]["memberof"];
                if ($groups) {
                    $groupNames = $this->adldap->utilities()->niceNames($groups);
                    $retGroups = array_merge($retGroups, $groupNames); //final groups to return
                    foreach ($groupNames as $id => $groupName) {
                        if (!in_array($groupName, $processed)) {
                            array_push($stack, $groupName);
                        }
                    }
                }
            }
        }

        return $retGroups;
    }

    /**
     * Obtain the group's distinguished name based on their groupid
     *
     * @param string $groupname The groupname
     * @return string
     * @throws adLDAPException
     */
    public function dn($groupname) {
        $group = $this->info($groupname, array("cn"));
        if ($group[0]["dn"] === NULL) {
            throw new adLDAPException("Invalid group dn");
        }

        return $group[0]["dn"];
    }

    /**
     * Returns a complete list of all groups in AD
     *
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array
     * @throws adLDAPException
     */
    public function all($includeDescription = FALSE, $search = "*", $sorted = TRUE) {
        $groupsArray = $this->search(NULL, $includeDescription, $search, $sorted);

        return $groupsArray;
    }

    /**
     * Returns a complete list of the groups in AD based on a SAM Account Type
     *
     * @param string $sAMAaccountType The account type to return
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array
     * @throws adLDAPException
     */
    public function search($sAMAaccountType = adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP, $includeDescription = FALSE, $search = "*", $sorted = TRUE) {
        if (!$this->adldap->getLdapBind()) {
            throw new adLDAPException("Ldap not binded");
        }

        $filter = '(&(objectCategory=group)';
        if ($sAMAaccountType !== NULL) {
            $filter .= '(samaccounttype=' . $sAMAaccountType . ')';
        }
        $filter .= '(cn=' . $search . '))';
        // Perform the search and grab all their details
        $fields = array("samaccountname", "description");
        $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        $groupsArray = array();
        for ($i = 0; $i < $entries["count"]; $i++) {
            if ($includeDescription && isset($entries[$i]["description"]) && strlen($entries[$i]["description"][0]) > 0) {
                $groupsArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["description"][0];
            } else if ($includeDescription) {
                $groupsArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["samaccountname"][0];
            } else {
                array_push($groupsArray, $entries[$i]["samaccountname"][0]);
            }
        }
        if ($sorted) {
            asort($groupsArray);
        }

        return $groupsArray;
    }

    /**
     * Returns a complete list of security groups in AD
     *
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array
     * @throws adLDAPException
     */
    public function allSecurity($includeDescription = FALSE, $search = "*", $sorted = TRUE) {
        $groupsArray = $this->search(adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP, $includeDescription, $search, $sorted);

        return $groupsArray;
    }

    /**
     * Returns a complete list of distribution lists in AD
     *
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array
     * @throws adLDAPException
     */
    public function allDistribution($includeDescription = FALSE, $search = "*", $sorted = TRUE) {
        $groupsArray = $this->search(adLDAP::ADLDAP_DISTRIBUTION_GROUP, $includeDescription, $search, $sorted);

        return $groupsArray;
    }

    /**
     * Coping with AD not returning the primary group
     * http://support.microsoft.com/?kbid=321360
     *
     * This is a re-write based on code submitted by Bruce which prevents the
     * need to search each security group to find the true primary group
     *
     * @param string $gid Group ID
     * @param string $usersid User's Object SID
     * @return string|bool false if not set
     * @throws adLDAPException
     */
    public function getPrimaryGroup($gid, $usersid) {
        if ($gid === NULL || $usersid === NULL) {
            throw new adLDAPException("Userid or group id empty");
        }

        $gsid = substr_replace($usersid, pack('V', $gid), strlen($usersid) - 4, 4);
        $filter = '(objectsid=' . $this->adldap->utilities()->getTextSID($gsid) . ')';
        $fields = array("samaccountname", "distinguishedname");
        $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        if (!isset($entries[0]['distinguishedname'][0])) {
            return false;
        }

        return $entries[0]['distinguishedname'][0];
    }

    /**
     * Coping with AD not returning the primary group
     * http://support.microsoft.com/?kbid=321360
     *
     * For some reason it's not possible to search on primarygrouptoken=XXX
     * If someone can show otherwise, I'd like to know about it :)
     * this way is resource intensive and generally a pain in the @#%^
     *
     * @deprecated deprecated since version 3.1, see get get_primary_group
     * @param string $gid Group ID
     * @return string
     * @throws adLDAPException
     */
    public function cn($gid) {
        if ($gid === NULL) {
            throw new adLDAPException("Group id empty");
        }

        $r = '';
        $filter = "(&(objectCategory=group)(samaccounttype=" . adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP . "))";
        $fields = array("primarygrouptoken", "samaccountname", "distinguishedname");
        $sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields);
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        for ($i = 0; $i < $entries["count"]; $i++) {
            if ($entries[$i]["primarygrouptoken"][0] == $gid) {
                $r = $entries[$i]["distinguishedname"][0];
                $i = $entries["count"];
            }
        }

        return $r;
    }
}

?>
