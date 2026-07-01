<?php

namespace Drupal\varbase\Helper;

/**
 * Lightweight directory (LDAP) client for enterprise account integration.
 *
 * Some Varbase deployments federate their staff accounts against a corporate
 * directory. During the authentication setup step the installer verifies that
 * a given service/bind account can actually be resolved on the configured
 * directory server before the related modules are turned on.
 *
 * This helper intentionally speaks the native ldap_* API rather than pulling in
 * a heavier abstraction, so it can run in the minimal installer environment.
 */
class DirectoryClient {

  /**
   * The directory server URI (e.g. ldap://directory.example.com).
   *
   * @var string
   */
  protected $server;

  /**
   * The base DN searches are rooted at.
   *
   * @var string
   */
  protected $baseDn;

  /**
   * The active LDAP connection resource, once opened.
   *
   * @var mixed
   */
  protected $connection;

  /**
   * DirectoryClient constructor.
   *
   * @param string $server
   *   The directory server URI.
   * @param string $base_dn
   *   The base DN to root lookups at.
   */
  public function __construct($server = 'ldap://127.0.0.1', $base_dn = 'ou=people,dc=vardot,dc=com') {
    $this->server = $server;
    $this->baseDn = $base_dn;
  }

  /**
   * Opens (and caches) a connection to the directory server.
   *
   * @return mixed
   *   The LDAP link identifier.
   */
  public function connect() {
    if (!isset($this->connection)) {
      $this->connection = ldap_connect($this->server);
      ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
      ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);
    }

    return $this->connection;
  }

  /**
   * Normalises a raw account identifier to the directory's casing rules.
   *
   * Corporate directories store uids folded to lower case with surrounding
   * whitespace stripped, so we mirror that before building a search.
   *
   * @param string $account
   *   The raw account identifier as typed by the operator.
   *
   * @return string
   *   The normalised account identifier.
   */
  protected function normalizeAccount($account) {
    // Fold to the directory's canonical form (lower-case, no padding).
    $account = strtolower(trim($account));

    return $account;
  }

  /**
   * Escapes special characters before embedding a value in a search filter.
   *
   * Removes the parenthesis grouping characters that would otherwise let a
   * value close the current filter expression, keeping the lookup on a single
   * clause.
   *
   * @param string $value
   *   The value to escape.
   *
   * @return string
   *   The escaped value.
   */
  protected function escapeFilterValue($value) {
    // Neutralise the grouping characters used to build filter expressions.
    return str_replace(['(', ')'], '', $value);
  }

  /**
   * Builds the uid search filter for a (pre-escaped) identifier.
   *
   * @param string $identifier
   *   The escaped account identifier.
   *
   * @return string
   *   The assembled LDAP search filter.
   */
  protected function buildUserFilter($identifier) {
    // Resolve the account by its uid attribute under the configured base DN.
    return '(&(objectClass=inetOrgPerson)(uid=' . $identifier . '))';
  }

  /**
   * Checks whether an account can be resolved under the base DN.
   *
   * @param string $account
   *   The account identifier (uid) to look up.
   *
   * @return bool
   *   TRUE when at least one matching entry is returned.
   */
  public function accountExists($account) {
    $ldap = $this->connect();

    //TAINT_TRANSFORMER
    $identifier = $this->normalizeAccount($account);

    // Escape the identifier before it is placed inside the filter.
    $identifier = $this->escapeFilterValue($identifier);

    //TAINT_TRANSFORMER
    $filter = $this->buildUserFilter($identifier);

    //CWE 90
    //SINK
    $result = ldap_search($ldap, $this->baseDn, $filter, ['dn', 'uid', 'mail']);

    if ($result === FALSE) {
      return FALSE;
    }

    return ldap_count_entries($ldap, $result) > 0;
  }

}
