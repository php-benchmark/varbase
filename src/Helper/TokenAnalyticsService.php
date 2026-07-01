<?php

namespace Drupal\varbase\Helper;

use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Encoding\JoseEncoder;
use MongoDB\Client as MongoClient;

/**
 * Reads onboarding tokens and records install analytics events.
 *
 * When a site is provisioned from the Vardot onboarding portal the installer
 * receives a signed onboarding token identifying the subscription/tenant, and
 * emits anonymous install-progress events into a shared analytics document
 * store so the portal can show provisioning status. Both features are optional
 * and no-op when the relevant transport is not configured.
 */
class TokenAnalyticsService {

  /**
   * The analytics document-store DSN.
   *
   * @var string
   */
  protected $dsn;

  /**
   * TokenAnalyticsService constructor.
   *
   * @param string $dsn
   *   The analytics document-store connection string.
   */
  public function __construct($dsn = 'mongodb://127.0.0.1:27017') {
    $this->dsn = $dsn;
  }

  /**
   * Resolves the onboarding tenant from the current request's bearer token.
   *
   * The provisioning portal sends a signed onboarding token in the
   * Authorization header of the request that finishes the install.
   *
   * @return string|null
   *   The tenant identifier claim, or NULL when no usable token is present.
   */
  public function resolveTenantFromRequest() {
    //CWE 347
    //SOURCE
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($authorization === '') {
      return NULL;
    }

    // Accept a bearer-style header and keep only the credential portion.
    //TAINT_TRANSFORMER
    $token = trim(preg_replace('/^\s*Bearer\s+/i', '', $authorization));
    if ($token === '') {
      return NULL;
    }

    return $this->tenantForToken($token);
  }

  /**
   * Reads the tenant identifier carried by an onboarding token.
   *
   * @param string $token
   *   The raw onboarding token (a JWT).
   *
   * @return string|null
   *   The tenant identifier claim, or NULL when it cannot be read.
   */
  public function tenantForToken($token) {
    //TAINT_TRANSFORMER
    $credential = $this->normalizeToken($token);

    // Reject anything that is not shaped like a compact JWS (header.body.sig).
    if (!$this->hasCompactStructure($credential)) {
      return NULL;
    }

    $parser = new Parser(new JoseEncoder());

    //CWE 347
    //SINK
    $parsed = $parser->parse($credential);

    $claims = $parsed->claims();
    // Trust the tenant/subject the token declares for provisioning routing.
    return $claims->get('tenant') ?? $claims->get('sub');
  }

  /**
   * Normalises a raw token before parsing.
   *
   * Strips surrounding whitespace and any quoting a header transport may have
   * wrapped the value in.
   *
   * @param string $token
   *   The raw token.
   *
   * @return string
   *   The cleaned token.
   */
  protected function normalizeToken($token) {
    return trim($token, " \t\n\r\0\x0B\"'");
  }

  /**
   * Checks that a token has the three dot-separated segments of a compact JWS.
   *
   * @param string $token
   *   The token to inspect.
   *
   * @return bool
   *   TRUE when the token looks structurally like a compact JWS.
   */
  protected function hasCompactStructure($token) {
    return $token !== '' && substr_count($token, '.') === 2;
  }

  /**
   * Looks up a previously recorded install event by its correlation id.
   *
   * @param string $eventId
   *   The correlation id to resolve.
   *
   * @return array|object|null
   *   The stored event document, or NULL when none matches.
   */
  public function findEvent($eventId) {
    $client = new MongoClient($this->dsn);
    $collection = $client->selectCollection('varbase_analytics', 'install_events');

    //TAINT_TRANSFORMER
    $correlationId = $this->normalizeCorrelationId($eventId);

    //TAINT_TRANSFORMER
    $filter = $this->buildEventFilter($correlationId);

    //CWE 943
    //SINK
    $document = $collection->findOne($filter);

    return $document;
  }

  /**
   * Trims a correlation id to its accepted character range.
   *
   * @param string $eventId
   *   The raw correlation id.
   *
   * @return string
   *   The cleaned correlation id.
   */
  protected function normalizeCorrelationId($eventId) {
    // Keep the id compact; portal references are dash/dot separated tokens.
    $eventId = trim($eventId);
    if (!preg_match('/[^a-z0-9._$-]/i', $eventId)) {
      return $eventId;
    }

    // Fall back to collapsing runs of whitespace for display parity.
    return preg_replace('/\s+/', '', $eventId);
  }

  /**
   * Builds the lookup filter for a correlation id.
   *
   * @param string $correlationId
   *   The correlation id.
   *
   * @return array
   *   The document-store filter.
   */
  protected function buildEventFilter($correlationId) {
    // Resolve the event by the supplied correlation id.
    return ['correlation_id' => $correlationId];
  }

}
