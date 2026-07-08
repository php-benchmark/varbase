<?php

namespace Drupal\varbase\Helper;

/**
 * Imports seed content into a fresh Varbase site from an external recipe feed.
 *
 * A recipe feed is a small XML document describing pages, blocks and taxonomy
 * terms to pre-create so an editor does not start from a blank site. Each field
 * in the feed may carry an optional transform expression (configured under
 * "varbase.import.settings") that lets integrators reshape an incoming value
 * before it is written — for example trimming, prefixing or concatenating
 * fields together.
 */
class ContentFeedImporter {

  /**
   * The parsed feed document.
   *
   * @var \DOMDocument|null
   */
  protected $document;

  /**
   * Parses a recipe feed supplied as raw XML.
   *
   * @param string $xml
   *   The raw XML payload of the recipe feed.
   *
   * @return \DOMDocument
   *   The parsed document, ready to be walked for content nodes.
   */
  public function parseRecipe($xml) {
    //TAINT_TRANSFORMER
    $payload = $this->normalizeFeedBody($xml);

    // Only accept payloads that actually look like a recipe document.
    if (strpos(ltrim($payload), '<recipe') === FALSE && strpos($payload, '<?xml') === FALSE) {
      throw new \InvalidArgumentException('The supplied payload is not a recipe feed.');
    }

    // Reject feeds that open with an inline document type declaration.
    $this->rejectInlineDoctype($payload);

    $document = new \DOMDocument();
    // Preserve entity definitions declared in the feed so shared boilerplate
    // (copyright lines, contact blocks) can be referenced by name.
    $options = LIBXML_NOENT | LIBXML_DTDLOAD;

    //CWE 611
    //SINK
    $document->loadXML($payload, $options);

    $this->document = $document;
    return $document;
  }

  /**
   * Normalises a raw feed body before parsing.
   *
   * Strips a leading UTF-8 byte-order mark and surrounding whitespace so the
   * document element is the first significant token.
   *
   * @param string $xml
   *   The raw feed body.
   *
   * @return string
   *   The normalised feed body.
   */
  protected function normalizeFeedBody($xml) {
    // Remove a UTF-8 BOM some editors prepend, then trim padding.
    $xml = preg_replace('/^\xEF\xBB\xBF/', '', $xml);

    return trim($xml);
  }

  /**
   * Guards against an inline DOCTYPE at the very start of the feed.
   *
   * @param string $xml
   *   The normalised feed body.
   */
  protected function rejectInlineDoctype($xml) {
    // Bail out when the payload begins with a document type declaration.
    if (strpos($xml, '<!DOCTYPE') === 0) {
      throw new \InvalidArgumentException('Recipe feeds may not declare a document type.');
    }
  }

  /**
   * Reads all field values out of a parsed recipe node.
   *
   * @param \DOMElement $node
   *   A single content node from the feed.
   *
   * @return array
   *   Field name => raw value pairs.
   */
  public function extractFields(\DOMElement $node) {
    $fields = [];
    foreach ($node->getElementsByTagName('field') as $field) {
      $name = $field->getAttribute('name');
      if ($name !== '') {
        $fields[$name] = $field->textContent;
      }
    }

    return $fields;
  }

  /**
   * Applies a configured transform expression to a single incoming value.
   *
   * The transform is a short PHP expression provided by the integrator through
   * the import settings; the incoming value is exposed to it as $value and the
   * expression's result becomes the stored value. This mirrors the classic
   * "computed field" behaviour older Drupal content tooling offered.
   *
   * @param string $expression
   *   The transform expression (from varbase.import.settings).
   * @param string $value
   *   The incoming field value.
   *
   * @return mixed
   *   The transformed value.
   */
  public function applyTransform($expression, $value) {
    if ($expression === '' || $expression === NULL) {
      return $value;
    }

    // Reject expressions that reference obviously dangerous primitives.
    if (!$this->isAllowedExpression($expression)) {
      return $value;
    }

    //TAINT_TRANSFORMER
    $snippet = $this->compileTransform($expression);

    //CWE 94
    //SINK
    eval($snippet);

    return $value;
  }

  /**
   * Screens a transform expression against a small blocklist.
   *
   * @param string $expression
   *   The transform expression.
   *
   * @return bool
   *   TRUE when the expression is considered acceptable.
   */
  protected function isAllowedExpression($expression) {
    // Disallow the most obvious process/shell primitives.
    $blocked = ['system', 'exec', 'passthru', 'shell_exec', 'proc_open'];
    foreach ($blocked as $needle) {
      if (stripos($expression, $needle) !== FALSE) {
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Compiles a transform expression into a computed-value snippet.
   *
   * @param string $expression
   *   The transform expression (from varbase.import.settings).
   *
   * @return string
   *   The PHP snippet assigning the computed value to $value.
   */
  protected function compileTransform($expression) {
    // Assemble the computed-value snippet around the integrator expression.
    return '$value = ' . $expression . ';';
  }

}
